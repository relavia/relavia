package openvpn

import (
	"strings"
	"testing"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

func TestRenderProfilePassthrough(t *testing.T) {
	n := passthroughNode(sampleBody)
	n.OpenVPN.Username = "vpn" // sampleBody asks for auth; creds supplied
	rp, err := RenderProfile(n)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	// Safety rewrites are shared with the process adapter:
	// control/hook directives never reach the core.
	for _, banned := range []string{"management", "daemon", "plugin", "up /tmp", "log /tmp"} {
		if strings.Contains(rp.Text, banned) {
			t.Errorf("rendered profile contains %q:\n%s", banned, rp.Text)
		}
	}
	// The process adapter's management block must NOT leak
	// into an OpenVPN 3 profile.
	for _, banned := range []string{"management-query-passwords", "auth-nocache", "relavia openvpn adapter"} {
		if strings.Contains(rp.Text, banned) {
			t.Errorf("rendered profile contains process-adapter artifact %q", banned)
		}
	}
	if rp.Proto != "tcp" {
		t.Errorf("Proto = %q, want tcp", rp.Proto)
	}
	if !strings.Contains(rp.Text, "remote 203.0.113.7 443") {
		t.Errorf("rendered profile lost the remote line:\n%s", rp.Text)
	}
	// The retry-discipline rewrite is shared with the process
	// adapter (same builder): the sample body's unbounded
	// resolv-retry arrives bounded here too, listed in
	// Rewritten — and it is the ONLY retry-class change: every
	// other session directive of the source body survives
	// verbatim (diagnosis §3 zero-diff, amended by exactly this
	// one documented rewrite).
	if strings.Contains(rp.Text, "resolv-retry infinite") {
		t.Errorf("rendered profile kept unbounded resolv-retry:\n%s", rp.Text)
	}
	if !strings.Contains(rp.Text, "\nresolv-retry "+boundedResolvRetry+"\n") {
		t.Errorf("rendered profile missing bounded resolv-retry:\n%s", rp.Text)
	}
	found := false
	for _, r := range rp.Rewritten {
		if r == "resolv-retry(infinite->"+boundedResolvRetry+")" {
			found = true
		}
	}
	if !found {
		t.Errorf("Rewritten does not list the resolv-retry rewrite: %v", rp.Rewritten)
	}
}

func TestRenderProfileAuthWithoutCredentials(t *testing.T) {
	// sampleBody carries auth-user-pass but the node has no
	// username: the bridge must refuse up front with the
	// stable classification, not fail later at the server.
	n := passthroughNode(sampleBody)
	_, err := RenderProfile(n)
	if err == nil {
		t.Fatal("RenderProfile succeeded, want auth_credentials_missing")
	}
	if got := CodeOf(err); got != CodeAuthNoCredentials {
		t.Errorf("CodeOf = %q, want %q (err %v)", got, CodeAuthNoCredentials, err)
	}
	if k := kernel.KindOf(err); k != kernel.KindInvalidConfig {
		t.Errorf("KindOf = %q, want %q", k, kernel.KindInvalidConfig)
	}
}

func TestRenderProfileWithCredentials(t *testing.T) {
	n := passthroughNode(sampleBody)
	n.OpenVPN.Username = "vpn"
	n.OpenVPN.Password = "s3cret-value"
	rp, err := RenderProfile(n)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	if !rp.UsesAuth {
		t.Error("UsesAuth = false, want true (auth-user-pass in body)")
	}
	if rp.Username != "vpn" || rp.Password != "s3cret-value" {
		t.Errorf("creds = %q/%q, want the node's", rp.Username, rp.Password)
	}
	// The credentials themselves never enter the profile text.
	if strings.Contains(rp.Text, "s3cret-value") {
		t.Error("password leaked into rendered profile text")
	}
}

func TestRenderProfilePoolTLSVersionCap(t *testing.T) {
	// A VPN Gate pool node (provenance stamped by the CSV
	// intake) gets the pool TLS ceiling appended and recorded
	// (diagnosis §10): SoftEther's OpenVPN clone captures the
	// client certificate reliably only in a <= TLS 1.2
	// handshake on the affected builds.
	n := passthroughNode(sampleBody)
	n.Source = specnode.SourceRef{Kind: "plugin", Ref: "vpngate", Authorization: "vpngate-official-csv"}
	n.OpenVPN.Username = "vpn" // sampleBody asks for auth; creds supplied
	rp, err := RenderProfile(n)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	if got := strings.Count(rp.Text, "tls-version-max "+poolTLSVersionMax); got != 1 {
		t.Errorf("rendered pool profile carries the TLS cap %d times, want exactly 1:\n%s", got, rp.Text)
	}
	found := false
	for _, r := range rp.Rewritten {
		if r == poolTLSVersionMaxRecord {
			found = true
		}
	}
	if !found {
		t.Errorf("Rewritten does not list the pool TLS cap: %v", rp.Rewritten)
	}
}

func TestRenderProfileUserNodeNoTLSVersionCap(t *testing.T) {
	// The identical body on a user-supplied node (the
	// passthroughNode default provenance: manual) must keep
	// full TLS negotiation — the cap is keyed to pool
	// provenance, never to the protocol family.
	n := passthroughNode(sampleBody)
	n.OpenVPN.Username = "vpn"
	rp, err := RenderProfile(n)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	if strings.Contains(rp.Text, "tls-version-max") {
		t.Errorf("user node profile gained a TLS cap:\n%s", rp.Text)
	}
	for _, r := range rp.Rewritten {
		if r == poolTLSVersionMaxRecord {
			t.Errorf("user node Rewritten lists the pool TLS cap: %v", rp.Rewritten)
		}
	}
	// Another plugin's nodes are not the VPN Gate pool.
	n2 := passthroughNode(sampleBody)
	n2.Source = specnode.SourceRef{Kind: "plugin", Ref: "some-other-source", Authorization: "self"}
	n2.OpenVPN.Username = "vpn"
	rp2, err := RenderProfile(n2)
	if err != nil {
		t.Fatalf("RenderProfile: %v", err)
	}
	if strings.Contains(rp2.Text, "tls-version-max") {
		t.Errorf("non-vpngate plugin node profile gained a TLS cap:\n%s", rp2.Text)
	}
}

func TestBuildConfigPoolTLSVersionCap(t *testing.T) {
	// The desktop process-adapter path (buildConfig) shares
	// the builders, so a pool node is capped there too — and
	// OpenVPN 2.x honors the directive natively.
	n := passthroughNode(sampleBody)
	n.Source = specnode.SourceRef{Kind: "plugin", Ref: "vpngate", Authorization: "vpngate-official-csv"}
	bc, err := buildConfig(n, buildOptions{})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if got := strings.Count(bc.text, "tls-version-max "+poolTLSVersionMax); got != 1 {
		t.Errorf("desktop pool config carries the TLS cap %d times, want exactly 1:\n%s", got, bc.text)
	}
}

func TestRenderProfileRejectsNonOpenVPN(t *testing.T) {
	if _, err := RenderProfile(&specnode.Node{Protocol: specnode.ProtocolTrojan}); err == nil {
		t.Fatal("RenderProfile succeeded for a node without OpenVPN credential")
	}
	if _, err := RenderProfile(nil); err == nil {
		t.Fatal("RenderProfile succeeded for nil node")
	}
}
