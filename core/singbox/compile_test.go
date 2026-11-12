package singbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

func specSource() specnode.SourceRef {
	return specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "user-provided"}
}

func baseNode(protocol string) *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "10000000-0000-4000-8000-000000000001",
		Name:          "test",
		Protocol:      protocol,
		Server:        "127.0.0.1",
		Port:          443,
		Source:        specSource(),
		UDP:           true,
	}
}

func mustCompile(t *testing.T, n *specnode.Node) map[string]any {
	t.Helper()
	if err := checkSupported(n); err != nil {
		t.Fatalf("checkSupported(%s): %v", n.Protocol, err)
	}
	if err := checkCompileInputs(n); err != nil {
		t.Fatalf("checkCompileInputs(%s): %v", n.Protocol, err)
	}
	raw, err := compileConfig(n, compileOptions{listenHost: "127.0.0.1", listenPort: 2080, logLevel: "warn", cachePath: "/tmp/test-cache.db"})
	if err != nil {
		t.Fatalf("compileConfig(%s): %v", n.Protocol, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("compiled config is not JSON: %v", err)
	}
	return cfg
}

func outboundOf(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	obs, _ := cfg["outbounds"].([]any)
	if len(obs) == 0 {
		t.Fatalf("no outbounds in config: %v", cfg)
	}
	ob, _ := obs[0].(map[string]any)
	return ob
}

func TestCompileShapes(t *testing.T) {
	ss := baseNode(specnode.ProtocolShadowsocks)
	ss.Port = 8388
	ss.Shadowsocks = &specnode.CredShadowsocks{Method: "2022-blake3-aes-256-gcm", Password: "cGFzc3dvcmQ="}
	ob := outboundOf(t, mustCompile(t, ss))
	if ob["type"] != "shadowsocks" || ob["method"] != "2022-blake3-aes-256-gcm" {
		t.Fatalf("ss outbound: %v", ob)
	}

	trojan := baseNode(specnode.ProtocolTrojan)
	trojan.Trojan = &specnode.CredTrojan{Password: "pw"}
	trojan.Transport = &specnode.Transport{Type: "ws", Path: "/ws", Host: "cdn.example.com"}
	trojan.Security = &specnode.Security{Type: "tls", ServerName: "example.com"}
	ob = outboundOf(t, mustCompile(t, trojan))
	tr, _ := ob["transport"].(map[string]any)
	if tr["type"] != "ws" || tr["path"] != "/ws" {
		t.Fatalf("trojan transport: %v", tr)
	}
	tls, _ := ob["tls"].(map[string]any)
	if tls["server_name"] != "example.com" {
		t.Fatalf("trojan tls: %v", tls)
	}

	if featureUTLS {
		vless := baseNode(specnode.ProtocolVLESS)
		vless.VLESS = &specnode.CredVLESS{UUID: "20000000-0000-4000-8000-000000000004", Flow: "xtls-rprx-vision"}
		vless.Security = &specnode.Security{Type: "reality", ServerName: "www.example.com", PublicKey: "pk", ShortID: "0123abcd"}
		ob = outboundOf(t, mustCompile(t, vless))
		tls, _ = ob["tls"].(map[string]any)
		reality, _ := tls["reality"].(map[string]any)
		if reality["public_key"] != "pk" || reality["short_id"] != "0123abcd" {
			t.Fatalf("vless reality: %v", reality)
		}
		if tls["utls"] == nil {
			t.Fatalf("reality must carry utls fingerprint: %v", tls)
		}
	}

	if !featureQUIC {
		return // hysteria2 / tuic / wireguard compile shapes are feature-gated
	}
	hy2 := baseNode(specnode.ProtocolHysteria2)
	hy2.Hysteria2 = &specnode.CredHysteria2{Auth: "secret", ObfsType: "salamander", ObfsPassword: "obfspw"}
	hy2.Security = &specnode.Security{Type: "tls", ServerName: "hy2.example.com"}
	hy2.ExtraPorts = []string{"20000-30000"}
	ob = outboundOf(t, mustCompile(t, hy2))
	ports, _ := ob["server_ports"].([]any)
	if len(ports) != 1 || ports[0] != "20000:30000" {
		t.Fatalf("hy2 server_ports: %v", ob["server_ports"])
	}
	if ob["obfs"] == nil {
		t.Fatalf("hy2 obfs missing: %v", ob)
	}

	tuic := baseNode(specnode.ProtocolTUIC)
	tuic.TUIC = &specnode.CredTUIC{UUID: "20000000-0000-4000-8000-000000000006", Password: "pw"}
	tuic.Transport = &specnode.Transport{Type: "quic", CongestionControl: "bbr", UDPRelayMode: "native"}
	tuic.Security = &specnode.Security{Type: "tls", ServerName: "tuic.example.com"}
	ob = outboundOf(t, mustCompile(t, tuic))
	if ob["congestion_control"] != "bbr" || ob["udp_relay_mode"] != "native" {
		t.Fatalf("tuic outbound: %v", ob)
	}

	if !featureWireGuard {
		return
	}
	wg := baseNode(specnode.ProtocolWireGuard)
	wg.Port = 51820
	wg.WireGuard = &specnode.CredWireGuard{
		PrivateKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PeerPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		Addresses:     []string{"10.66.66.2/32"},
		AllowedIPs:    []string{"0.0.0.0/0"},
	}
	cfg := mustCompile(t, wg)
	eps, _ := cfg["endpoints"].([]any)
	if len(eps) != 1 {
		t.Fatalf("wireguard endpoints: %v", cfg["endpoints"])
	}
	ep, _ := eps[0].(map[string]any)
	if ep["type"] != "wireguard" || ep["tag"] != "out" {
		t.Fatalf("wireguard endpoint: %v", ep)
	}
	if route, _ := cfg["route"].(map[string]any); route["final"] != "out" {
		t.Fatalf("route final: %v", route)
	}
}

func TestSupportGateRejections(t *testing.T) {
	a := New(Options{})
	cases := []struct {
		name string
		node *specnode.Node
		kind kernel.Kind
	}{
		{"openvpn independent process", func() *specnode.Node {
			n := baseNode(specnode.ProtocolOpenVPN)
			n.OpenVPN = &specnode.CredOpenVPN{ConfigContent: "client\n"}
			return n
		}(), kernel.KindUnsupported},
		{"legacy ss method", func() *specnode.Node {
			n := baseNode(specnode.ProtocolShadowsocks)
			n.Shadowsocks = &specnode.CredShadowsocks{Method: "aes-256-cfb", Password: "pw"}
			return n
		}(), kernel.KindUnsupported},
		{"kcp transport", func() *specnode.Node {
			n := baseNode(specnode.ProtocolVMess)
			n.VMess = &specnode.CredVMess{UUID: "20000000-0000-4000-8000-000000000003"}
			n.Transport = &specnode.Transport{Type: "kcp"}
			return n
		}(), kernel.KindUnsupported},
		{"trojan without tls", func() *specnode.Node {
			n := baseNode(specnode.ProtocolTrojan)
			n.Trojan = &specnode.CredTrojan{Password: "pw"}
			return n
		}(), kernel.KindUnsupported},
	}
	for _, tc := range cases {
		err := a.ValidateSpec(context.Background(), tc.node)
		if err == nil {
			t.Errorf("%s: ValidateSpec passed, want %s", tc.name, tc.kind)
		} else if kernel.KindOf(err) != tc.kind {
			t.Errorf("%s: kind = %s, want %s (err: %v)", tc.name, kernel.KindOf(err), tc.kind, err)
		}
	}
}

// Every combination in the spec support table must project inside
// the kernel-facing capability matrix (projection consistency).
func TestCapabilitiesConsistency(t *testing.T) {
	a := New(Options{})
	caps := a.Capabilities()
	if caps.KernelID != "sing-box" {
		t.Fatalf("KernelID = %q", caps.KernelID)
	}
	if _, ok := caps.Protocols[kernel.ProtocolOpenVPN]; ok {
		t.Fatal("openvpn must not appear in the in-process adapter matrix")
	}
	if _, ok := caps.Protocols[kernel.ProtocolAnyTLS]; ok {
		t.Fatal("anytls must not appear until it passes interop verification (book 4.1 tier 2)")
	}
	if v := linkedSingBoxVersion(); v != "" && v != singBoxVersion {
		t.Fatalf("pinned version %s drifts from linked module version %s", singBoxVersion, v)
	}
	// Spot-projections:
	probes := []*specnode.Node{}
	ss := baseNode(specnode.ProtocolShadowsocks)
	ss.Shadowsocks = &specnode.CredShadowsocks{Method: "aes-256-gcm", Password: "pw"}
	probes = append(probes, ss)
	vl := baseNode(specnode.ProtocolVLESS)
	vl.VLESS = &specnode.CredVLESS{UUID: "20000000-0000-4000-8000-000000000004"}
	vl.Security = &specnode.Security{Type: "tls", ServerName: "x"}
	probes = append(probes, vl)
	for _, n := range probes {
		kn := n.ProjectKernel()
		if !caps.SupportsNode(kn) {
			t.Errorf("projection of %s/%s/%s outside kernel matrix",
				kn.Protocol, kn.Transport.Type, kn.Security.Type)
		}
	}
	// Kernel version string must be the pinned release.
	if !strings.HasPrefix(caps.KernelVersion, "1.14") {
		t.Fatalf("KernelVersion = %q", caps.KernelVersion)
	}
}
