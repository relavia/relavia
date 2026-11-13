package openvpn

import (
	"strings"
	"testing"

	"openproxy/core/specnode"
)

func passthroughNode(content string) *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "11111111-1111-1111-1111-111111111111",
		Name:          "test",
		Protocol:      specnode.ProtocolOpenVPN,
		OpenVPN:       &specnode.CredOpenVPN{ConfigContent: content},
		Source:        specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "self"},
	}
}

const sampleBody = `# vpn gate style sample
client
dev tun
proto tcp
remote 203.0.113.7 443
cipher AES-128-CBC
data-ciphers AES-128-CBC
auth SHA1
resolv-retry infinite
nobind
persist-key
persist-tun
management 127.0.0.1 9999
daemon
log /tmp/evil.log
status /tmp/evil.status 10
plugin /tmp/evil.so
up /tmp/evil.sh
user nobody
auth-user-pass /tmp/creds.txt
verb 3
<ca>
-----BEGIN CERTIFICATE-----
FAKECA
-----END CERTIFICATE-----
</ca>
`

func TestPassthroughRewrite(t *testing.T) {
	bc, err := buildConfig(passthroughNode(sampleBody), buildOptions{
		mgmtLines: []string{"management /tmp/x/mgmt.sock unix"},
	})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	mustContain := []string{
		"remote 203.0.113.7 443",
		"-----BEGIN CERTIFICATE-----",
		"management /tmp/x/mgmt.sock unix",
		"management-query-passwords",
		"\nauth-user-pass\n", // rewritten to bare form (management answers)
	}
	for _, s := range mustContain {
		if !strings.Contains(bc.text, s) {
			t.Errorf("generated config missing %q\n---\n%s", s, bc.text)
		}
	}
	mustNotContain := []string{
		"management 127.0.0.1 9999",
		"daemon",
		"/tmp/evil.log",
		"/tmp/evil.status",
		"/tmp/evil.so",
		"/tmp/evil.sh",
		"user nobody",
		"/tmp/creds.txt",
	}
	for _, s := range mustNotContain {
		if strings.Contains(bc.text, s) {
			t.Errorf("generated config must not contain %q\n---\n%s", s, bc.text)
		}
	}
	if bc.proto != "tcp" {
		t.Errorf("proto = %q, want tcp", bc.proto)
	}
	for _, want := range []string{"management", "daemon", "log", "status", "plugin", "up", "user"} {
		found := false
		for _, r := range bc.rewritten {
			if r == want {
				found = true
			}
		}
		if !found {
			t.Errorf("rewritten list missing %q (got %v)", want, bc.rewritten)
		}
	}
}

func TestPassthroughNoRemoteFails(t *testing.T) {
	_, err := buildConfig(passthroughNode("client\ndev tun\n"), buildOptions{})
	if err == nil {
		t.Fatal("expected error for config without remote")
	}
}

func TestPassthroughDevOverride(t *testing.T) {
	bc, err := buildConfig(passthroughNode(sampleBody), buildOptions{devOverride: "null"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bc.text, "\ndev null\n") {
		t.Errorf("dev override not applied:\n%s", bc.text)
	}
	if strings.Contains(bc.text, "dev tun") {
		t.Errorf("original dev tun survived override")
	}
}

func structuredNode() *specnode.Node {
	dir := 1
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "22222222-2222-2222-2222-222222222222",
		Name:          "structured",
		Protocol:      specnode.ProtocolOpenVPN,
		Server:        "198.51.100.9",
		Port:          1194,
		OpenVPN: &specnode.CredOpenVPN{
			Proto:           "tcp",
			DataCiphers:     "AES-256-GCM",
			CACert:          "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
			ClientCert:      "-----BEGIN CERTIFICATE-----\nCT\n-----END CERTIFICATE-----",
			ClientKey:       "-----BEGIN PRIVATE KEY-----\nCK\n-----END PRIVATE KEY-----",
			TLSAuthKey:      "-----BEGIN OpenVPN Static key V1-----\nTA\n-----END OpenVPN Static key V1-----",
			KeyDirection:    &dir,
			RedirectGateway: true,
			Username:        "alice",
			Password:        "s3cret",
		},
		Source: specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "self"},
	}
}

func TestStructuredBuild(t *testing.T) {
	bc, err := buildConfig(structuredNode(), buildOptions{
		mgmtLines: []string{"management /tmp/x/mgmt.sock unix"},
	})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	for _, s := range []string{
		"client\n", "dev tun\n", "proto tcp-client\n",
		"remote 198.51.100.9 1194\n",
		"remote-cert-tls server\n",
		"data-ciphers AES-256-GCM\n",
		"<ca>\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n</ca>",
		"<cert>", "<key>",
		"key-direction 1\n<tls-auth>",
		"redirect-gateway def1\n",
		"auth-user-pass\n",
		"auth-nocache\n", // because usesAuth
		"management-query-passwords\n",
	} {
		if !strings.Contains(bc.text, s) {
			t.Errorf("structured config missing %q\n---\n%s", s, bc.text)
		}
	}
	if bc.proto != "tcp" || !bc.usesAuth {
		t.Errorf("proto=%q usesAuth=%v, want tcp/true", bc.proto, bc.usesAuth)
	}
	// The password itself must never be rendered into the config.
	if strings.Contains(bc.text, "s3cret") {
		t.Error("password leaked into generated config text")
	}
}

func TestStructuredRequiresCA(t *testing.T) {
	n := structuredNode()
	n.OpenVPN.CACert = ""
	if _, err := buildConfig(n, buildOptions{}); err == nil {
		t.Fatal("expected error when structured node has no CA")
	}
}

func TestRedactor(t *testing.T) {
	n := structuredNode()
	r := newRedactor(n)
	got := r.line("user alice typed s3cret twice: s3cret")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "alice") {
		t.Errorf("redaction failed: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("expected mask in %q", got)
	}
}
