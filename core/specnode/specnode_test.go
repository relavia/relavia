package specnode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openproxy/core/kernel"
)

// The Step 5 example documents are the conformance fixtures: every
// node example shipped with the frozen schema must parse and
// validate through this type layer unchanged.
func TestParseSpecExamples(t *testing.T) {
	dir := filepath.Join("..", "..", "spec", "examples", "nodes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read examples dir: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		n, err := Parse(data)
		if err != nil {
			t.Errorf("%s: Parse failed: %v", e.Name(), err)
			continue
		}
		seen[n.Protocol] = true
		// credential dispatch must have populated exactly the
		// per-protocol struct
		if n.RawCredential == nil {
			t.Errorf("%s: RawCredential lost", e.Name())
		}
		// round-trip: marshal and re-parse, compare key fields
		out, err := json.Marshal(n)
		if err != nil {
			t.Errorf("%s: Marshal failed: %v", e.Name(), err)
			continue
		}
		n2, err := Parse(out)
		if err != nil {
			t.Errorf("%s: re-Parse of round-trip failed: %v\n%s", e.Name(), err, out)
			continue
		}
		if n2.Protocol != n.Protocol || n2.Server != n.Server || n2.Port != n.Port {
			t.Errorf("%s: round-trip mismatch: %+v vs %+v", e.Name(), n2, n)
		}
	}
	for _, p := range []string{
		ProtocolShadowsocks, ProtocolTrojan, ProtocolVMess, ProtocolVLESS,
		ProtocolHysteria2, ProtocolTUIC, ProtocolWireGuard, ProtocolOpenVPN,
		ProtocolSOCKS5, ProtocolHTTP,
	} {
		if !seen[p] {
			t.Errorf("no example parsed for protocol %s", p)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() *Node {
		return &Node{
			SchemaVersion: "1.0",
			ID:            "10000000-0000-4000-8000-000000000001",
			Name:          "x",
			Protocol:      ProtocolVLESS,
			Server:        "example.com",
			Port:          443,
			VLESS:         &CredVLESS{UUID: "20000000-0000-4000-8000-000000000004"},
			Source:        SourceRef{Kind: "manual", Ref: "manual-entry", Authorization: "user-provided"},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Node)
	}{
		{"bad schema version", func(n *Node) { n.SchemaVersion = "2.0" }},
		{"bad id", func(n *Node) { n.ID = "n1" }},
		{"empty server", func(n *Node) { n.Server = "" }},
		{"port range", func(n *Node) { n.Port = 70000 }},
		{"reality without public key", func(n *Node) {
			n.Security = &Security{Type: "reality", ServerName: "www.example.com"}
		}},
		{"none with tls fields", func(n *Node) {
			n.Security = &Security{Type: "none", ServerName: "x"}
		}},
		{"bad transport for protocol", func(n *Node) {
			n.Protocol = ProtocolShadowsocks
			n.VLESS = nil
			n.Shadowsocks = &CredShadowsocks{Method: "aes-256-gcm", Password: "pw"}
			n.Transport = &Transport{Type: "ws"}
		}},
		{"legacy-but-listed ss method ok, unlisted rejected", func(n *Node) {
			n.Protocol = ProtocolShadowsocks
			n.VLESS = nil
			n.Shadowsocks = &CredShadowsocks{Method: "aes-256-cfb", Password: "pw"}
			n.Transport = &Transport{Type: "kcp"} // also wrong transport; method checked after transport
		}},
		{"missing source authorization", func(n *Node) { n.Source.Authorization = "" }},
		{"wireguard bad key", func(n *Node) {
			n.Protocol = ProtocolWireGuard
			n.VLESS = nil
			n.WireGuard = &CredWireGuard{PrivateKey: "short", PeerPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", Addresses: []string{"10.0.0.2/32"}}
		}},
	}
	for _, tc := range cases {
		n := base()
		tc.mutate(n)
		err := n.Validate()
		if err == nil {
			t.Errorf("%s: Validate passed, want error", tc.name)
		} else if !kernel.IsKind(err, kernel.KindInvalidConfig) {
			t.Errorf("%s: error kind = %v, want invalid_config (%v)", tc.name, kernel.KindOf(err), err)
		}
	}
}

func TestProjectionCoordinates(t *testing.T) {
	// VLESS + Reality over TCP stays vless/tcp/reality.
	n := &Node{
		Protocol: ProtocolVLESS,
		Server:   "s", Port: 443,
		Transport: &Transport{Type: "tcp"},
		Security:  &Security{Type: "reality", PublicKey: "pk", Fingerprint: "chrome"},
		VLESS:     &CredVLESS{UUID: "20000000-0000-4000-8000-000000000004", Flow: "xtls-rprx-vision"},
	}
	kn := n.ProjectKernel()
	if kn.Protocol != kernel.ProtocolVLESS || kn.Transport.Type != kernel.TransportTCP ||
		kn.Security.Type != kernel.SecurityReality {
		t.Fatalf("projection = %s/%s/%s", kn.Protocol, kn.Transport.Type, kn.Security.Type)
	}
	if kn.Credential.Flow != "xtls-rprx-vision" || kn.Security.PublicKey != "pk" {
		t.Fatalf("projection lost flow/publicKey: %+v", kn)
	}

	// Shadowsocks native transport + protocol-native crypto.
	ss := &Node{
		Protocol: ProtocolShadowsocks,
		Server:   "s", Port: 8388,
		Shadowsocks: &CredShadowsocks{Method: "aes-256-gcm", Password: "pw"},
	}
	kn = ss.ProjectKernel()
	if kn.Transport.Type != kernel.TransportNative || kn.Security.Type != kernel.SecurityAEAD {
		t.Fatalf("ss projection = %s/%s", kn.Transport.Type, kn.Security.Type)
	}

	// VMess gRPC carries through; VMess no-security projects to aead.
	vm := &Node{
		Protocol: ProtocolVMess,
		Server:   "s", Port: 443,
		Transport: &Transport{Type: "grpc", ServiceName: "svc"},
		VMess:     &CredVMess{UUID: "20000000-0000-4000-8000-000000000003"},
	}
	kn = vm.ProjectKernel()
	if kn.Transport.Type != kernel.TransportGRPC || kn.Security.Type != kernel.SecurityAEAD {
		t.Fatalf("vmess projection = %s/%s", kn.Transport.Type, kn.Security.Type)
	}
}

func TestFromKernelRoundTrip(t *testing.T) {
	kn := &kernel.Node{
		ID: "n1", Name: "示例", Protocol: kernel.ProtocolVLESS,
		Server: "example.com", Port: 443,
		Credential: kernel.Credential{UUID: "20000000-0000-4000-8000-000000000004", Flow: "xtls-rprx-vision"},
		Transport:  kernel.Transport{Type: kernel.TransportTCP},
		Security:   kernel.Security{Type: kernel.SecurityReality, PublicKey: "pk", Fingerprint: "chrome"},
	}
	n := FromKernel(kn)
	if n.Protocol != ProtocolVLESS || n.VLESS == nil || n.VLESS.Flow != "xtls-rprx-vision" {
		t.Fatalf("FromKernel vless: %+v", n)
	}
	if n.SecurityType() != "reality" || n.Security.PublicKey != "pk" {
		t.Fatalf("FromKernel security: %+v", n.Security)
	}
	if n.TransportType() != "tcp" {
		t.Fatalf("FromKernel transport: %+v", n.Transport)
	}
}
