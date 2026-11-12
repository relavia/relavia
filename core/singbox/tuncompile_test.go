package singbox

import (
	"encoding/json"
	"testing"

	"openproxy/core/kernel"
	"openproxy/core/routecfg"
	"openproxy/core/specnode"
)

// Tests for CompileTunConfig (libbox binding): the tun inbound
// must carry exactly the interface parameters the shell
// establishes (app/platform.DefaultTUNRequest mirror), the
// route must force auto_detect_interface (the protect() path),
// the Step 11 fragment must be installed without being
// mutated, and the real libbox parser must accept the output.

func mustCompileTun(t *testing.T, n *specnode.Node, opts TunCompileOptions) ([]byte, map[string]any) {
	t.Helper()
	raw, err := CompileTunConfig(n, opts)
	if err != nil {
		t.Fatalf("CompileTunConfig(%s): %v", n.Protocol, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("tun config is not JSON: %v", err)
	}
	return raw, cfg
}

func tunInboundOf(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	ibs, _ := cfg["inbounds"].([]any)
	if len(ibs) != 1 {
		t.Fatalf("want exactly one inbound (tun), got %v", cfg["inbounds"])
	}
	ib, _ := ibs[0].(map[string]any)
	if ib["type"] != "tun" {
		t.Fatalf("inbound is not tun: %v", ib)
	}
	return ib
}

func TestCompileTunConfigShape(t *testing.T) {
	ss := baseNode(specnode.ProtocolShadowsocks)
	ss.Port = 8388
	ss.Shadowsocks = &specnode.CredShadowsocks{Method: "2022-blake3-aes-256-gcm", Password: "cGFzc3dvcmQ="}
	raw, cfg := mustCompileTun(t, ss, TunCompileOptions{})

	ib := tunInboundOf(t, cfg)
	if ib["tag"] != "tun-in" || ib["auto_route"] != true || ib["strict_route"] != true || ib["stack"] != "gvisor" {
		t.Fatalf("tun inbound core fields: %v", ib)
	}
	if ib["mtu"] != float64(9000) {
		t.Fatalf("tun mtu = %v, want 9000 (DefaultTUNRequest mirror)", ib["mtu"])
	}
	addrs, _ := ib["address"].([]any)
	if len(addrs) != 1 || addrs[0] != "172.18.0.1/30" {
		t.Fatalf("tun addresses = %v, want [172.18.0.1/30]", addrs)
	}
	// DNS mode is left to upstream derivation (hijack under
	// auto_route); setting it here would be a second source.
	if _, set := ib["dns_mode"]; set {
		t.Fatalf("dns_mode must stay unset for upstream derivation: %v", ib)
	}

	route, _ := cfg["route"].(map[string]any)
	if route["auto_detect_interface"] != true {
		t.Fatalf("route.auto_detect_interface must be true (protect path): %v", route)
	}
	if route["final"] != "out" {
		t.Fatalf("route.final = %v, want out", route["final"])
	}

	ob := outboundOf(t, cfg)
	if ob["type"] != "shadowsocks" || ob["tag"] != "out" {
		t.Fatalf("node outbound: %v", ob)
	}
	// libbox owns the cache file under its working path.
	if _, present := cfg["experimental"]; present {
		t.Fatalf("tun config must not carry an experimental section: %s", raw)
	}
	// Acceptance by the real libbox parser (libbox.CheckConfig)
	// is asserted in app/libboxbind's tests: libbox is not part
	// of the core module's dependency graph and must not become
	// one for a test-only import.
	_ = raw
}

func TestCompileTunConfigIPv6(t *testing.T) {
	n := baseNode(specnode.ProtocolSOCKS5)
	_, cfg := mustCompileTun(t, n, TunCompileOptions{IPv6: true})
	addrs, _ := tunInboundOf(t, cfg)["address"].([]any)
	if len(addrs) != 2 || addrs[0] != "172.18.0.1/30" || addrs[1] != "fd00::1/126" {
		t.Fatalf("ipv6 tun addresses = %v, want [172.18.0.1/30 fd00::1/126]", addrs)
	}
}

func TestCompileTunConfigWithFragment(t *testing.T) {
	n := baseNode(specnode.ProtocolShadowsocks)
	n.Shadowsocks = &specnode.CredShadowsocks{Method: "aes-256-gcm", Password: "pw"}
	frag, err := routecfg.Compile(routecfg.DefaultTUNPolicy())
	if err != nil {
		t.Fatalf("default TUN fragment: %v", err)
	}
	if _, pre := frag.Route["auto_detect_interface"]; pre {
		t.Fatal("test premise broken: fragment already carries auto_detect_interface")
	}
	_, cfg := mustCompileTun(t, n, TunCompileOptions{Fragment: frag})

	route, _ := cfg["route"].(map[string]any)
	if route["auto_detect_interface"] != true {
		t.Fatalf("fragment route lost the platform flag: %v", route)
	}
	if _, hasRules := route["rules"]; !hasRules {
		t.Fatalf("fragment rules missing from route: %v", route)
	}
	if _, hasDNS := cfg["dns"].(map[string]any); !hasDNS {
		t.Fatalf("fragment dns missing: %v", cfg)
	}
	// The shared fragment object must NOT be mutated by the
	// platform flag injection (copy-on-write route clone).
	if _, mutated := frag.Route["auto_detect_interface"]; mutated {
		t.Fatal("CompileTunConfig mutated the caller's fragment route map")
	}
}

func TestCompileTunConfigGates(t *testing.T) {
	// OpenVPN stays an independent process (Step 2 finding);
	// it must be refused by the in-process TUN compile, not
	// silently compiled into something else.
	ovpn := baseNode(specnode.ProtocolOpenVPN)
	if _, err := CompileTunConfig(ovpn, TunCompileOptions{}); err == nil {
		t.Fatalf("OpenVPN must not compile into a libbox tun config")
	}
	// Missing credential body: compile-input gate, typed error.
	bad := baseNode(specnode.ProtocolShadowsocks)
	_, err := CompileTunConfig(bad, TunCompileOptions{})
	if err == nil {
		t.Fatalf("shadowsocks without credentials must fail")
	}
	if !kernel.IsKind(err, kernel.KindInvalidConfig) {
		t.Fatalf("gate error should be kind invalid_config: %v", err)
	}
}
