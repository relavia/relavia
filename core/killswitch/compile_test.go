package killswitch

import (
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{
		Mode: ModeWhenConnected,
		Endpoints: []Endpoint{
			{Address: "203.0.113.7", Port: 443}, // both protocols
			{Address: "2001:db8::7", Port: 8443, Protocols: []string{"udp"}},
			{Address: "198.51.100.9", Port: 22, Protocols: []string{"tcp"}},
		},
	}
}

func TestCompileNFTBlockScope(t *testing.T) {
	d, err := Compile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	nft := d.LinuxNFT
	for _, want := range []string{
		"table inet " + NFTTable,
		"type filter hook output priority -100",
		`oif "lo" accept`,
		`oifname "relavia0" accept`,
		"ip daddr 203.0.113.7 tcp dport 443 counter accept",
		"ip daddr 203.0.113.7 udp dport 443 counter accept",
		"ip6 daddr 2001:db8::7 udp dport 8443 counter accept",
		"ip daddr 198.51.100.9 tcp dport 22 counter accept",
		"counter drop", // the fail-safe itself, last in the chain
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("ruleset missing %q\n---\n%s", want, nft)
		}
	}
	// The drop must be the LAST rule in the chain.
	if strings.LastIndex(nft, "counter drop") < strings.LastIndex(nft, "accept") {
		t.Error("drop rule is not last: an accept follows it")
	}
}

func TestCompileNFTNoDNSException(t *testing.T) {
	// Book 5.4 / Step 11: DNS must ride the tunnel or fail.
	// There must be no port-53 exception anywhere in any
	// descriptor.
	d, err := Compile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.LinuxNFT, "53") && strings.Contains(d.LinuxNFT, "dport 53") {
		t.Errorf("nft ruleset has a DNS exception:\n%s", d.LinuxNFT)
	}
	for _, cmd := range d.LinuxIPTables {
		if strings.Contains(cmd, "--dport 53") {
			t.Errorf("iptables list has a DNS exception: %s", cmd)
		}
	}
	for _, r := range d.Windows.Rules {
		if r.RemotePort == "53" {
			t.Errorf("windows descriptor has a DNS exception: %+v", r)
		}
	}
}

func TestCompileNFTLANtoggle(t *testing.T) {
	off, _ := Compile(testConfig())
	if strings.Contains(off.LinuxNFT, "192.168.0.0/16") {
		t.Error("LAN ranges present with AllowLAN=false")
	}
	cfg := testConfig()
	cfg.AllowLAN = true
	on, _ := Compile(cfg)
	for _, want := range []string{"10.0.0.0/8", "192.168.0.0/16", "fe80::/10", "fc00::/7"} {
		if !strings.Contains(on.LinuxNFT, want) {
			t.Errorf("LAN range %s missing with AllowLAN=true", want)
		}
	}
}

func TestCompileDeterministic(t *testing.T) {
	a, _ := Compile(testConfig())
	b, _ := Compile(testConfig())
	if a.LinuxNFT != b.LinuxNFT {
		t.Error("nft compile not deterministic")
	}
	// Endpoint order in the input must not matter.
	cfg := testConfig()
	cfg.Endpoints[0], cfg.Endpoints[2] = cfg.Endpoints[2], cfg.Endpoints[0]
	c, _ := Compile(cfg)
	if a.LinuxNFT != c.LinuxNFT {
		t.Error("nft compile depends on input endpoint order")
	}
}

func TestCompileWindowsDescriptor(t *testing.T) {
	d, err := Compile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	w := d.Windows
	if w.DefaultOutboundAction != "block" {
		t.Errorf("windows default outbound = %q, want block", w.DefaultOutboundAction)
	}
	var endpointRules int
	for _, r := range w.Rules {
		if !strings.HasPrefix(r.Name, RuleNamePrefix) {
			t.Errorf("rule %q lacks the Relavia prefix (executor teardown depends on it)", r.Name)
		}
		if r.Action != "allow" || r.Direction != "out" {
			t.Errorf("rule %q: got %s/%s, descriptor must contain allow/out rules only", r.Name, r.Action, r.Direction)
		}
		if strings.Contains(r.Name, "tunnel endpoint") {
			endpointRules++
		}
	}
	// 2 (both-proto endpoint) + 1 (udp v6) + 1 (tcp) = 4.
	if endpointRules != 4 {
		t.Errorf("endpoint rules = %d, want 4", endpointRules)
	}
}

func TestCompileAndroidMappingHonest(t *testing.T) {
	d, err := Compile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	a := d.Android
	if a.Mechanism != "system-lockdown" || !a.RequiresUserOptIn {
		t.Errorf("android mapping must be system-lockdown with user opt-in: %+v", a)
	}
	if !strings.Contains(a.WithoutOptIn, "does NOT guarantee") {
		t.Error("android mapping must state the no-opt-in guarantee gap verbatim-grade")
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []Config{
		{Mode: "sometimes"},
		{Mode: ModeAlwaysOn, Endpoints: []Endpoint{{Address: "node.example.com", Port: 443}}}, // hostname
		{Mode: ModeAlwaysOn, Endpoints: []Endpoint{{Address: "203.0.113.7", Port: 0}}},
		{Mode: ModeAlwaysOn, Endpoints: []Endpoint{{Address: "203.0.113.7", Port: 70000}}},
		{Mode: ModeAlwaysOn, Endpoints: []Endpoint{{Address: "203.0.113.7", Port: 443, Protocols: []string{"sctp"}}}},
		{Mode: ModeAlwaysOn, TunnelInterface: "bad name"},
	}
	for i, cfg := range bad {
		if _, err := Compile(cfg); err == nil {
			t.Errorf("case %d: Compile(%+v) succeeded, want error", i, cfg)
		}
	}
}
