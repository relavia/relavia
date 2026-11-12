package routecfg

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// --- a semantic evaluator over compiled fragments -------------
//
// The evaluator re-implements sing-box's documented rule
// semantics (first match wins; conditions ANDed; values inside
// one field ORed) restricted to the field subset this package
// emits. It exists so precedence is tested as BEHAVIOUR —
// "which outbound does this target get" — not just as JSON
// shape.

type target struct {
	domain   string
	ip       netip.Addr
	port     int
	protocol string
	process  string
	sets     map[string]bool // rule-set tags whose content matches this target
}

func (tg target) ipVersion() int {
	if tg.ip.IsValid() {
		if tg.ip.Is6() {
			return 6
		}
		return 4
	}
	return 0
}

func decide(t *testing.T, route map[string]any, tg target) string {
	t.Helper()
	rules, _ := route["rules"].([]any)
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		if ruleMatches(rule, tg) {
			if rule["action"] == "reject" {
				return "reject"
			}
			if ob, ok := rule["outbound"].(string); ok {
				return ob
			}
			t.Fatalf("rule without action or outbound: %v", rule)
		}
	}
	final, _ := route["final"].(string)
	return final
}

func ruleMatches(rule map[string]any, tg target) bool {
	for key, raw := range rule {
		switch key {
		case "outbound", "action":
			continue
		case "domain":
			if !anyStr(raw, func(s string) bool { return tg.domain == s }) {
				return false
			}
		case "domain_suffix":
			if !anyStr(raw, func(s string) bool {
				s = strings.TrimPrefix(s, ".")
				return tg.domain == s || strings.HasSuffix(tg.domain, "."+s)
			}) {
				return false
			}
		case "domain_keyword":
			if !anyStr(raw, func(s string) bool { return strings.Contains(tg.domain, s) }) {
				return false
			}
		case "domain_regex":
			if !anyStr(raw, func(s string) bool {
				ok, _ := regexp.MatchString(s, tg.domain)
				return ok
			}) {
				return false
			}
		case "ip_cidr":
			if !anyStr(raw, func(s string) bool {
				pfx, err := netip.ParsePrefix(s)
				return err == nil && tg.ip.IsValid() && pfx.Contains(tg.ip)
			}) {
				return false
			}
		case "ip_is_private":
			if raw != true || !tg.ip.IsValid() || !tg.ip.IsPrivate() {
				return false
			}
		case "ip_version":
			if int(raw.(float64)) != tg.ipVersion() {
				return false
			}
		case "port":
			found := false
			for _, p := range raw.([]any) {
				if int(p.(float64)) == tg.port {
					found = true
				}
			}
			if !found {
				return false
			}
		case "port_range":
			if !anyStr(raw, func(s string) bool {
				parts := strings.Split(s, ":")
				if len(parts) != 2 {
					return false
				}
				l, e1 := atoi(parts[0])
				h, e2 := atoi(parts[1])
				return e1 == nil && e2 == nil && tg.port >= l && tg.port <= h
			}) {
				return false
			}
		case "protocol":
			if !anyStr(raw, func(s string) bool { return tg.protocol == s }) {
				return false
			}
		case "process_name":
			if !anyStr(raw, func(s string) bool { return tg.process == s }) {
				return false
			}
		case "rule_set":
			if !anyStr(raw, func(s string) bool { return tg.sets[s] }) {
				return false
			}
		default:
			// Unknown emitted field: the evaluator must not
			// silently pass a rule it cannot evaluate.
			panic("evaluator: unhandled rule field " + key)
		}
	}
	return true
}

func atoi(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errSyntax
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errSyntax = &syntaxError{"invalid syntax"}

type syntaxError struct{ s string }

func (e *syntaxError) Error() string { return e.s }

func anyStr(raw any, pred func(string) bool) bool {
	list, _ := raw.([]any)
	for _, v := range list {
		if s, ok := v.(string); ok && pred(s) {
			return true
		}
	}
	return false
}

// roundTrip pushes a fragment through JSON so the evaluator
// sees exactly what sing-box would parse (numbers as float64,
// etc.).
func roundTrip(t *testing.T, f *Fragment) (route, dns map[string]any) {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Route map[string]any `json:"route"`
		DNS   map[string]any `json:"dns"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	return back.Route, back.DNS
}

func basePolicy() Policy {
	return Policy{
		Mode: ModeRule,
		DNS: DNSPolicy{
			Remote: DNSServerSpec{Type: "tls", Server: "1.1.1.1", Port: 853},
			Local:  DNSServerSpec{Type: "local"},
		},
	}
}

// --- precedence behaviour ---------------------------------------

func TestPrecedenceBlockBeatsDirectRegardlessOfOrder(t *testing.T) {
	p := basePolicy()
	p.Rules = []Rule{
		{Match: Match{DomainSuffixes: []string{"example.com"}}, Action: ActionDirect},
		{Match: Match{Domains: []string{"ads.example.com"}}, Action: ActionBlock},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	if got := decide(t, route, target{domain: "ads.example.com"}); got != "reject" {
		t.Fatalf("blocked subdomain: got %s, want reject (class B must outrank the earlier direct rule)", got)
	}
	if got := decide(t, route, target{domain: "www.example.com"}); got != OutboundDirect {
		t.Fatalf("plain subdomain: got %s, want direct", got)
	}
}

func TestPrecedenceUserOrderWithinClassD(t *testing.T) {
	p := basePolicy()
	p.Rules = []Rule{
		{Match: Match{DomainSuffixes: []string{"corp.example"}}, Action: ActionDirect},
		{Match: Match{DomainKeywords: []string{"corp"}}, Action: ActionProxy},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	if got := decide(t, route, target{domain: "mail.corp.example"}); got != OutboundDirect {
		t.Fatalf("first declared rule must win inside class D: got %s", got)
	}
	if got := decide(t, route, target{domain: "corp.other.net"}); got != OutboundProxy {
		t.Fatalf("keyword proxy rule: got %s", got)
	}
	if got := decide(t, route, target{domain: "unrelated.org"}); got != OutboundProxy {
		t.Fatalf("unmatched target must fall to final=out: got %s", got)
	}
}

func TestPrecedencePrivateBypassBelowUserRules(t *testing.T) {
	p := basePolicy()
	p.BypassPrivate = true
	p.Rules = []Rule{
		{Match: Match{IPCIDRs: []string{"10.0.0.0/8"}}, Action: ActionProxy},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	if got := decide(t, route, target{ip: netip.MustParseAddr("10.1.2.3")}); got != OutboundProxy {
		t.Fatalf("user rule for 10/8 must beat the private bypass: got %s", got)
	}
	if got := decide(t, route, target{ip: netip.MustParseAddr("192.168.1.1")}); got != OutboundDirect {
		t.Fatalf("private target without a user rule must bypass: got %s", got)
	}
	if got := decide(t, route, target{ip: netip.MustParseAddr("8.8.8.8")}); got != OutboundProxy {
		t.Fatalf("public target: got %s, want final out", got)
	}
}

func TestPrecedenceIPv6OffIsAbsolute(t *testing.T) {
	p := basePolicy()
	p.IPv6 = IPv6Off
	p.BypassPrivate = true
	p.Rules = []Rule{
		{Match: Match{DomainSuffixes: []string{"example.com"}}, Action: ActionDirect},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, dns := roundTrip(t, frag)
	v6 := target{domain: "www.example.com", ip: netip.MustParseAddr("2001:db8::1")}
	if got := decide(t, route, v6); got != "reject" {
		t.Fatalf("ipv6 off must reject even a direct-listed v6 target: got %s", got)
	}
	if dns["strategy"] != "ipv4_only" {
		t.Fatalf("ipv6 off must set dns strategy ipv4_only, got %v", dns["strategy"])
	}
}

func TestPrecedenceIPv6TunnelBeatsDirectButNotBlock(t *testing.T) {
	p := basePolicy()
	p.IPv6 = IPv6Tunnel
	p.Rules = []Rule{
		{Match: Match{DomainSuffixes: []string{"example.com"}}, Action: ActionDirect},
		{Match: Match{Domains: []string{"bad.example.com"}}, Action: ActionBlock},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	v6 := target{domain: "www.example.com", ip: netip.MustParseAddr("2001:db8::5")}
	if got := decide(t, route, v6); got != OutboundProxy {
		t.Fatalf("ipv6 tunnel: v6 must take the tunnel over a direct rule: got %s", got)
	}
	v6bad := target{domain: "bad.example.com", ip: netip.MustParseAddr("2001:db8::6")}
	if got := decide(t, route, v6bad); got != "reject" {
		t.Fatalf("ipv6 tunnel: block (class B) still outranks the v6 tunnel rule (class C): got %s", got)
	}
	v4 := target{domain: "www.example.com", ip: netip.MustParseAddr("93.184.216.34")}
	if got := decide(t, route, v4); got != OutboundDirect {
		t.Fatalf("ipv6 tunnel must not disturb v4 direct rules: got %s", got)
	}
}

func TestGlobalModeEmitsNoDirectPath(t *testing.T) {
	p := basePolicy()
	p.Mode = ModeGlobal
	p.BypassPrivate = true // must be ignored in global mode
	p.Rules = []Rule{
		{Match: Match{Domains: []string{"tracker.example"}}, Action: ActionBlock},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	rules, _ := route["rules"].([]any)
	for _, raw := range rules {
		if raw.(map[string]any)["outbound"] == OutboundDirect {
			t.Fatalf("global mode emitted a direct rule: %v", raw)
		}
	}
	if got := decide(t, route, target{ip: netip.MustParseAddr("192.168.0.1")}); got != OutboundProxy {
		t.Fatalf("global mode: even private targets go to the node: got %s", got)
	}
	if got := decide(t, route, target{domain: "tracker.example"}); got != "reject" {
		t.Fatalf("global mode: blocks still apply: got %s", got)
	}
}

func TestRuleSetAndProcessAndPortMatchers(t *testing.T) {
	p := basePolicy()
	p.RuleSets = []RuleSetRef{
		{Tag: "cat-cn", Kind: RuleSetKindDomain, Type: "remote", Format: "binary", URL: "https://example.invalid/geosite-cn.srs", DownloadViaProxy: true},
	}
	p.Rules = []Rule{
		{Match: Match{RuleSets: []string{"cat-cn"}}, Action: ActionDirect},
		{Match: Match{Ports: []int{25}, Protocols: []string{"tls"}}, Action: ActionBlock},
		{Match: Match{ProcessNames: []string{"game.exe"}, PortRanges: []string{"8000:9000"}}, Action: ActionProxy},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	if got := decide(t, route, target{sets: map[string]bool{"cat-cn": true}}); got != OutboundDirect {
		t.Fatalf("rule-set rule: got %s", got)
	}
	if got := decide(t, route, target{port: 25, protocol: "tls"}); got != "reject" {
		t.Fatalf("port+protocol block: got %s", got)
	}
	if got := decide(t, route, target{port: 25, protocol: "http"}); got != OutboundProxy {
		t.Fatalf("AND semantics: port without the protocol must not match the block: got %s", got)
	}
	if got := decide(t, route, target{process: "game.exe", port: 8443}); got != OutboundProxy {
		t.Fatalf("process+range rule: got %s", got)
	}
	sets, _ := route["rule_set"].([]any)
	if len(sets) != 1 || sets[0].(map[string]any)["download_detour"] != OutboundProxy {
		t.Fatalf("remote rule set must carry download_detour=out when DownloadViaProxy: %v", sets)
	}
}

// --- DNS compilation ----------------------------------------------

func dnsRuleFor(t *testing.T, dns map[string]any, domain string) map[string]any {
	t.Helper()
	rules, _ := dns["rules"].([]any)
	for _, raw := range rules {
		rule := raw.(map[string]any)
		for _, field := range []string{"domain", "domain_suffix"} {
			if anyStr(rule[field], func(s string) bool {
				return domain == s || (field == "domain_suffix" && strings.HasSuffix(domain, "."+s))
			}) {
				return rule
			}
		}
	}
	return nil
}

func TestDNSMirrorPureDomainRulesOnly(t *testing.T) {
	p := basePolicy()
	p.Rules = []Rule{
		{Match: Match{DomainSuffixes: []string{"lan.example"}}, Action: ActionDirect},
		{Match: Match{Domains: []string{"bank.example"}}, Action: ActionProxy},
		{Match: Match{Domains: []string{"ads.example"}}, Action: ActionBlock},
		// Mixed rules must NOT mirror:
		{Match: Match{Domains: []string{"mixed.example"}, Ports: []int{443}}, Action: ActionDirect},
		{Match: Match{IPCIDRs: []string{"203.0.113.0/24"}}, Action: ActionDirect},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, dns := roundTrip(t, frag)

	if r := dnsRuleFor(t, dns, "host.lan.example"); r == nil || r["server"] != DNSServerLocal {
		t.Fatalf("direct suffix rule must mirror to local DNS: %v", r)
	}
	if r := dnsRuleFor(t, dns, "bank.example"); r == nil || r["server"] != DNSServerRemote {
		t.Fatalf("proxy domain rule must mirror to remote DNS: %v", r)
	}
	if r := dnsRuleFor(t, dns, "ads.example"); r == nil || r["action"] != "reject" {
		t.Fatalf("block domain rule must mirror to DNS reject: %v", r)
	}
	if r := dnsRuleFor(t, dns, "mixed.example"); r != nil {
		t.Fatalf("mixed domain+port rule must NOT mirror into DNS: %v", r)
	}
	if dns["final"] != DNSServerRemote {
		t.Fatalf("dns final must be the remote server (no plaintext fallback), got %v", dns["final"])
	}
}

func TestDNSServersShapeAndDetour(t *testing.T) {
	p := basePolicy()
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, dns := roundTrip(t, frag)
	servers, _ := dns["servers"].([]any)
	byTag := map[string]map[string]any{}
	for _, raw := range servers {
		s := raw.(map[string]any)
		byTag[s["tag"].(string)] = s
	}
	remote := byTag[DNSServerRemote]
	if remote["type"] != "tls" || remote["detour"] != OutboundProxy || remote["server_port"].(float64) != 853 {
		t.Fatalf("remote DNS must be DoT detoured through the node: %v", remote)
	}
	local := byTag[DNSServerLocal]
	if local["type"] != "local" {
		t.Fatalf("default local DNS is the system resolver: %v", local)
	}
	if _, leaked := local["detour"]; leaked {
		t.Fatalf("local DNS must never be detoured: %v", local)
	}
}

func TestDNSFakeIPVariant(t *testing.T) {
	p := basePolicy()
	p.DNS.FakeIP = true
	p.Rules = []Rule{
		{Match: Match{DomainSuffixes: []string{"lan.example"}}, Action: ActionDirect},
	}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, dns := roundTrip(t, frag)
	// sing-box 1.14 forbids a fakeip default server: final
	// stays remote, and the fake catch-all must be the LAST
	// dns rule, after the mirrored direct rule.
	if dns["final"] != DNSServerRemote {
		t.Fatalf("fake-ip on: dns final must stay remote, got %v", dns["final"])
	}
	rules, _ := dns["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("fake-ip on: want [direct mirror, fake catch-all], got %v", rules)
	}
	if last := rules[len(rules)-1].(map[string]any); last["server"] != DNSServerFakeIP || last["query_type"] == nil {
		t.Fatalf("last dns rule must be the fake A/AAAA catch-all: %v", last)
	}
	if first := rules[0].(map[string]any); first["server"] != DNSServerLocal {
		t.Fatalf("mirrored direct rule must precede the fake catch-all: %v", first)
	}
	found := false
	for _, raw := range dns["servers"].([]any) {
		s := raw.(map[string]any)
		if s["type"] == "fakeip" {
			found = true
			if s["inet4_range"] != "198.18.0.0/15" || s["inet6_range"] != "fc00::/18" {
				t.Fatalf("fake-ip default ranges wrong: %v", s)
			}
		}
	}
	if !found {
		t.Fatal("fake-ip server missing")
	}

	p.IPv6 = IPv6Off
	frag, err = Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, dns = roundTrip(t, frag)
	for _, raw := range dns["servers"].([]any) {
		s := raw.(map[string]any)
		if s["type"] == "fakeip" {
			if _, has6 := s["inet6_range"]; has6 {
				t.Fatal("ipv6 off: fake-ip must not hand out v6 addresses")
			}
		}
	}
}

// --- validation -----------------------------------------------------

func TestValidationRejectsBadPolicies(t *testing.T) {
	cases := map[string]func(p *Policy){
		"global with direct rule": func(p *Policy) {
			p.Mode = ModeGlobal
			p.Rules = []Rule{{Match: Match{Domains: []string{"a.example"}}, Action: ActionDirect}}
		},
		"direct-list with proxy rule": func(p *Policy) {
			p.Mode = ModeDirectList
			p.Rules = []Rule{{Match: Match{Domains: []string{"a.example"}}, Action: ActionProxy}}
		},
		"empty match": func(p *Policy) {
			p.Rules = []Rule{{Match: Match{}, Action: ActionDirect}}
		},
		"bad cidr": func(p *Policy) {
			p.Rules = []Rule{{Match: Match{IPCIDRs: []string{"999.0.0.0/8"}}, Action: ActionDirect}}
		},
		"bad port": func(p *Policy) {
			p.Rules = []Rule{{Match: Match{Ports: []int{70000}}, Action: ActionBlock}}
		},
		"bad range": func(p *Policy) {
			p.Rules = []Rule{{Match: Match{PortRanges: []string{"9000:8000"}}, Action: ActionBlock}}
		},
		"unknown rule set ref": func(p *Policy) {
			p.Rules = []Rule{{Match: Match{RuleSets: []string{"nope"}}, Action: ActionDirect}}
		},
		"duplicate rule set tag": func(p *Policy) {
			p.RuleSets = []RuleSetRef{
				{Tag: "x", Type: "inline", Inline: []Match{{Domains: []string{"a.example"}}}},
				{Tag: "x", Type: "inline", Inline: []Match{{Domains: []string{"b.example"}}}},
			}
		},
		"remote dns without server": func(p *Policy) {
			p.DNS.Remote.Server = ""
		},
		"local dns with encrypted type": func(p *Policy) {
			p.DNS.Local = DNSServerSpec{Type: "tls", Server: "192.168.1.1"}
		},
		"bad regex": func(p *Policy) {
			p.Rules = []Rule{{Match: Match{DomainRegexes: []string{"(["}}, Action: ActionBlock}}
		},
		"inline set with port rule": func(p *Policy) {
			p.RuleSets = []RuleSetRef{{Tag: "x", Type: "inline", Inline: []Match{{Ports: []int{80}}}}}
		},
	}
	for name, mutate := range cases {
		p := basePolicy()
		mutate(&p)
		if _, err := Compile(p); err == nil {
			t.Errorf("%s: Compile succeeded, want validation error", name)
		}
	}
}

func TestBareIPNormalizedToHostPrefix(t *testing.T) {
	p := basePolicy()
	p.Rules = []Rule{{Match: Match{IPCIDRs: []string{"203.0.113.7"}}, Action: ActionDirect}}
	frag, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	route, _ := roundTrip(t, frag)
	if got := decide(t, route, target{ip: netip.MustParseAddr("203.0.113.7")}); got != OutboundDirect {
		t.Fatalf("bare IP rule: got %s", got)
	}
	if got := decide(t, route, target{ip: netip.MustParseAddr("203.0.113.8")}); got != OutboundProxy {
		t.Fatalf("neighbour IP must not match a host prefix: got %s", got)
	}
}
