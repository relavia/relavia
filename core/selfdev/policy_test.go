package selfdev

import (
	"net/netip"
	"testing"

	"openproxy/core/kernel"
	"openproxy/core/routecfg"
)

// Step 11 semantics, evaluator level (the forwarding-plane
// counterpart of core/routecfg's compile tests and
// core/singbox's step11 leak rig): class order A-E, the DNS
// mirror, and the plane's honest refusals.

func mustEval(t *testing.T, p routecfg.Policy) *policyEval {
	t.Helper()
	ev, err := compilePolicyEval(&p)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return ev
}

func ip(s string) *netip.Addr {
	a := netip.MustParseAddr(s)
	return &a
}

func basePolicy() routecfg.Policy {
	return routecfg.Policy{
		Mode: routecfg.ModeRule,
		DNS: routecfg.DNSPolicy{
			Remote: routecfg.DNSServerSpec{Type: "tls", Server: "1.1.1.1"},
			Local:  routecfg.DNSServerSpec{Type: "local"},
		},
	}
}

func TestEvalClassBBlockBeatsDirect(t *testing.T) {
	p := basePolicy()
	// Direct declared BEFORE the block on purpose: class B
	// must win regardless of declared order across classes.
	p.Rules = []routecfg.Rule{
		{Match: routecfg.Match{DomainSuffixes: []string{"example.com"}}, Action: routecfg.ActionDirect},
		{Match: routecfg.Match{DomainSuffixes: []string{"example.com"}}, Action: routecfg.ActionBlock},
	}
	ev := mustEval(t, p)
	if got := ev.decide("www.example.com", nil, 443); got != routecfg.ActionBlock {
		t.Fatalf("block must beat direct across classes, got %s", got)
	}
}

func TestEvalClassAIPv6Off(t *testing.T) {
	p := basePolicy()
	p.IPv6 = routecfg.IPv6Off
	p.Rules = []routecfg.Rule{
		{Match: routecfg.Match{IPCIDRs: []string{"::1/128"}}, Action: routecfg.ActionDirect},
	}
	ev := mustEval(t, p)
	if got := ev.decide("", ip("::1"), 80); got != routecfg.ActionBlock {
		t.Fatalf("ipv6 off must reject v6 ahead of user rules, got %s", got)
	}
	if got := ev.decide("", ip("127.0.0.1"), 80); got == routecfg.ActionBlock {
		t.Fatalf("ipv6 off must not touch v4, got %s", got)
	}
}

func TestEvalClassCIPv6Tunnel(t *testing.T) {
	p := basePolicy()
	p.IPv6 = routecfg.IPv6Tunnel
	p.BypassPrivate = true
	ev := mustEval(t, p)
	// Even a private v6 (class E candidate) may only tunnel.
	if got := ev.decide("", ip("fd00::1"), 80); got != routecfg.ActionProxy {
		t.Fatalf("ipv6 tunnel: v6 must go to the node, got %s", got)
	}
	// v4 private still bypasses.
	if got := ev.decide("", ip("192.168.1.1"), 80); got != routecfg.ActionDirect {
		t.Fatalf("ipv6 tunnel must not change v4 private bypass, got %s", got)
	}
}

func TestEvalClassDOrderAndE(t *testing.T) {
	p := basePolicy()
	p.BypassPrivate = true
	p.Rules = []routecfg.Rule{
		{Match: routecfg.Match{IPCIDRs: []string{"192.168.0.0/16"}}, Action: routecfg.ActionProxy},
		{Match: routecfg.Match{DomainSuffixes: []string{"corp.test"}}, Action: routecfg.ActionDirect},
	}
	ev := mustEval(t, p)
	// User proxy rule for the private range beats class E.
	if got := ev.decide("", ip("192.168.1.5"), 80); got != routecfg.ActionProxy {
		t.Fatalf("user rule must outrank private bypass, got %s", got)
	}
	// Unlisted private target takes class E.
	if got := ev.decide("", ip("10.0.0.9"), 80); got != routecfg.ActionDirect {
		t.Fatalf("class E private bypass missing, got %s", got)
	}
	// Declared order inside class D.
	if got := ev.decide("mail.corp.test", nil, 25); got != routecfg.ActionDirect {
		t.Fatalf("class D direct rule missed, got %s", got)
	}
	// Final is the node.
	if got := ev.decide("www.other.test", nil, 443); got != routecfg.ActionProxy {
		t.Fatalf("final must be proxy, got %s", got)
	}
}

func TestEvalGlobalMode(t *testing.T) {
	p := basePolicy()
	p.Mode = routecfg.ModeGlobal
	p.Rules = []routecfg.Rule{
		{Match: routecfg.Match{DomainSuffixes: []string{"bad.test"}}, Action: routecfg.ActionBlock},
	}
	ev := mustEval(t, p)
	if got := ev.decide("x.bad.test", nil, 80); got != routecfg.ActionBlock {
		t.Fatalf("global mode keeps blocks, got %s", got)
	}
	if got := ev.decide("anything.test", nil, 80); got != routecfg.ActionProxy {
		t.Fatalf("global mode: everything else to the node, got %s", got)
	}
	if got := ev.dnsRoute("anything.test"); got != dnsRemote {
		t.Fatalf("global mode DNS must be remote-only, got %v", got)
	}
	if got := ev.dnsRoute("x.bad.test"); got != dnsReject {
		t.Fatalf("global mode DNS must still mirror blocks, got %v", got)
	}
	// A direct rule in global mode is a policy error (routecfg
	// rejects it; the plane must accept exactly the same set).
	p.Rules = append(p.Rules, routecfg.Rule{
		Match: routecfg.Match{DomainSuffixes: []string{"x.test"}}, Action: routecfg.ActionDirect})
	if _, err := compilePolicyEval(&p); err == nil {
		t.Fatal("direct rule in global mode must be rejected")
	}
}

func TestEvalDNSMirror(t *testing.T) {
	p := basePolicy()
	p.Rules = []routecfg.Rule{
		{Match: routecfg.Match{DomainSuffixes: []string{"direct.test"}}, Action: routecfg.ActionDirect},
		{Match: routecfg.Match{DomainSuffixes: []string{"blocked.test"}}, Action: routecfg.ActionBlock},
		// A port-carrying direct rule is NOT mirrored (its
		// decision needs a fact a DNS query does not have).
		{Match: routecfg.Match{DomainSuffixes: []string{"porty.test"}, Ports: []int{443}}, Action: routecfg.ActionDirect},
		// An IP-carrying rule is not mirrored either.
		{Match: routecfg.Match{IPCIDRs: []string{"203.0.113.0/24"}}, Action: routecfg.ActionDirect},
	}
	ev := mustEval(t, p)
	if got := ev.dnsRoute("www.direct.test"); got != dnsLocal {
		t.Fatalf("mirrored direct name must resolve locally, got %v", got)
	}
	if got := ev.dnsRoute("www.blocked.test"); got != dnsReject {
		t.Fatalf("mirrored block name must be rejected, got %v", got)
	}
	if got := ev.dnsRoute("www.porty.test"); got != dnsRemote {
		t.Fatalf("port-carrying rule must not be mirrored, got %v", got)
	}
	if got := ev.dnsRoute("unlisted.test"); got != dnsRemote {
		t.Fatalf("unlisted name must resolve remotely (no plaintext fallback), got %v", got)
	}
	// ... while the ROUTE decision for the porty name still
	// honours its rule once the port is known.
	if got := ev.decide("www.porty.test", nil, 443); got != routecfg.ActionDirect {
		t.Fatalf("port rule must decide at route time, got %s", got)
	}
	if got := ev.decide("www.porty.test", nil, 80); got != routecfg.ActionProxy {
		t.Fatalf("port rule must not fire on other ports, got %s", got)
	}
	if !ev.needsIPPhase {
		t.Fatal("IP-carrying rule must set needsIPPhase")
	}
}

func TestEvalInlineRuleSets(t *testing.T) {
	p := basePolicy()
	p.RuleSets = []routecfg.RuleSetRef{
		{Tag: "corp", Kind: routecfg.RuleSetKindDomain, Type: "inline",
			Inline: []routecfg.Match{{DomainSuffixes: []string{"corp.test"}}}},
		{Tag: "ranges", Kind: routecfg.RuleSetKindIP, Type: "inline",
			Inline: []routecfg.Match{{IPCIDRs: []string{"198.51.100.0/24"}}}},
	}
	p.Rules = []routecfg.Rule{
		{Match: routecfg.Match{RuleSets: []string{"corp"}}, Action: routecfg.ActionDirect},
		{Match: routecfg.Match{RuleSets: []string{"ranges"}}, Action: routecfg.ActionDirect},
	}
	ev := mustEval(t, p)
	if got := ev.decide("mail.corp.test", nil, 80); got != routecfg.ActionDirect {
		t.Fatalf("inline domain set not evaluated, got %s", got)
	}
	if got := ev.dnsRoute("mail.corp.test"); got != dnsLocal {
		t.Fatalf("inline domain set must mirror to local DNS, got %v", got)
	}
	if got := ev.decide("", ip("198.51.100.7"), 80); got != routecfg.ActionDirect {
		t.Fatalf("inline IP set not evaluated, got %s", got)
	}
}

func TestEvalRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*routecfg.Policy)
	}{
		{"protocol matcher", func(p *routecfg.Policy) {
			p.Rules = []routecfg.Rule{{Match: routecfg.Match{Protocols: []string{"tls"}}, Action: routecfg.ActionBlock}}
		}},
		{"process matcher", func(p *routecfg.Policy) {
			p.Rules = []routecfg.Rule{{Match: routecfg.Match{ProcessNames: []string{"x.exe"}}, Action: routecfg.ActionBlock}}
		}},
		{"remote rule set", func(p *routecfg.Policy) {
			p.RuleSets = []routecfg.RuleSetRef{{Tag: "geo", Type: "remote", URL: "https://example.com/x.srs"}}
			p.Rules = []routecfg.Rule{{Match: routecfg.Match{RuleSets: []string{"geo"}}, Action: routecfg.ActionBlock}}
		}},
		{"local rule set", func(p *routecfg.Policy) {
			p.RuleSets = []routecfg.RuleSetRef{{Tag: "geo", Type: "local", Path: "/tmp/x.srs"}}
			p.Rules = []routecfg.Rule{{Match: routecfg.Match{RuleSets: []string{"geo"}}, Action: routecfg.ActionBlock}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := basePolicy()
			tc.mutate(&p)
			_, err := compilePolicyEval(&p)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !kernel.IsKind(err, kernel.KindUnsupported) {
				t.Fatalf("refusal kind = %v, want unsupported (%v)", err, err)
			}
		})
	}
}

func TestEvalNilPolicy(t *testing.T) {
	ev, err := compilePolicyEval(nil)
	if err != nil || ev != nil {
		t.Fatalf("nil policy must compile to nil eval, got %v %v", ev, err)
	}
	if got := ev.decide("anything.test", nil, 80); got != routecfg.ActionProxy {
		t.Fatalf("nil policy: everything to the node, got %s", got)
	}
	if got := ev.dnsRoute("anything.test"); got != dnsRemote {
		t.Fatalf("nil policy DNS must be remote (egress-side), got %v", got)
	}
}
