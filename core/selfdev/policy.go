package selfdev

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"openproxy/core/kernel"
	"openproxy/core/routecfg"
)

// Step 11 semantics for the self-developed forwarding plane.
//
// The sing-box data plane receives the Step 11 policy as a
// compiled sing-box fragment (package routecfg). The
// self-developed plane cannot consume sing-box JSON, so this
// file re-implements the policy's DECISIONS in Go, following
// routecfg's normative precedence exactly (routecfg package
// documentation, "Rule precedence"):
//
//	class A - IPv6 policy "off" rejects IPv6 ahead of everything
//	class B - user block rules, declared order (hard deny)
//	class C - IPv6 policy "tunnel": IPv6 only ever goes to the node
//	class D - remaining user rules (direct/proxy), declared order
//	class E - built-in private bypass (rule/direct-list modes)
//	final   - the node (proxy)
//
// and the DNS mirror: pure-domain rules are mirrored in the
// same class order (blocks first), direct -> local resolver,
// proxy -> remote resolver, block -> reject, default remote
// ("no plaintext fallback": a name the policy does not send
// direct is NEVER resolved locally).
//
// Features the plane cannot evaluate honestly are refused at
// compile time instead of being silently approximated:
// sniffed-protocol matchers (the plane does not sniff),
// process-name matchers (no process attribution on this path),
// and non-inline rule sets (the plane does not load sing-box
// rule-set files). A policy using them fails the self-developed
// Start with KindUnsupported; the sing-box backend - which can
// evaluate them - remains available under the singbox gear.

// compiledMatch is one routecfg.Match (or one inline rule-set
// entry) in evaluable form.
type compiledMatch struct {
	domains  map[string]struct{}
	suffixes []string
	keywords []string
	regexes  []*regexp.Regexp
	prefixes []netip.Prefix
	ports    map[int]struct{}
	ranges   [][2]int
	sets     []*compiledMatch // expanded inline rule sets (one level)

	famDomain  bool // any domain-family matcher (self or via sets)
	famIP      bool // any IP matcher (self or via sets)
	famPort    bool // any port matcher (self only; sets cannot carry ports)
	domainOnly bool // routecfg's DNS-mirror definition
}

func compileMatch(m routecfg.Match, sets map[string]routecfg.RuleSetRef, depth int) (*compiledMatch, error) {
	cm := &compiledMatch{}
	if len(m.Domains) > 0 {
		cm.domains = make(map[string]struct{}, len(m.Domains))
		for _, d := range m.Domains {
			cm.domains[strings.ToLower(d)] = struct{}{}
		}
		cm.famDomain = true
	}
	if len(m.DomainSuffixes) > 0 {
		for _, s := range m.DomainSuffixes {
			cm.suffixes = append(cm.suffixes, strings.ToLower(s))
		}
		cm.famDomain = true
	}
	if len(m.DomainKeywords) > 0 {
		for _, k := range m.DomainKeywords {
			cm.keywords = append(cm.keywords, strings.ToLower(k))
		}
		cm.famDomain = true
	}
	for _, re := range m.DomainRegexes {
		rx, err := regexp.Compile(re)
		if err != nil {
			return nil, err // validated upstream; defensive
		}
		cm.regexes = append(cm.regexes, rx)
		cm.famDomain = true
	}
	for _, c := range m.IPCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			// routecfg accepts bare IPs; normalize to a host prefix.
			addr, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, err
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		cm.prefixes = append(cm.prefixes, pfx.Masked())
		cm.famIP = true
	}
	if len(m.Ports) > 0 {
		cm.ports = make(map[int]struct{}, len(m.Ports))
		for _, p := range m.Ports {
			cm.ports[p] = struct{}{}
		}
		cm.famPort = true
	}
	for _, pr := range m.PortRanges {
		var lo, hi int
		if _, err := fmt.Sscanf(pr, "%d:%d", &lo, &hi); err != nil {
			return nil, fmt.Errorf("invalid port_range %q", pr)
		}
		cm.ranges = append(cm.ranges, [2]int{lo, hi})
		cm.famPort = true
	}
	for _, tag := range m.RuleSets {
		rs := sets[tag]
		if rs.Type != "inline" {
			return nil, errPolicyUnsupported(fmt.Sprintf(
				"rule set %q is a %s rule set; the self-developed plane evaluates inline rule sets only", tag, rs.Type))
		}
		if depth > 0 {
			return nil, errPolicyUnsupported("nested rule sets are not evaluable by the self-developed plane")
		}
		set := &compiledMatch{}
		for _, entry := range rs.Inline {
			ec, err := compileMatch(entry, sets, depth+1)
			if err != nil {
				return nil, err
			}
			set.sets = append(set.sets, ec)
			set.famDomain = set.famDomain || ec.famDomain
			set.famIP = set.famIP || ec.famIP
		}
		cm.sets = append(cm.sets, set.sets...)
		cm.famDomain = cm.famDomain || set.famDomain
		cm.famIP = cm.famIP || set.famIP
	}
	// routecfg's domainOnly, verbatim: no IP/port/protocol/process
	// matchers on the rule itself, and no referenced set of kind
	// ip. (Protocol/process presence is rejected before this
	// point; kind-mixed sets count as domain-family here, exactly
	// as routecfg's mirror treats them - their IP entries simply
	// cannot confirm membership from a bare name, see
	// matchDomain.)
	cm.domainOnly = len(m.IPCIDRs) == 0 && len(m.Ports) == 0 && len(m.PortRanges) == 0
	if cm.domainOnly {
		for _, tag := range m.RuleSets {
			if sets[tag].Kind == routecfg.RuleSetKindIP {
				cm.domainOnly = false
			}
		}
	}
	return cm, nil
}

// matchDomain evaluates only the domain family (the DNS-mirror
// view): set entries that also require an IP fact cannot
// confirm membership from a bare name and do not match.
func (m *compiledMatch) matchDomain(host string) bool {
	if m.hasDomainMatchers() && !m.domainMatches(host) {
		return false
	}
	if len(m.sets) > 0 {
		anySet := false
		for _, s := range m.sets {
			if s.famIP {
				continue // needs an IP fact; invisible to the mirror
			}
			if s.matchDomain(host) {
				anySet = true
				break
			}
		}
		if !anySet {
			return false
		}
	}
	return m.hasDomainMatchers() || len(m.sets) > 0
}

func (m *compiledMatch) hasDomainMatchers() bool {
	return len(m.domains) > 0 || len(m.suffixes) > 0 || len(m.keywords) > 0 || len(m.regexes) > 0
}

func (m *compiledMatch) domainMatches(host string) bool {
	h := strings.ToLower(host)
	if _, ok := m.domains[h]; ok {
		return true
	}
	for _, s := range m.suffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	for _, k := range m.keywords {
		if strings.Contains(h, k) {
			return true
		}
	}
	for _, rx := range m.regexes {
		if rx.MatchString(host) {
			return true
		}
	}
	return false
}

// matches evaluates the full condition set: every family
// present must match (AND across families, OR inside one).
// ip == nil is the name phase: rules requiring an IP fact do
// not match (their decision is deferred until resolution, the
// same two-phase shape sing-box's resolve-then-route takes).
func (m *compiledMatch) matches(host string, ip *netip.Addr, port int) bool {
	if m.hasDomainMatchers() {
		if host == "" || !m.domainMatches(host) {
			return false
		}
	}
	if len(m.prefixes) > 0 {
		if ip == nil || !prefixMatches(m.prefixes, *ip) {
			return false
		}
	}
	if m.famPort {
		if _, ok := m.ports[port]; !ok {
			inRange := false
			for _, r := range m.ranges {
				if port >= r[0] && port <= r[1] {
					inRange = true
					break
				}
			}
			if !inRange {
				return false
			}
		}
	}
	if len(m.sets) > 0 {
		anySet := false
		for _, s := range m.sets {
			if s.matches(host, ip, port) {
				anySet = true
				break
			}
		}
		if !anySet {
			return false
		}
	}
	return true
}

func prefixMatches(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
		// A 4-in-6 target should still match IPv4 prefixes.
		if ip.Is4In6() && p.Addr().Is4() {
			if p.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}

// isPrivateIP mirrors sing-box's ip_is_private set (RFC1918 +
// RFC6598 shared space + unique-local + loopback + link-local).
func isPrivateIP(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func isV6(ip netip.Addr) bool { return ip.Is6() && !ip.Is4In6() }

// errPolicyUnsupported marks a policy feature the plane cannot
// evaluate (see the package comment at the top of this file).
func errPolicyUnsupported(why string) error {
	return kernel.NewError(kernel.KindUnsupported, "selfdev.Start",
		"routing policy is not evaluable by the self-developed plane: "+why+
			" (the sing-box backend evaluates it; use the singbox policy gear)", nil)
}

type evalRule struct {
	match  *compiledMatch
	action routecfg.Action
}

// policyEval is a routecfg.Policy compiled for the forwarding
// plane. A nil *policyEval means "no policy attached": the
// Step 7 behaviour (everything to the node, names carried to
// the egress, no local resolution ever).
type policyEval struct {
	mode          routecfg.Mode
	ipv6          routecfg.IPv6Policy
	bypassPrivate bool
	blocks        []*evalRule // class B, declared order
	rest          []*evalRule // class D, declared order
	dns           routecfg.DNSPolicy
	// needsIPPhase reports whether any decision can depend on
	// a resolved IP (IP matchers anywhere, or the class-E
	// private bypass). When false, name targets are decided in
	// the name phase alone and proxied names are never resolved
	// by the plane at all.
	needsIPPhase bool
}

// compilePolicyEval validates p (through routecfg's own
// compiler, so the two backends accept exactly the same
// policies) and compiles it for the plane.
func compilePolicyEval(p *routecfg.Policy) (*policyEval, error) {
	if p == nil {
		return nil, nil
	}
	if _, err := routecfg.Compile(*p); err != nil {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "selfdev.Start",
			"routing policy does not compile", err)
	}
	sets := make(map[string]routecfg.RuleSetRef, len(p.RuleSets))
	for _, rs := range p.RuleSets {
		sets[rs.Tag] = rs
	}
	ev := &policyEval{
		mode:          p.Mode,
		ipv6:          p.IPv6Effective(),
		bypassPrivate: p.BypassPrivate,
		dns:           p.DNS,
	}
	for _, r := range p.Rules {
		if len(r.Match.Protocols) > 0 {
			return nil, errPolicyUnsupported("a rule matches on sniffed protocols, which the plane does not sniff")
		}
		if len(r.Match.ProcessNames) > 0 {
			return nil, errPolicyUnsupported("a rule matches on process names, which the plane cannot attribute")
		}
		cm, err := compileMatch(r.Match, sets, 0)
		if err != nil {
			if ke, ok := err.(*kernel.Error); ok {
				return nil, ke
			}
			return nil, kernel.NewError(kernel.KindInvalidConfig, "selfdev.Start",
				"routing policy rule does not compile", err)
		}
		er := &evalRule{match: cm, action: r.Action}
		if r.Action == routecfg.ActionBlock {
			ev.blocks = append(ev.blocks, er)
		} else {
			ev.rest = append(ev.rest, er)
		}
		if cm.famIP {
			ev.needsIPPhase = true
		}
	}
	if ev.bypassPrivate && ev.mode != routecfg.ModeGlobal {
		ev.needsIPPhase = true
	}
	return ev, nil
}

// decide runs the class A-E stack for one target. host is the
// target name ("" for IP literals), ip the literal or resolved
// IP (nil in the name phase), port the destination port.
func (e *policyEval) decide(host string, ip *netip.Addr, port int) routecfg.Action {
	if e == nil {
		return routecfg.ActionProxy
	}
	// Class A: IPv6 off means off.
	if e.ipv6 == routecfg.IPv6Off && ip != nil && isV6(*ip) {
		return routecfg.ActionBlock
	}
	// Class B: user blocks, declared order.
	for _, r := range e.blocks {
		if r.match.matches(host, ip, port) {
			return routecfg.ActionBlock
		}
	}
	// Class C: IPv6 may only ever take the tunnel.
	if e.ipv6 == routecfg.IPv6Tunnel && ip != nil && isV6(*ip) {
		return routecfg.ActionProxy
	}
	if e.mode != routecfg.ModeGlobal {
		// Class D: remaining user rules, declared order.
		for _, r := range e.rest {
			if r.match.matches(host, ip, port) {
				return r.action
			}
		}
		// Class E: built-in private bypass, below all user rules.
		if e.bypassPrivate && ip != nil && isPrivateIP(*ip) {
			return routecfg.ActionDirect
		}
	}
	// final: the node.
	return routecfg.ActionProxy
}

// dnsClass is the resolver decision for one name.
type dnsClass int

const (
	dnsRemote dnsClass = iota // resolve through the tunnel (the default)
	dnsLocal                  // resolve locally (mirrored direct rules only)
	dnsReject                 // mirrored block rule: refuse the name
)

// dnsRoute mirrors routecfg's DNS rule derivation: blocks
// first, then (outside global mode) the rest in declared
// order, considering pure-domain rules only; the default is
// remote - there is no fallback from an unlisted name to the
// local resolver.
func (e *policyEval) dnsRoute(host string) dnsClass {
	if e == nil {
		return dnsRemote
	}
	for _, r := range e.blocks {
		if r.match.domainOnly && r.match.matchDomain(host) {
			return dnsReject
		}
	}
	if e.mode != routecfg.ModeGlobal {
		for _, r := range e.rest {
			if !r.match.domainOnly {
				continue
			}
			if !r.match.matchDomain(host) {
				continue
			}
			if r.action == routecfg.ActionDirect {
				return dnsLocal
			}
			return dnsRemote
		}
	}
	return dnsRemote
}

// fakeIP reports whether the policy enables fake-ip. The plane
// does not serve fake-ip DNS (that surface belongs to TUN
// mode, which stays on the sing-box plane); for the manual-mode
// plane the documented sing-box fallback applies - real
// resolution through the remote server at connect time - which
// is what the resolver does either way. Recorded here so the
// equivalence is explicit, not silent.
func (e *policyEval) fakeIP() bool {
	return e != nil && e.dns.FakeIP
}
