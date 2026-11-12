package routecfg

import (
	"strings"
)

// Fragment is the compiled output: the "route" and "dns"
// sections of a sing-box configuration, ready for
// ApplyTo into a full configuration map produced by the
// Step 7 node compiler.
type Fragment struct {
	Route map[string]any `json:"route"`
	DNS   map[string]any `json:"dns"`
}

// ApplyTo installs the fragment as cfg's route and dns
// sections, replacing whatever the node compiler emitted for
// them (Step 7 emits only route.final, which the fragment
// supersedes).
func (f *Fragment) ApplyTo(cfg map[string]any) {
	cfg["route"] = f.Route
	cfg["dns"] = f.DNS
}

// Compile validates the policy and compiles it to a Fragment.
// The emitted JSON shapes are sing-box 1.14's: the legacy DNS
// server format and the legacy geosite/geoip rule fields were
// REMOVED upstream in 1.14.0, so DNS servers use the typed
// format and category references travel as rule sets.
func Compile(p Policy) (*Fragment, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Fragment{
		Route: compileRoute(p),
		DNS:   compileDNS(p),
	}, nil
}

// --- route --------------------------------------------------------

func compileRoute(p Policy) map[string]any {
	// NOTE on what is deliberately NOT emitted:
	// route.default_domain_resolver. sing-box 1.14 offers it
	// (and deprecates its absence), but both of its forms
	// defeat this policy's DNS design, as verified
	// empirically in the Step 11 leak rig:
	//
	//   - naming a server ("remote") makes outbound
	//     resolution query that transport directly and SKIP
	//     DNS rule evaluation — a direct-listed name was
	//     answered by the remote resolver despite its
	//     mirrored DNS rule;
	//   - the server-less object form is rejected by the
	//     1.14 parser ("empty domain_resolver.server").
	//
	// The unset state has exactly the semantics this design
	// wants (see the package documentation, "two resolution
	// paths"). When a future sing-box removes the unset
	// state, this decision must be revisited before the
	// kernel is upgraded — recorded in
	// docs/step11-路由与DNS.md as a kernel-upgrade watch item.
	route := map[string]any{"final": OutboundProxy}
	var rules []any

	// Class A — hard invariant: IPv6 off means off.
	if p.IPv6Effective() == IPv6Off {
		rules = append(rules, map[string]any{
			"ip_version": 6,
			"action":     "reject",
		})
	}
	// Class B — user blocks, declared order.
	for _, r := range p.Rules {
		if r.Action == ActionBlock {
			rules = append(rules, routeRule(r))
		}
	}
	// Class C — IPv6 may only ever take the tunnel.
	if p.IPv6Effective() == IPv6Tunnel {
		rules = append(rules, map[string]any{
			"ip_version": 6,
			"outbound":   OutboundProxy,
		})
	}
	// Class D — remaining user rules, declared order.
	if p.Mode != ModeGlobal {
		for _, r := range p.Rules {
			if r.Action != ActionBlock {
				rules = append(rules, routeRule(r))
			}
		}
		// Class E — built-in private bypass, below all user
		// rules.
		if p.BypassPrivate {
			rules = append(rules, map[string]any{
				"ip_is_private": true,
				"outbound":      OutboundDirect,
			})
		}
	}
	if len(rules) > 0 {
		route["rules"] = rules
	}
	if len(p.RuleSets) > 0 {
		sets := make([]any, 0, len(p.RuleSets))
		for _, rs := range p.RuleSets {
			sets = append(sets, compileRuleSet(rs))
		}
		route["rule_set"] = sets
	}
	return route
}

// routeRule renders one user rule with sing-box's default
// (route) action flattened into the rule object; blocks use
// the explicit reject action.
func routeRule(r Rule) map[string]any {
	m := matchFields(r.Match)
	switch r.Action {
	case ActionBlock:
		m["action"] = "reject"
	case ActionDirect:
		m["outbound"] = OutboundDirect
	case ActionProxy:
		m["outbound"] = OutboundProxy
	}
	return m
}

// matchFields renders a Match as sing-box rule condition
// fields. It is shared by route rules and inline rule-set
// rules (headless rules accept the domain/IP subset).
func matchFields(m Match) map[string]any {
	out := map[string]any{}
	if len(m.Domains) > 0 {
		out["domain"] = strs(m.Domains)
	}
	if len(m.DomainSuffixes) > 0 {
		out["domain_suffix"] = strs(m.DomainSuffixes)
	}
	if len(m.DomainKeywords) > 0 {
		out["domain_keyword"] = strs(m.DomainKeywords)
	}
	if len(m.DomainRegexes) > 0 {
		out["domain_regex"] = strs(m.DomainRegexes)
	}
	if len(m.IPCIDRs) > 0 {
		cidrs := make([]string, 0, len(m.IPCIDRs))
		for _, c := range m.IPCIDRs {
			pfx, _ := parsePrefixLoose(c) // validated
			cidrs = append(cidrs, pfx.String())
		}
		out["ip_cidr"] = cidrs
	}
	if len(m.Ports) > 0 {
		ports := make([]any, 0, len(m.Ports))
		for _, p := range m.Ports {
			ports = append(ports, p)
		}
		out["port"] = ports
	}
	if len(m.PortRanges) > 0 {
		out["port_range"] = strs(m.PortRanges)
	}
	if len(m.Protocols) > 0 {
		out["protocol"] = strs(m.Protocols)
	}
	if len(m.ProcessNames) > 0 {
		out["process_name"] = strs(m.ProcessNames)
	}
	if len(m.RuleSets) > 0 {
		out["rule_set"] = strs(m.RuleSets)
	}
	return out
}

func compileRuleSet(rs RuleSetRef) map[string]any {
	m := map[string]any{"type": rs.Type, "tag": rs.Tag}
	switch rs.Type {
	case "local":
		m["format"] = formatOr(rs.Format, "binary")
		m["path"] = rs.Path
	case "remote":
		m["format"] = formatOr(rs.Format, "binary")
		m["url"] = rs.URL
		if rs.DownloadViaProxy {
			m["download_detour"] = OutboundProxy
		}
	case "inline":
		rules := make([]any, 0, len(rs.Inline))
		for _, im := range rs.Inline {
			rules = append(rules, matchFields(im))
		}
		m["rules"] = rules
	}
	return m
}

func formatOr(got, def string) string {
	if got == "" {
		return def
	}
	return got
}

// --- DNS ----------------------------------------------------------

func compileDNS(p Policy) map[string]any {
	sets := p.ruleSetIndex()

	var servers []any
	if p.DNS.FakeIP {
		fake := map[string]any{
			"type":        "fakeip",
			"tag":         DNSServerFakeIP,
			"inet4_range": defaultStr(p.DNS.FakeIPInet4Range, "198.18.0.0/15"),
		}
		if p.IPv6Effective() != IPv6Off {
			fake["inet6_range"] = defaultStr(p.DNS.FakeIPInet6Range, "fc00::/18")
		}
		servers = append(servers, fake)
	}
	servers = append(servers, dnsRemoteServer(p.DNS.Remote))
	servers = append(servers, dnsLocalServer(p.DNS.Local))

	// Mirrored rules, in the same class order as the route
	// compiler: blocks first, then the rest in declared order.
	var rules []any
	mirror := func(r Rule) {
		if !r.Match.domainOnly(sets) {
			return
		}
		m := matchFieldsDNS(r.Match)
		switch r.Action {
		case ActionBlock:
			m["action"] = "reject"
		case ActionDirect:
			m["server"] = DNSServerLocal
		case ActionProxy:
			if p.DNS.FakeIP {
				// With fake-ip on, proxied names are
				// answered by the fake catch-all rule
				// below, not resolved really here.
				return
			}
			m["server"] = DNSServerRemote
		}
		rules = append(rules, m)
	}
	for _, r := range p.Rules {
		if r.Action == ActionBlock {
			mirror(r)
		}
	}
	if p.Mode != ModeGlobal {
		for _, r := range p.Rules {
			if r.Action != ActionBlock {
				mirror(r)
			}
		}
	}
	if p.DNS.FakeIP {
		// sing-box 1.14 forbids a fakeip default server
		// ("default server cannot be fakeip"): dns.final
		// stays the real remote resolver, and fake answers
		// interpose through this trailing catch-all for
		// address queries only (TXT etc. still resolve for
		// real). Mirrored direct names above keep their
		// real local answers, and connect-time resolution
		// of a fake address runs through the remote server.
		rules = append(rules, map[string]any{
			"query_type": []any{"A", "AAAA"},
			"server":     DNSServerFakeIP,
		})
	}

	dns := map[string]any{
		"servers":  servers,
		"final":    DNSServerRemote,
		"strategy": dnsStrategy(p.IPv6Effective()),
	}
	if len(rules) > 0 {
		dns["rules"] = rules
	}
	return dns
}

// matchFieldsDNS renders the domain-family subset of a Match
// for a DNS rule.
func matchFieldsDNS(m Match) map[string]any {
	out := map[string]any{}
	if len(m.Domains) > 0 {
		out["domain"] = strs(m.Domains)
	}
	if len(m.DomainSuffixes) > 0 {
		out["domain_suffix"] = strs(m.DomainSuffixes)
	}
	if len(m.DomainKeywords) > 0 {
		out["domain_keyword"] = strs(m.DomainKeywords)
	}
	if len(m.DomainRegexes) > 0 {
		out["domain_regex"] = strs(m.DomainRegexes)
	}
	if len(m.RuleSets) > 0 {
		out["rule_set"] = strs(m.RuleSets)
	}
	return out
}

func dnsRemoteServer(spec DNSServerSpec) map[string]any {
	m := map[string]any{
		"type":   spec.Type,
		"tag":    DNSServerRemote,
		"server": spec.Server,
		// The remote resolver is only ever reached through
		// the tunnel. This detour is the anti-leak invariant
		// of the whole DNS design; do not make it optional.
		"detour": OutboundProxy,
	}
	if spec.Port > 0 {
		m["server_port"] = spec.Port
	}
	switch spec.Type {
	case "tls":
		if spec.Port == 0 {
			m["server_port"] = 853
		}
		m["tls"] = tlsBlock(spec)
	case "https":
		if spec.Port == 0 {
			m["server_port"] = 443
		}
		m["tls"] = tlsBlock(spec)
		m["path"] = defaultStr(spec.Path, "/dns-query")
	}
	return m
}

func dnsLocalServer(spec DNSServerSpec) map[string]any {
	if spec.Type == "local" {
		return map[string]any{"type": "local", "tag": DNSServerLocal}
	}
	m := map[string]any{
		"type":   spec.Type,
		"tag":    DNSServerLocal,
		"server": spec.Server,
		// Deliberately NO detour: this server is reached
		// directly, and it only ever receives the names the
		// routing layer sends direct anyway.
	}
	if spec.Port > 0 {
		m["server_port"] = spec.Port
	}
	return m
}

func tlsBlock(spec DNSServerSpec) map[string]any {
	tls := map[string]any{"enabled": true}
	if spec.ServerName != "" {
		tls["server_name"] = spec.ServerName
	}
	return tls
}

func dnsStrategy(ipv6 IPv6Policy) string {
	if ipv6 == IPv6Off {
		return "ipv4_only"
	}
	return "prefer_ipv4"
}

func defaultStr(got, def string) string {
	if strings.TrimSpace(got) == "" {
		return def
	}
	return got
}

func strs(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
