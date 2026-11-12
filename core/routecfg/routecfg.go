// Package routecfg compiles Relavia routing and DNS policy into
// sing-box configuration fragments (proposal book Step 11: 路由与
// DNS; book 5.4 platform networking, 8.1 routing modes).
//
// # Architecture choice
//
// Step 7's config compiler (package singbox) compiles ONE node
// into a full client configuration and deliberately emitted no
// route rules and no DNS section ("routing/DNS policy is Step
// 11's deliverable"). This package is that deliverable, placed
// BESIDE the node compiler rather than inside it:
//
//   - Policy (this package) is the user-facing, node-independent
//     description of split-routing intent and DNS strategy. It
//     is JSON-serializable as-is; the shipped default security
//     configurations are Policy documents (see defaults/).
//   - Compile turns a Policy into a Fragment: the "route" and
//     "dns" sections of a sing-box configuration, referencing
//     exactly the outbound tags the Step 7 compiler emits
//     ("out" for the node, "direct").
//   - The singbox adapter accepts an optional Policy via its
//     Options and merges the fragment into the compiled node
//     configuration. With no policy set, Step 7 behaviour is
//     unchanged (route.final = the node, no DNS section).
//
// # Rule precedence (the裁决 semantics, normative)
//
// sing-box evaluates route rules top-to-bottom; the first rule
// whose conditions ALL match decides, and route.final is the
// fallback. The compiler emits rules in a fixed class order so
// precedence never depends on how the user happened to order
// unrelated rules:
//
//	Class A — hard invariants. IPv6 policy "off" emits one
//	  rule {ip_version: 6, action: reject} ahead of
//	  everything: no later rule can resurrect IPv6.
//	Class B — user block rules, in declared order. An
//	  explicit block is a hard deny and beats any direct or
//	  proxy rule for the same target, wherever the user
//	  wrote it in their list.
//	Class C — IPv6 policy "tunnel": {ip_version: 6 → out}.
//	  IPv6 may never take a direct rule below this point;
//	  if the node cannot carry IPv6 the connection fails
//	  closed instead of leaking direct.
//	Class D — remaining user rules (direct / proxy), in
//	  declared order. Within this class the user's own
//	  ordering is the precedence: first match wins.
//	Class E — built-in private bypass (rule and direct-list
//	  modes, when enabled): {ip_is_private → direct}.
//	  It sits below every user rule, so an explicit user
//	  rule for a private target always wins over it.
//	final — "out" (the node) in every mode.
//
// Modes (book 8.1: 全局、规则、直连名单):
//
//   - global: classes D and E are not emitted; the compiler
//     REJECTS direct/proxy user rules in this mode instead of
//     silently ignoring them. Blocks (class B) still apply.
//   - rule: all classes as above.
//   - direct-list: the whitelist reading of 直连名单 — user
//     rules may only be direct or block (a proxy rule would be
//     a no-op against final=out and is rejected as a config
//     mistake); everything not listed goes to the node.
//
// # DNS consistency
//
// Two resolution paths exist, and the policy governs both:
//
//   - Names this client resolves itself — direct-routed
//     connections, and every OS query under TUN DNS hijack —
//     are decided by the DNS rules below: direct names to the
//     local server, everything else to the remote server
//     through the tunnel.
//   - Names inside domain-carrying proxy connections (socks,
//     shadowsocks, trojan, vmess outbounds all carry the name
//     to the far end) are resolved at the egress, by the
//     node. They never touch a local resolver: the tunnel
//     carries the NAME, not a locally-resolved address, so
//     nothing leaks locally. Forcing local resolution via
//     route.default_domain_resolver was evaluated and
//     rejected — its named-server form skips DNS rule
//     evaluation in sing-box 1.14 (empirically breaking the
//     direct-name mirror) and its server-less form is a
//     parse error; see compile.go.
//
// DNS rules are DERIVED from the same policy rules so the two
// cannot drift apart: every user rule whose matchers are purely
// domain-family (domains, suffixes, keywords, regexes, and
// domain-kind rule sets) is mirrored into a DNS rule, in the
// same class order (blocks first, then the rest in declared
// order), mapping direct → the local server, proxy → the
// remote server, block → DNS reject. Rules that also carry IP,
// port, protocol or process conditions are NOT mirrored: their
// routing decision depends on facts a DNS query does not have,
// so those names resolve via the default (remote) server and
// the route layer still applies the full rule afterwards.
// dns.final is always the remote server: there is NO fallback
// path from a non-listed name to the local resolver — that is
// the anti-leak default book 5.4 requires (禁止明文回落).
// (When fake-ip is enabled, sing-box 1.14 forbids a fakeip
// default server, so fake answers interpose through a
// trailing query_type rule instead; final stays remote and
// performs the real resolution at connect time.)
package routecfg

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Outbound tags emitted by the Step 7 node compiler; fragments
// reference exactly these.
const (
	OutboundProxy  = "out"
	OutboundDirect = "direct"
)

// DNS server tags used inside compiled fragments.
const (
	DNSServerRemote = "remote"
	DNSServerLocal  = "local"
	DNSServerFakeIP = "fake"
)

// Mode is the split-routing mode (book 8.1).
type Mode string

const (
	ModeGlobal     Mode = "global"
	ModeRule       Mode = "rule"
	ModeDirectList Mode = "direct-list"
)

// Action is what a rule does with a matching connection.
type Action string

const (
	ActionProxy  Action = "proxy"
	ActionDirect Action = "direct"
	ActionBlock  Action = "block"
)

// IPv6Policy is the IPv6 posture (book 8.1: IPv6 开关):
//
//   - "on": IPv6 follows the same rules as IPv4; DNS strategy
//     prefer_ipv4.
//   - "off": IPv6 is rejected outright (class A) and DNS
//     strategy is ipv4_only, so no AAAA answer is ever used.
//   - "tunnel": IPv6 may only ever leave via the node
//     (class C); it can never match a direct rule.
type IPv6Policy string

const (
	IPv6On     IPv6Policy = "on"
	IPv6Off    IPv6Policy = "off"
	IPv6Tunnel IPv6Policy = "tunnel"
)

// Match is the condition set of one rule. Fields are ANDed
// together; values inside one field are ORed — sing-box's
// default-rule semantics, preserved verbatim by the compiler.
type Match struct {
	// Domains are exact hostnames ("example.com").
	Domains []string `json:"domains,omitempty"`
	// DomainSuffixes match the suffix itself and any subdomain
	// ("example.com" matches "www.example.com").
	DomainSuffixes []string `json:"domain_suffixes,omitempty"`
	// DomainKeywords match any hostname containing the keyword.
	DomainKeywords []string `json:"domain_keywords,omitempty"`
	// DomainRegexes are RE2 regular expressions on hostnames.
	DomainRegexes []string `json:"domain_regexes,omitempty"`
	// IPCIDRs are destination prefixes ("203.0.113.0/24",
	// "2001:db8::/32"); a bare IP is accepted and normalized
	// to a host prefix.
	IPCIDRs []string `json:"ip_cidrs,omitempty"`
	// Ports are single destination ports.
	Ports []int `json:"ports,omitempty"`
	// PortRanges are "low:high" destination port ranges.
	PortRanges []string `json:"port_ranges,omitempty"`
	// Protocols are sing-box sniffed-protocol names ("tls",
	// "http", "quic", "dns", "stun", ...). Matching requires
	// protocol detection on the platform path; a rule that
	// matches nothing on a given platform is inert, never an
	// error.
	Protocols []string `json:"protocols,omitempty"`
	// ProcessNames match the originating process by name.
	// RESERVED for Windows (book 8.2 platform work, Step 9):
	// the compiler emits the condition on every platform, but
	// process attribution only exists where the platform
	// layer supplies it (sing-box find_process); elsewhere
	// such rules simply never match.
	ProcessNames []string `json:"process_names,omitempty"`
	// RuleSets references Policy.RuleSets tags (GeoSite /
	// GeoIP category references travel as rule sets in
	// sing-box 1.14; the legacy geosite/geoip rule fields no
	// longer exist upstream).
	RuleSets []string `json:"rule_sets,omitempty"`
}

// domainOnly reports whether every matcher present is
// domain-family — the condition for DNS mirroring.
func (m Match) domainOnly(sets map[string]RuleSetRef) bool {
	if len(m.IPCIDRs) > 0 || len(m.Ports) > 0 || len(m.PortRanges) > 0 ||
		len(m.Protocols) > 0 || len(m.ProcessNames) > 0 {
		return false
	}
	for _, tag := range m.RuleSets {
		if sets[tag].Kind == RuleSetKindIP {
			return false
		}
	}
	return m.hasAny()
}

func (m Match) hasAny() bool {
	return len(m.Domains)+len(m.DomainSuffixes)+len(m.DomainKeywords)+
		len(m.DomainRegexes)+len(m.IPCIDRs)+len(m.Ports)+len(m.PortRanges)+
		len(m.Protocols)+len(m.ProcessNames)+len(m.RuleSets) > 0
}

// Rule is one user routing rule.
type Rule struct {
	Match  Match  `json:"match"`
	Action Action `json:"action"`
}

// RuleSetKind declares what a rule set matches, so the DNS
// mirror can decide whether the set is safe to mirror.
type RuleSetKind string

const (
	// RuleSetKindDomain sets match hostnames (GeoSite-style).
	RuleSetKindDomain RuleSetKind = "domain"
	// RuleSetKindIP sets match destination IPs (GeoIP-style)
	// and are never mirrored into DNS rules.
	RuleSetKindIP RuleSetKind = "ip"
	// RuleSetKindMixed sets may match either; they are not
	// mirrored (the DNS layer cannot evaluate their IP half).
	RuleSetKindMixed RuleSetKind = "mixed"
)

// RuleSetRef declares one rule set the policy's rules can
// reference by tag. The project ships NO category data in this
// step: users point at local files or upstream rule-set URLs
// (e.g. the sing-box rule-set repositories); the compiler only
// emits the reference.
type RuleSetRef struct {
	Tag  string      `json:"tag"`
	Kind RuleSetKind `json:"kind,omitempty"` // default: domain
	// Type is the sing-box rule-set source: "local", "remote"
	// or "inline".
	Type string `json:"type"`
	// Format is "source" or "binary" (local/remote only).
	Format string `json:"format,omitempty"`
	// Path is the local file path (type "local").
	Path string `json:"path,omitempty"`
	// URL is the download URL (type "remote").
	URL string `json:"url,omitempty"`
	// DownloadViaProxy fetches remote rule sets through the
	// node instead of directly (avoids exposing the fetch and
	// works where the source is unreachable directly).
	DownloadViaProxy bool `json:"download_via_proxy,omitempty"`
	// Inline holds literal rules for type "inline". Only
	// domain/IP matchers are meaningful in a headless rule.
	Inline []Match `json:"inline,omitempty"`
}

// DNSServerSpec describes one DNS server. Type is one of
// "udp", "tcp", "tls" (DoT), "https" (DoH) for the remote
// server, and "local" (system resolver), "udp" or "tcp" for
// the local server.
type DNSServerSpec struct {
	Type string `json:"type"`
	// Server is the server hostname or IP. Empty for "local".
	Server string `json:"server,omitempty"`
	// Port 0 means the transport default (53 udp/tcp, 853 tls,
	// 443 https).
	Port int `json:"port,omitempty"`
	// ServerName is the TLS server name for tls/https when it
	// differs from Server (e.g. an IP server with a named
	// certificate). Empty: the kernel uses Server.
	ServerName string `json:"server_name,omitempty"`
	// Path is the DoH path for type "https" (default
	// "/dns-query").
	Path string `json:"path,omitempty"`
}

// DNSPolicy is the DNS half of a Policy.
type DNSPolicy struct {
	// Remote resolves everything not explicitly assigned to
	// the local server. It is ALWAYS detoured through the
	// node by the compiler — a remote server that bypassed
	// the tunnel would itself be a leak.
	Remote DNSServerSpec `json:"remote"`
	// Local resolves ONLY the names the routing layer sends
	// direct (mirrored pure-domain direct rules). Those names
	// are exposed to the local resolver by design: their
	// traffic is direct anyway, and resolving them remotely
	// would return CDN answers for the wrong egress.
	Local DNSServerSpec `json:"local"`
	// FakeIP enables the fake-ip DNS server. DEFAULT OFF —
	// see docs/step11-路由与DNS.md for the ruling: fake-ip
	// optimizes TUN-mode connection setup at the cost of
	// changed resolution semantics for every application;
	// the default posture of this project is real resolution
	// with remote-by-default, which is deterministic and
	// testable. Opt-in per policy.
	FakeIP bool `json:"fake_ip,omitempty"`
	// FakeIPInet4Range / FakeIPInet6Range override the
	// fake-ip pools. Empty: 198.18.0.0/15 and fc00::/18.
	FakeIPInet4Range string `json:"fake_ip_inet4_range,omitempty"`
	FakeIPInet6Range string `json:"fake_ip_inet6_range,omitempty"`
}

// Policy is a complete routing + DNS policy: the input of
// Compile and the on-disk format of the shipped defaults.
type Policy struct {
	Mode Mode `json:"mode"`
	// Rules are the user's rules in declared order (see the
	// package documentation for how classes reorder them).
	Rules []Rule `json:"rules,omitempty"`
	// RuleSets declares the rule sets Rules may reference.
	RuleSets []RuleSetRef `json:"rule_sets,omitempty"`
	// BypassPrivate enables class E ({ip_is_private →
	// direct}) in rule and direct-list modes. Default off at
	// the zero value; the shipped default policies enable it.
	BypassPrivate bool `json:"bypass_private,omitempty"`
	// IPv6 is the IPv6 posture. Empty means "on".
	IPv6  IPv6Policy `json:"ipv6,omitempty"`
	DNS   DNSPolicy  `json:"dns"`
	Notes string     `json:"notes,omitempty"` // free-form, ignored by the compiler
}

// IPv6Effective returns the IPv6 policy with the zero value
// resolved to "on".
func (p Policy) IPv6Effective() IPv6Policy {
	if p.IPv6 == "" {
		return IPv6On
	}
	return p.IPv6
}

func (p Policy) ruleSetIndex() map[string]RuleSetRef {
	idx := make(map[string]RuleSetRef, len(p.RuleSets))
	for _, rs := range p.RuleSets {
		idx[rs.Tag] = rs
	}
	return idx
}

// Validate checks a policy for structural and semantic errors.
// Compile calls it first; the errors are written for the user
// who authored the policy, not for a log file.
func (p Policy) Validate() error {
	switch p.Mode {
	case ModeGlobal, ModeRule, ModeDirectList:
	default:
		return fmt.Errorf("routecfg: unknown mode %q (want global, rule or direct-list)", p.Mode)
	}
	switch p.IPv6Effective() {
	case IPv6On, IPv6Off, IPv6Tunnel:
	default:
		return fmt.Errorf("routecfg: unknown ipv6 policy %q (want on, off or tunnel)", p.IPv6)
	}
	sets := make(map[string]RuleSetRef, len(p.RuleSets))
	for _, rs := range p.RuleSets {
		if rs.Tag == "" {
			return fmt.Errorf("routecfg: rule set with empty tag")
		}
		if _, dup := sets[rs.Tag]; dup {
			return fmt.Errorf("routecfg: duplicate rule set tag %q", rs.Tag)
		}
		switch rs.Kind {
		case "", RuleSetKindDomain, RuleSetKindIP, RuleSetKindMixed:
		default:
			return fmt.Errorf("routecfg: rule set %q: unknown kind %q", rs.Tag, rs.Kind)
		}
		switch rs.Type {
		case "local":
			if rs.Path == "" {
				return fmt.Errorf("routecfg: rule set %q: local type requires a path", rs.Tag)
			}
		case "remote":
			if rs.URL == "" {
				return fmt.Errorf("routecfg: rule set %q: remote type requires a url", rs.Tag)
			}
		case "inline":
			if len(rs.Inline) == 0 {
				return fmt.Errorf("routecfg: rule set %q: inline type requires at least one rule", rs.Tag)
			}
			for i, m := range rs.Inline {
				if err := validateMatch(m, sets, true); err != nil {
					return fmt.Errorf("routecfg: rule set %q inline rule %d: %w", rs.Tag, i, err)
				}
			}
		default:
			return fmt.Errorf("routecfg: rule set %q: unknown type %q (want local, remote or inline)", rs.Tag, rs.Type)
		}
		if rs.Type != "inline" && rs.Format != "" && rs.Format != "source" && rs.Format != "binary" {
			return fmt.Errorf("routecfg: rule set %q: unknown format %q (want source or binary)", rs.Tag, rs.Format)
		}
		sets[rs.Tag] = rs
	}
	for i, r := range p.Rules {
		switch r.Action {
		case ActionProxy, ActionDirect, ActionBlock:
		default:
			return fmt.Errorf("routecfg: rule %d: unknown action %q", i, r.Action)
		}
		if p.Mode == ModeGlobal && r.Action != ActionBlock {
			return fmt.Errorf("routecfg: rule %d: global mode accepts only block rules; a %s rule would be silently meaningless against final=%s", i, r.Action, OutboundProxy)
		}
		if p.Mode == ModeDirectList && r.Action == ActionProxy {
			return fmt.Errorf("routecfg: rule %d: direct-list mode accepts only direct and block rules; unlisted traffic already goes to the node", i)
		}
		if err := validateMatch(r.Match, sets, false); err != nil {
			return fmt.Errorf("routecfg: rule %d: %w", i, err)
		}
	}
	if err := validateDNSServer("remote", p.DNS.Remote, true); err != nil {
		return err
	}
	if err := validateDNSServer("local", p.DNS.Local, false); err != nil {
		return err
	}
	if p.DNS.FakeIP {
		for name, rng := range map[string]string{
			"fake_ip_inet4_range": p.DNS.FakeIPInet4Range,
			"fake_ip_inet6_range": p.DNS.FakeIPInet6Range,
		} {
			if rng == "" {
				continue
			}
			pfx, err := netip.ParsePrefix(rng)
			if err != nil || pfx != pfx.Masked() {
				return fmt.Errorf("routecfg: dns %s %q is not a valid network prefix", name, rng)
			}
		}
	}
	return nil
}

func validateMatch(m Match, sets map[string]RuleSetRef, inline bool) error {
	if !m.hasAny() {
		return fmt.Errorf("rule matches nothing: at least one matcher is required")
	}
	if inline && (len(m.Ports) > 0 || len(m.PortRanges) > 0 || len(m.Protocols) > 0 ||
		len(m.ProcessNames) > 0 || len(m.RuleSets) > 0) {
		return fmt.Errorf("inline rule-set rules may only use domain and IP matchers")
	}
	for _, cidr := range m.IPCIDRs {
		if _, err := parsePrefixLoose(cidr); err != nil {
			return fmt.Errorf("invalid ip_cidr %q", cidr)
		}
	}
	for _, port := range m.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}
	}
	for _, pr := range m.PortRanges {
		lo, hi, ok := strings.Cut(pr, ":")
		if !ok {
			return fmt.Errorf("invalid port_range %q (want low:high)", pr)
		}
		var l, h int
		if _, err := fmt.Sscanf(lo, "%d", &l); err != nil {
			return fmt.Errorf("invalid port_range %q", pr)
		}
		if _, err := fmt.Sscanf(hi, "%d", &h); err != nil {
			return fmt.Errorf("invalid port_range %q", pr)
		}
		if l < 1 || h > 65535 || l > h {
			return fmt.Errorf("invalid port_range %q", pr)
		}
	}
	for _, re := range m.DomainRegexes {
		if _, err := regexp.Compile(re); err != nil {
			return fmt.Errorf("invalid domain_regex %q: %v", re, err)
		}
	}
	for _, tag := range m.RuleSets {
		if _, ok := sets[tag]; !ok {
			return fmt.Errorf("references undeclared rule set %q", tag)
		}
	}
	return nil
}

func validateDNSServer(which string, spec DNSServerSpec, remote bool) error {
	if remote {
		switch spec.Type {
		case "udp", "tcp", "tls", "https":
		default:
			return fmt.Errorf("routecfg: dns %s: unknown type %q (want udp, tcp, tls or https)", which, spec.Type)
		}
		if spec.Server == "" {
			return fmt.Errorf("routecfg: dns %s: server is required", which)
		}
	} else {
		switch spec.Type {
		case "local":
			// System resolver; Server must be empty so nobody
			// mistakes this for an explicit server.
			if spec.Server != "" {
				return fmt.Errorf("routecfg: dns local: type \"local\" takes no server address; use udp/tcp for an explicit local server")
			}
		case "udp", "tcp":
			if spec.Server == "" {
				return fmt.Errorf("routecfg: dns local: explicit %s server requires a server address", spec.Type)
			}
		default:
			return fmt.Errorf("routecfg: dns local: unknown type %q (want local, udp or tcp)", spec.Type)
		}
	}
	if spec.Port < 0 || spec.Port > 65535 {
		return fmt.Errorf("routecfg: dns %s: invalid port %d", which, spec.Port)
	}
	return nil
}

// parsePrefixLoose accepts "203.0.113.0/24" and bare IPs
// (normalized to host prefixes by the compiler).
func parsePrefixLoose(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
