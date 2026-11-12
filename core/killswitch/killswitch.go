// Package killswitch implements Relavia's断网保护 (kill switch):
// proposal book 5.4 ("全局断网保护：隧道异常断开时阻断直连流量"),
// 8.1 (安全：断网保护), 8.2 (Windows and Android are both v1.0),
// Step 12 (交付双平台 kill switch; 验收：强杀隧道、断网、休眠唤醒
// 等场景下无直连流量泄露）.
//
// # What this layer is — and is not
//
// The kill switch is a HOST EGRESS FAIL-SAFE, independent of the
// routing policy in core/routecfg:
//
//   - routecfg decides where traffic goes INSIDE the client's
//     data path: it compiles to sing-box route/DNS fragments that
//     the kernel evaluates per connection.
//   - killswitch decides whether traffic may leave the host AT
//     ALL outside the tunnel while a protected session exists:
//     it compiles to operating-system firewall rules (Windows
//     Firewall policy, Linux nftables) or maps onto a platform
//     mechanism (Android system lockdown). It consumes no
//     routecfg.Policy and emits no sing-box fragment; the two
//     layers share only the node identity (the tunnel endpoint
//     exceptions below come from the connected node, resolved
//     by the caller).
//
// If the kernel dies, routecfg fragments die with it — that is
// exactly the failure this layer exists for: the OS-level block
// must survive the process that asked for it, which is why the
// state machine persists its intent and re-applies on boot
// (see state.go).
//
// # Semantics (normative)
//
// Modes (the user's setting):
//
//   - ModeOff: the feature is disabled. No rules are ever
//     applied; session events are no-ops.
//   - ModeWhenConnected （连接时）: blocking applies from the
//     moment a connection session starts until the user
//     explicitly disconnects.
//   - ModeAlwaysOn （常开）: blocking applies whenever the
//     setting is on — before any session, between sessions, and
//     after a user disconnect: a disconnect ends the session,
//     never the block.
//
// Block scope while blocking: ALL outbound traffic that does
// not leave via the tunnel interface, including DNS (name
// resolution must ride the tunnel per the Step 11 DNS policy,
// or fail — there is deliberately NO port-53 exception) and
// including IPv6 (the compiled rules live in an inet-family /
// all-profile ruleset, so v6 cannot slip past a v4-only rule).
//
// Exceptions while blocking (the complete list — anything not
// listed is dropped):
//
//   - loopback traffic;
//   - traffic leaving via the tunnel interface;
//   - the kernel's own connections to the tunnel endpoint(s):
//     the node server address(es) and port(s) of the active
//     session. Endpoints are IP literals: hostnames must be
//     resolved BEFORE the session starts (resolution itself
//     would be blocked once rules apply), and the caller must
//     re-issue the Config if the resolved address changes;
//   - LAN/private ranges, ONLY when Config.AllowLAN is set
//     (a user toggle; default off — note this is independent of
//     routecfg's private-bypass routing rule, which governs
//     where traffic goes, not whether it may leave).
//
// # Honesty grading (book 3.3)
//
// Enforcement readiness is graded, never binary-claimed:
//
//   - ReadinessUnavailable: no Controller/enforcer exists.
//   - ReadinessPolicyReady: the state machine and the compiled
//     platform rules are ready and tested, but the attached
//     enforcer is not a real platform enforcer (fake, or the
//     platform implementation is a compile-verified skeleton).
//   - ReadinessEnforceable: a real platform enforcer is
//     attached (e.g. the Linux nftables enforcer, or a future
//     verified Windows WFP/Firewall implementation).
//
// The sing-box adapter reports Platform.KillSwitch=true only at
// ReadinessEnforceable (see core/singbox's KillSwitchReport
// hook); this step ships the policy layer and enforcers below
// but wires NO production Windows/Android enforcement into the
// adapter, so default builds keep reporting false.
package killswitch

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Mode is the user's kill-switch setting.
type Mode string

const (
	// ModeOff disables the kill switch entirely.
	ModeOff Mode = "off"
	// ModeWhenConnected blocks from session start until the
	// user explicitly disconnects.
	ModeWhenConnected Mode = "when-connected"
	// ModeAlwaysOn blocks whenever the setting is on,
	// independent of session state.
	ModeAlwaysOn Mode = "always-on"
)

// DefaultTunnelInterface is the interface name the compiled
// descriptors allow egress on. The platform layer (Steps 9/10)
// must name its TUN device accordingly, or pass the real name
// in Config.TunnelInterface.
const DefaultTunnelInterface = "relavia0"

// NFTTable is the nftables table name used by the Linux
// descriptor and enforcer.
const NFTTable = "relavia_ks"

// Endpoint is one tunnel-endpoint exception: the node server
// the kernel itself must be able to reach while blocking.
type Endpoint struct {
	// Address is an IP literal (v4 or v6). Hostnames are
	// rejected on purpose: they must be resolved before the
	// block applies (see package documentation).
	Address string `json:"address"`
	// Port is the server port, 1..65535.
	Port int `json:"port"`
	// Protocols are "tcp" and/or "udp". Empty means both.
	Protocols []string `json:"protocols,omitempty"`
}

// protocols returns the normalized protocol list (default both).
func (e Endpoint) protocols() []string {
	if len(e.Protocols) == 0 {
		return []string{"tcp", "udp"}
	}
	out := append([]string(nil), e.Protocols...)
	sort.Strings(out)
	return out
}

// Config is the complete kill-switch configuration for one
// client installation/session. It is the input of Compile and
// of the state machine (Controller).
type Config struct {
	Mode Mode `json:"mode"`
	// Endpoints are the tunnel endpoint exceptions. May be
	// empty (then only loopback and tunnel egress pass).
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// AllowLAN permits egress to private/link-local ranges.
	// Default false.
	AllowLAN bool `json:"allow_lan,omitempty"`
	// TunnelInterface is the TUN device name egress is
	// allowed on. Empty means DefaultTunnelInterface.
	TunnelInterface string `json:"tunnel_interface,omitempty"`
}

// tunnelInterface returns the effective TUN interface name.
func (c Config) tunnelInterface() string {
	if c.TunnelInterface == "" {
		return DefaultTunnelInterface
	}
	return c.TunnelInterface
}

// Validate checks the configuration for structural errors.
func (c Config) Validate() error {
	switch c.Mode {
	case ModeOff, ModeWhenConnected, ModeAlwaysOn:
	default:
		return fmt.Errorf("killswitch: unknown mode %q (want off, when-connected or always-on)", c.Mode)
	}
	for i, e := range c.Endpoints {
		if _, err := netip.ParseAddr(e.Address); err != nil {
			return fmt.Errorf("killswitch: endpoint %d: address %q is not an IP literal (resolve hostnames before session start)", i, e.Address)
		}
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("killswitch: endpoint %d: invalid port %d", i, e.Port)
		}
		for _, p := range e.Protocols {
			if p != "tcp" && p != "udp" {
				return fmt.Errorf("killswitch: endpoint %d: unknown protocol %q (want tcp or udp)", i, p)
			}
		}
	}
	if strings.ContainsAny(c.tunnelInterface(), " \t\"'") {
		return fmt.Errorf("killswitch: invalid tunnel interface name %q", c.TunnelInterface)
	}
	return nil
}

// sortedEndpoints returns the endpoints in a deterministic
// order so compiled descriptors are stable (diffable, and the
// SBOM-style review of generated rules stays meaningful).
func (c Config) sortedEndpoints() []Endpoint {
	out := append([]Endpoint(nil), c.Endpoints...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// Readiness grades how real the enforcement behind a
// Controller is (see package documentation).
type Readiness int

const (
	// ReadinessUnavailable: no enforcer attached.
	ReadinessUnavailable Readiness = iota
	// ReadinessPolicyReady: policy + state machine ready,
	// platform enforcement not real (yet).
	ReadinessPolicyReady
	// ReadinessEnforceable: a real platform enforcer is
	// attached and able to apply the compiled rules.
	ReadinessEnforceable
)

func (r Readiness) String() string {
	switch r {
	case ReadinessUnavailable:
		return "unavailable"
	case ReadinessPolicyReady:
		return "policy-ready"
	case ReadinessEnforceable:
		return "enforceable"
	}
	return "unknown"
}
