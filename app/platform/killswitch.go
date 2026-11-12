package platform

import (
	"fmt"
	"net/netip"
	"strings"

	"openproxy/core/killswitch"
)

// Kill switch facility (proposal book 5.4, 8.1, 8.2; Step 12).
//
// The POLICY (semantics, state machine, compiled rules) lives
// in openproxy/core/killswitch and is platform-independent.
// This facility is the platform EXECUTOR side: it takes the
// compiled killswitch.Descriptors and puts them into force at
// OS level.
//
// Step 12 status per platform:
//
//   - Linux: real executor backed by core/killswitch's
//     NFTEnforcer (needs CAP_NET_ADMIN in the current network
//     namespace). Linux is a phase-2 platform (book 8.2); this
//     executor also serves the Step 12 test rig.
//   - Windows: netsh-based executor SKELETON,
//     COMPILE-VERIFIED ONLY — no Windows machine exists in the
//     build sandbox; it is listed in the Step 12 report as
//     "implemented as skeleton, pending real-machine
//     verification", and its Enforcer grading stays
//     policy-ready (Enforceable=false) until that lands.
//   - Android: no executor exists in this Go module at all —
//     Android enforcement is the system lockdown mechanism,
//     reached through the Step 10 shell bridge proposed in
//     core/killswitch/android.go. Nothing here pretends
//     otherwise.
//
// Wiring note: constructors are named NewKillSwitch like the
// other facilities, but the Step 9 factory bundles are NOT
// modified by this step (Step 10 is settling its side in
// parallel); the app service adopts the facility through
// NewKillSwitch directly.

// KillSwitch is the platform kill-switch executor facility.
type KillSwitch interface {
	// Apply puts the compiled descriptors into force.
	Apply(desc killswitch.Descriptors) error
	// Remove takes them out of force (idempotent).
	Remove() error
	// Applied reports whether the executor believes its rules
	// are in force (fact, not intent).
	Applied() bool
	// Available reports whether Apply can work here at all.
	Available() bool
	// Detail explains the availability/status for display.
	Detail() string
}

// --- Windows command builder (pure; tested on every OS) ------

// WinCommand is one netsh invocation. BestEffort commands
// (deleting a possibly-absent rule before re-adding it) may
// fail without failing the operation.
type WinCommand struct {
	Args       []string
	BestEffort bool
}

// BuildWindowsApplyCommands translates the Windows rule-set
// descriptor into netsh advfirewall commands: one allow rule
// per descriptor rule, then the profile policy flip that makes
// the block real (default outbound = block on all profiles).
// The descriptor's own Notes carry the semantics; this builder
// is their mechanical translation.
func BuildWindowsApplyCommands(desc killswitch.Descriptors) ([]WinCommand, error) {
	w := desc.Windows
	if w.DefaultOutboundAction != "block" {
		return nil, fmt.Errorf("platform: windows descriptor default outbound = %q, want \"block\"", w.DefaultOutboundAction)
	}
	var cmds []WinCommand
	for _, r := range w.Rules {
		remote, err := netshRemoteIP(r.RemoteAddress)
		if err != nil {
			return nil, fmt.Errorf("platform: rule %q: %w", r.Name, err)
		}
		// Delete-then-add keeps Apply idempotent.
		cmds = append(cmds, WinCommand{
			Args:       []string{"advfirewall", "firewall", "delete", "rule", "name=" + r.Name},
			BestEffort: true,
		})
		args := []string{
			"advfirewall", "firewall", "add", "rule",
			"name=" + r.Name,
			"dir=out",
			"action=allow",
			"protocol=" + netshProtocol(r.Protocol),
			"remoteip=" + remote,
		}
		if r.RemotePort != "" && !strings.EqualFold(r.Protocol, "any") {
			args = append(args, "remoteport="+r.RemotePort)
		}
		cmds = append(cmds, WinCommand{Args: args})
	}
	// The block itself. SKELETON CAVEAT (Step 12 report): this
	// also pins inbound to block; Windows' default inbound is
	// already block, but the verified implementation must read
	// and restore the user's actual inbound policy instead of
	// assuming it.
	cmds = append(cmds, WinCommand{Args: []string{
		"advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound",
	}})
	return cmds, nil
}

// BuildWindowsRemoveCommands removes every rule this package
// created (matched by the descriptor's rule names) and
// restores the default outbound action to allow.
func BuildWindowsRemoveCommands(desc killswitch.Descriptors) []WinCommand {
	var cmds []WinCommand
	seen := map[string]bool{}
	for _, r := range desc.Windows.Rules {
		if seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		cmds = append(cmds, WinCommand{
			Args:       []string{"advfirewall", "firewall", "delete", "rule", "name=" + r.Name},
			BestEffort: true,
		})
	}
	cmds = append(cmds, WinCommand{Args: []string{
		"advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound",
	}})
	return cmds
}

func netshProtocol(p string) string {
	switch strings.ToUpper(p) {
	case "TCP":
		return "TCP"
	case "UDP":
		return "UDP"
	default:
		return "any"
	}
}

// netshRemoteIP translates descriptor addresses to netsh
// syntax: IPv4 prefixes become address/dotted-netmask, IPv6
// prefixes keep address/prefix-length (netsh accepts that
// form for v6), plain addresses pass through. Lists are
// comma-separated in both worlds.
func netshRemoteIP(s string) (string, error) {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if pfx, err := netip.ParsePrefix(p); err == nil {
			addr := pfx.Addr()
			if addr.Is4() {
				bits := pfx.Bits()
				var mask [4]byte
				for b := 0; b < bits; b++ {
					mask[b/8] |= 1 << (7 - b%8)
				}
				parts[i] = fmt.Sprintf("%s/%d.%d.%d.%d", addr, mask[0], mask[1], mask[2], mask[3])
			} else {
				parts[i] = p // v6: address/prefix-length is netsh's form
			}
			continue
		}
		if _, err := netip.ParseAddr(p); err != nil {
			return "", fmt.Errorf("remote address %q is neither an IP nor a prefix", p)
		}
		parts[i] = p
	}
	return strings.Join(parts, ","), nil
}
