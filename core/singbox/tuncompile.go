package singbox

import (
	"encoding/json"

	"openproxy/core/routecfg"
	"openproxy/core/specnode"
)

// TUN configuration compilation for the Android data plane
// (libbox binding, docs/libbox绑定.md).
//
// The document format is exactly the sing-box JSON the rest of
// this package compiles — libbox's CommandServer consumes it
// verbatim via StartOrReloadService, so this is NOT a new config
// format: it is compileConfig's sibling with the loopback mixed
// inbound replaced by a tun inbound and the route section
// carrying auto_detect_interface. Node outbound construction,
// support gates and the Step 11 routing/DNS fragment are shared
// with the desktop path (applyNodeOutbounds, routecfg.Fragment).
//
// The tun parameters below mirror app/platform's
// DefaultTUNRequest (the shell's TUNRequest source of truth)
// and the Kotlin shell's established interface. They cannot be
// imported from app/platform (module direction: app imports
// core, never the reverse), so the values are duplicated here
// and a cross-package test in app/libboxbind asserts they can
// never drift apart.
//
// DNS posture: the tun inbound leaves dns_mode unset, so with
// auto_route sing-tun derives hijack mode, and the platform DNS
// address derives as the first tun address + 1 (172.18.0.2) —
// exactly DefaultTUNRequest's DNSServers. Queries therefore
// land in the box's DNS module, where the Step 11 fragment's
// DNS policy (remote-over-tunnel by default) governs them.

const (
	// tunIPv4Address mirrors platform.DefaultTUNRequest.
	tunIPv4Address = "172.18.0.1/30"
	// tunIPv6Address mirrors platform.DefaultTUNRequest(ipv6=true).
	tunIPv6Address = "fd00::1/126"
	// tunMTU mirrors platform.DefaultTUNRequest.
	tunMTU = 9000
	// tunInboundTag is the tag of the compiled tun inbound.
	tunInboundTag = "tun-in"
)

// TunCompileOptions configures CompileTunConfig.
type TunCompileOptions struct {
	// LogLevel is the sing-box log level ("trace".."panic").
	// Default "info" (libbox surfaces logs through its own
	// platform log; the desktop compile default is "warn").
	LogLevel string
	// IPv6 adds the IPv6 tun address (fd00::1/126), matching
	// platform.DefaultTUNRequest(true). The interface itself is
	// established by the shell from the same request values.
	IPv6 bool
	// Fragment, when non-nil, is the Step 11 routing/DNS
	// policy for the session. Its route section is installed
	// with auto_detect_interface forced on (see below); its DNS
	// section is installed unchanged.
	Fragment *routecfg.Fragment
}

// CompileTunConfig compiles a TUN-mode client configuration
// for one unified-model node, in the exact JSON form libbox's
// StartOrReloadService consumes. The caller must NOT have to
// pre-validate: the same support and compile-input gates as
// the desktop path run here first.
func CompileTunConfig(n *specnode.Node, opts TunCompileOptions) ([]byte, error) {
	if err := checkSupported(n); err != nil {
		return nil, err
	}
	if err := checkCompileInputs(n); err != nil {
		return nil, err
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "info"
	}

	addresses := []any{tunIPv4Address}
	if opts.IPv6 {
		addresses = append(addresses, tunIPv6Address)
	}
	cfg := map[string]any{
		"log": map[string]any{
			"level":     opts.LogLevel,
			"timestamp": true,
		},
		"inbounds": []any{
			map[string]any{
				"type":         "tun",
				"tag":          tunInboundTag,
				"address":      addresses,
				"mtu":          tunMTU,
				"auto_route":   true,
				"strict_route": true,
				// gvisor is the userspace stack: it needs no
				// system TUN administration and is the stack
				// DefaultTUNRequest's MTU guidance assumes.
				"stack": "gvisor",
			},
		},
		// auto_detect_interface is the Android-critical route
		// key: it makes every outbound dial pass its socket fd
		// through the platform interface's
		// AutoDetectInterfaceControl — VpnService.protect() —
		// before connecting. Without it the kernel's own
		// outbound sockets would be routed back into the
		// tunnel it serves (a routing loop) the moment the
		// default route enters the TUN.
		"route": map[string]any{
			"final":                 "out",
			"auto_detect_interface": true,
		},
	}

	if opts.Fragment != nil {
		// The fragment replaces route and dns wholesale
		// (routecfg.ApplyTo). Transplant its sections, then
		// force auto_detect_interface onto a CLONE of its
		// route map: the fragment object is shared policy
		// state and must not be mutated, and the flag is an
		// Android platform requirement the desktop-oriented
		// policy compiler deliberately does not emit.
		scratch := map[string]any{}
		opts.Fragment.ApplyTo(scratch)
		if fragRoute, ok := scratch["route"].(map[string]any); ok {
			route := make(map[string]any, len(fragRoute)+1)
			for k, v := range fragRoute {
				route[k] = v
			}
			route["auto_detect_interface"] = true
			cfg["route"] = route
		}
		if fragDNS, ok := scratch["dns"]; ok {
			cfg["dns"] = fragDNS
		}
	}

	// Deliberately NO experimental.cache_file section: the
	// desktop compiler sets an explicit per-instance path
	// because its in-process instances share a working
	// directory; a libbox instance owns its working path (set
	// at libbox.Setup) and manages the cache file itself.

	if err := applyNodeOutbounds(cfg, n); err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}
