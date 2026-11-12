package routecfg

// The default security configuration package (Step 11
// deliverable 3): two baseline policies, shipped as JSON in
// defaults/ and guaranteed — by test — to be exactly these
// constructors serialized.
//
// Shared posture of both defaults:
//
//   - Rule mode with the private bypass on: LAN destinations
//     stay reachable without hand-written rules, and every
//     user rule still outranks the bypass.
//   - DNS remote-by-default through the tunnel (DoT to
//     1.1.1.1; the resolver is a replaceable policy field,
//     not a product endorsement), local resolver ONLY for
//     names the user routes direct. No plaintext fallback:
//     dns.final is the remote server, full stop.
//   - Fake-ip OFF (the Step 11 ruling; opt-in per policy).
//
// The difference between the two is the traffic surface they
// are written for; see defaults/README.md.

const defaultRemoteDNS = "1.1.1.1" // Cloudflare DoT; replaceable

func defaultDNS() DNSPolicy {
	return DNSPolicy{
		Remote: DNSServerSpec{Type: "tls", Server: defaultRemoteDNS, Port: 853},
		Local:  DNSServerSpec{Type: "local"},
	}
}

// DefaultSystemProxyPolicy is the baseline for system-proxy
// mode (book 8.2: Windows v1.0; apps that honor the OS proxy
// hand their names to the client, which resolves them under
// this policy). IPv6 posture "on": a system-proxy client does
// not own the OS network stack, so an IPv6 posture stronger
// than the routing rules themselves would promise control it
// does not have; the v6 story of this mode is the leak-check
// guidance, not a config invariant.
func DefaultSystemProxyPolicy() Policy {
	return Policy{
		Mode:          ModeRule,
		BypassPrivate: true,
		IPv6:          IPv6On,
		DNS:           defaultDNS(),
		Notes:         "Relavia default security configuration: system-proxy mode. See core/routecfg/defaults/README.md.",
	}
}

// DefaultTUNPolicy is the baseline for TUN mode (Windows
// Wintun / Android VpnService), where the client DOES own the
// device's traffic. IPv6 posture is therefore "tunnel": any
// IPv6 the OS emits enters the tunnel and can never fall back
// to a direct path — the classic TUN-mode IPv6 bypass is
// closed at the config layer (the platform layer still owes
// its half: capturing v6 in the TUN interface at all, Steps
// 9/10, and the kill switch, Step 12).
func DefaultTUNPolicy() Policy {
	return Policy{
		Mode:          ModeRule,
		BypassPrivate: true,
		IPv6:          IPv6Tunnel,
		DNS:           defaultDNS(),
		Notes:         "Relavia default security configuration: TUN mode. See core/routecfg/defaults/README.md.",
	}
}
