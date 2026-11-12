package kernel

// Capabilities is the adapter's self-reported capability set:
// proposal book 5.3's "Capabilities() -> protocolMatrix", expressing
// the protocol x transport x security matrix of book 4.1 plus the
// platform capabilities of book 5.4.
//
// The UI renders this matrix and greys out unsupported combinations;
// adapters must report honestly — a combination that is not listed is
// NOT supported, and ValidateConfig/Start must reject it with
// KindUnsupported rather than failing silently later.
type Capabilities struct {
	// KernelID identifies the adapter implementation, e.g. "mock" or
	// a neutral backend identifier. It is a diagnostics label, not a
	// product name.
	KernelID string
	// KernelVersion is the implementation's version string.
	KernelVersion string

	// Protocols is the support matrix: protocol -> transports ->
	// security layers.
	Protocols map[Protocol]ProtocolSupport

	// Platform describes the current environment's capabilities.
	Platform PlatformCapabilities

	// Features lists cross-cutting adapter features.
	Features FeatureSet
}

// ProtocolSupport is one row of the matrix.
type ProtocolSupport struct {
	Transports map[TransportType]TransportSupport
}

// TransportSupport is one cell column of the matrix: which security
// layers are available over this transport, and whether UDP is
// carried.
type TransportSupport struct {
	Security []SecurityType
	UDP      bool
}

// PlatformCapabilities expresses the platform network layer (book
// 5.4) as observable facts, so Start can fail explicitly with
// KindPlatformUnavailable instead of silently degrading.
type PlatformCapabilities struct {
	// Platform is a neutral identifier: "windows" | "android" |
	// "macos" | "linux".
	Platform string
	// TUN reports whether TUN mode can be used here (Windows:
	// Wintun present; Android: VpnService permission grantable).
	TUN bool
	// SystemProxy reports whether system-proxy mode is available.
	SystemProxy bool
	// KillSwitch reports whether the platform kill switch (book
	// 5.4) can be enforced.
	KillSwitch bool
	// IPv6 reports whether IPv6 can be routed through the tunnel.
	IPv6 bool
	// RequiresVPNPermission is true where the OS requires an
	// explicit per-app VPN consent flow before TUN start
	// (e.g. Android VpnService).
	RequiresVPNPermission bool
}

// FeatureSet lists cross-cutting capabilities not tied to a protocol.
type FeatureSet struct {
	HandshakeTest bool // real-handshake TestHandshake implemented
	TrafficStats  bool // QueryTraffic returns real counters
	UDP           bool // any protocol can carry UDP
}

// Supports reports whether the exact protocol/transport/security
// combination is in the matrix.
func (c Capabilities) Supports(p Protocol, t TransportType, s SecurityType) bool {
	ps, ok := c.Protocols[p]
	if !ok {
		return false
	}
	ts, ok := ps.Transports[t]
	if !ok {
		return false
	}
	for _, sec := range ts.Security {
		if sec == s {
			return true
		}
	}
	return false
}

// SupportsNode reports whether the node's combination is supported.
func (c Capabilities) SupportsNode(n *Node) bool {
	if n == nil {
		return false
	}
	return c.Supports(n.Protocol, n.Transport.Type, n.Security.Type)
}
