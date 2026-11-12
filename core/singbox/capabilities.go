package singbox

import (
	"fmt"
	"runtime"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// Capability honesty rules for this adapter (proposal book 3.3
// honesty principle, 4.3, 5.3):
//
//   - The single source of truth is specSupport below, expressed in
//     UNIFIED MODEL coordinates (spec transport/security names). The
//     kernel-facing matrix in Capabilities() is hand-mirrored from
//     it in kernel coordinates, and a consistency test fails if a
//     spec combination projects outside the kernel matrix.
//   - A combination is only listed if the pinned sing-box build
//     (with the project's official build tags) actually implements
//     it. Upstream features that exist but were NOT verified by
//     this step's loopback tests stay unlisted (e.g. AnyTLS, VLESS
//     over QUIC transport, mKCP, XHTTP — the latter two do not
//     exist in sing-box 1.14 at all).
//   - OpenVPN is intentionally absent: per the Step 2 license
//     audit (F-1) it is integrated as an independent process, never
//     linked into this in-process adapter.

// specSupport: protocol -> transport -> security layers, in
// unified-model coordinates. Feature-gated rows are added by
// supportedSpec() according to the build's feature flags.
var specSupportBase = map[string]map[string][]string{
	specnode.ProtocolShadowsocks: {
		"raw": {"none"},
	},
	specnode.ProtocolTrojan: {
		"raw": {"tls"}, "tcp": {"tls"}, "ws": {"tls"},
		"grpc": {"tls"}, "http": {"tls"}, "httpupgrade": {"tls"},
	},
	specnode.ProtocolVMess: {
		"raw": {"none", "tls"}, "tcp": {"none", "tls"}, "ws": {"none", "tls"},
		"grpc": {"none", "tls"}, "http": {"none", "tls"}, "httpupgrade": {"none", "tls"},
	},
	specnode.ProtocolVLESS: {
		"raw": {"none", "tls"}, "tcp": {"none", "tls"}, "ws": {"none", "tls"},
		"grpc": {"none", "tls"}, "http": {"none", "tls"}, "httpupgrade": {"none", "tls"},
	},
	specnode.ProtocolSOCKS5: {
		"raw": {"none"},
	},
	specnode.ProtocolHTTP: {
		"raw": {"none", "tls"},
	},
}

// specSupportGated rows depend on build features.
func supportedSpec() map[string]map[string][]string {
	out := make(map[string]map[string][]string, len(specSupportBase))
	for p, rows := range specSupportBase {
		cp := make(map[string][]string, len(rows))
		for t, secs := range rows {
			cp[t] = append([]string(nil), secs...)
		}
		out[p] = cp
	}
	if featureUTLS {
		// Reality (vless, stream transports raw/tcp only).
		for _, tr := range []string{"raw", "tcp"} {
			out[specnode.ProtocolVLESS][tr] = append(out[specnode.ProtocolVLESS][tr], "reality")
		}
	}
	if featureQUIC {
		out[specnode.ProtocolHysteria2] = map[string][]string{
			"raw": {"tls"}, "quic": {"tls"},
		}
		out[specnode.ProtocolTUIC] = map[string][]string{
			"raw": {"tls"}, "quic": {"tls"},
		}
	}
	if featureWireGuard {
		out[specnode.ProtocolWireGuard] = map[string][]string{
			"raw": {"none"},
		}
	}
	return out
}

// ssAEADMethods are the Shadowsocks methods the pinned sing-box
// implements (AEAD family + SS2022). The schema's legacy methods
// (cfb family, chacha20 variants, rc4-md5, none) remain importable
// into the unified model but cannot be compiled by this kernel;
// checkSupported rejects them explicitly.
var ssAEADMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
}

// checkSupported is the adapter's authoritative support gate,
// evaluated on the unified model before compilation. It returns
// *kernel.Error with KindUnsupported (or KindInvalidConfig for
// missing compile inputs that a placeholder projection cannot
// carry).
func checkSupported(n *specnode.Node) error {
	unsup := func(format string, args ...any) error {
		return kernel.NewError(kernel.KindUnsupported, "ValidateConfig",
			fmt.Sprintf(format, args...), nil)
	}
	if n.Protocol == specnode.ProtocolOpenVPN {
		return unsup("openvpn is integrated as an independent process " +
			"(Step 2 license audit F-1) and is not supported by the in-process sing-box adapter")
	}
	rows, ok := supportedSpec()[n.Protocol]
	if !ok {
		return unsup("protocol %s not supported by kernel %q", n.Protocol, kernelID)
	}
	secs, ok := rows[n.TransportType()]
	if !ok {
		return unsup("transport %s not supported for protocol %s by kernel %q",
			n.TransportType(), n.Protocol, kernelID)
	}
	st := n.SecurityType()
	found := false
	for _, s := range secs {
		if s == st {
			found = true
			break
		}
	}
	if !found {
		return unsup("security %s not supported for %s/%s by kernel %q",
			st, n.Protocol, n.TransportType(), kernelID)
	}
	// Feature-level refinements.
	if n.Security != nil && n.Security.Fingerprint != "" && !featureUTLS {
		return unsup("uTLS fingerprint %q requires a build with the with_utls tag", n.Security.Fingerprint)
	}
	if n.Protocol == specnode.ProtocolShadowsocks && n.Shadowsocks != nil {
		if !ssAEADMethods[n.Shadowsocks.Method] {
			return unsup("shadowsocks method %s is not implemented by sing-box "+
				"(legacy method kept in the unified model for lossless import only)",
				n.Shadowsocks.Method)
		}
	}
	return nil
}

// checkCompileInputs verifies the credential fields compilation
// actually consumes. It complements spec validation on the
// kernel-placeholder path, where a full spec document (with UUID
// ids and source registration) does not exist.
func checkCompileInputs(n *specnode.Node) error {
	inv := func(format string, args ...any) error {
		return kernel.NewError(kernel.KindInvalidConfig, "ValidateConfig",
			fmt.Sprintf(format, args...), nil)
	}
	if n.Server == "" && n.Protocol != specnode.ProtocolOpenVPN {
		return inv("node.server is empty")
	}
	if n.Port < 1 || n.Port > 65535 {
		return inv("node.port %d out of range 1..65535", n.Port)
	}
	switch n.Protocol {
	case specnode.ProtocolShadowsocks:
		if n.Shadowsocks == nil || n.Shadowsocks.Password == "" {
			return inv("shadowsocks password is empty")
		}
	case specnode.ProtocolTrojan:
		if n.Trojan == nil || n.Trojan.Password == "" {
			return inv("trojan password is empty")
		}
	case specnode.ProtocolVMess:
		if n.VMess == nil || n.VMess.UUID == "" {
			return inv("vmess uuid is empty")
		}
	case specnode.ProtocolVLESS:
		if n.VLESS == nil || n.VLESS.UUID == "" {
			return inv("vless uuid is empty")
		}
		if n.SecurityType() == "reality" && (n.Security == nil || n.Security.PublicKey == "") {
			return inv("reality security requires security.publicKey")
		}
	case specnode.ProtocolHysteria2:
		if n.Hysteria2 == nil || n.Hysteria2.Auth == "" {
			return inv("hysteria2 auth is empty")
		}
	case specnode.ProtocolTUIC:
		if n.TUIC == nil || n.TUIC.UUID == "" || n.TUIC.Password == "" {
			return inv("tuic uuid/password is empty")
		}
	case specnode.ProtocolWireGuard:
		c := n.WireGuard
		if c == nil || c.PrivateKey == "" || c.PeerPublicKey == "" || len(c.Addresses) == 0 {
			return inv("wireguard requires privateKey, peerPublicKey and addresses; " +
				"these cannot be carried by the placeholder kernel node — supply a unified-model node")
		}
	case specnode.ProtocolOpenVPN:
		return inv("openvpn nodes are handled by the independent-process adapter, not this one")
	case specnode.ProtocolSOCKS5, specnode.ProtocolHTTP:
		if n.UserPass != nil && n.UserPass.Username != "" && n.UserPass.Password == "" {
			return inv("password required when username is set")
		}
	}
	return nil
}

// Capabilities implements kernel.Adapter: the kernel-coordinate
// matrix mirrored from supportedSpec(), plus this build's platform
// facts. TUN / system-proxy are reported FALSE: this step
// integrates the kernel as an in-process local listener only;
// platform networking lands in Steps 9-12 and Start refuses those
// modes explicitly instead of silently degrading. KillSwitch is
// reported from the REAL Step 12 status source when one is
// attached (Options.KillSwitchReport): true only at
// ReadinessEnforceable — with no source attached (every build
// Step 12 ships) it stays honestly false.
func (a *Adapter) Capabilities() kernel.Capabilities {
	tlsOnly := []kernel.SecurityType{kernel.SecurityTLS}
	protocols := map[kernel.Protocol]kernel.ProtocolSupport{
		kernel.ProtocolShadowsocks: {Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityAEAD}, UDP: true},
		}},
		kernel.ProtocolTrojan: {Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportTCP:   {Security: tlsOnly},
			kernel.TransportWS:    {Security: tlsOnly},
			kernel.TransportGRPC:  {Security: tlsOnly},
			kernel.TransportHTTP2: {Security: tlsOnly},
		}},
		kernel.ProtocolVMess: {Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportTCP:   {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}, UDP: true},
			kernel.TransportWS:    {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}},
			kernel.TransportGRPC:  {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}},
			kernel.TransportHTTP2: {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}},
		}},
		kernel.ProtocolVLESS: {Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportTCP:   {Security: vlessTCPSecurity(), UDP: true},
			kernel.TransportWS:    {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
			kernel.TransportGRPC:  {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
			kernel.TransportHTTP2: {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
		}},
		kernel.ProtocolSOCKS5: {Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityNone}},
		}},
		kernel.ProtocolHTTP: {Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
		}},
	}
	if featureQUIC {
		protocols[kernel.ProtocolHysteria2] = kernel.ProtocolSupport{Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportQUIC: {Security: tlsOnly, UDP: true},
		}}
		protocols[kernel.ProtocolTUIC] = kernel.ProtocolSupport{Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportQUIC: {Security: tlsOnly, UDP: true},
		}}
	}
	if featureWireGuard {
		protocols[kernel.ProtocolWireGuard] = kernel.ProtocolSupport{Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityNone}, UDP: true},
		}}
	}
	return kernel.Capabilities{
		KernelID:      kernelID,
		KernelVersion: singBoxVersion,
		Protocols:     protocols,
		Platform: kernel.PlatformCapabilities{
			Platform:              runtime.GOOS,
			TUN:                   false,
			SystemProxy:           false,
			KillSwitch:            a.killSwitchEnforceable(),
			IPv6:                  false,
			RequiresVPNPermission: false,
		},
		Features: kernel.FeatureSet{
			HandshakeTest: true,
			TrafficStats:  true,
			UDP:           true,
		},
	}
}

func vlessTCPSecurity() []kernel.SecurityType {
	secs := []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS, kernel.SecurityXTLSVision}
	if featureUTLS {
		secs = append(secs, kernel.SecurityReality)
	}
	return secs
}
