package specnode

import (
	"fmt"
	"regexp"

	"openproxy/core/kernel"
)

// Structural validation aligned with the frozen schema
// (spec/unified-node-model.schema.json). It checks the constraints a
// compiler relies on: required fields, per-protocol credential
// required keys, per-protocol transport enums, and the Security
// conditional rules (reality requires publicKey; none forbids TLS
// fields). It deliberately does NOT check adapter support — that is
// the compiler's / Capabilities' job. Errors are *kernel.Error with
// KindInvalidConfig, matching the adapter layer's error language.

var (
	uuidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	schemaVerRe  = regexp.MustCompile(`^1\.[0-9]+$`)
	base64Key32  = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	extraPortsRe = regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`)
)

func invalid(format string, args ...any) error {
	return kernel.NewError(kernel.KindInvalidConfig, "ValidateNode",
		fmt.Sprintf(format, args...), nil)
}

// allowedTransports per protocol, from the schema's Node branches.
var allowedTransports = map[string][]string{
	ProtocolShadowsocks: {"raw"},
	ProtocolTrojan:      {"raw", "tcp", "ws", "grpc", "http", "httpupgrade", "xhttp"},
	ProtocolVMess:       {"raw", "tcp", "ws", "grpc", "http", "httpupgrade", "xhttp", "kcp", "quic"},
	ProtocolVLESS:       {"raw", "tcp", "ws", "grpc", "http", "httpupgrade", "xhttp", "kcp", "quic"},
	ProtocolHysteria2:   {"raw", "quic"},
	ProtocolTUIC:        {"raw", "quic"},
	ProtocolWireGuard:   {"raw"},
	ProtocolOpenVPN:     {"raw"},
	ProtocolSOCKS5:      {"raw"},
	ProtocolHTTP:        {"raw"},
}

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true,
	"aes-128-cfb":                   true, "aes-192-cfb": true, "aes-256-cfb": true,
	"chacha20": true, "chacha20-ietf": true, "xchacha20": true,
	"rc4-md5": true, "none": true,
}

// Validate checks the node against the schema's structural rules.
func (n *Node) Validate() error {
	if n == nil {
		return invalid("node is nil")
	}
	if !schemaVerRe.MatchString(n.SchemaVersion) {
		return invalid("schemaVersion %q is not a 1.x version", n.SchemaVersion)
	}
	if !uuidRe.MatchString(n.ID) {
		return invalid("id %q is not a UUID", n.ID)
	}
	if n.Name == "" {
		return invalid("name is empty")
	}
	allowed, known := allowedTransports[n.Protocol]
	if !known {
		return invalid("protocol %q is not in the unified model v1", n.Protocol)
	}
	// server/port required except OpenVPN full-text mode.
	ovpnContent := n.Protocol == ProtocolOpenVPN && n.OpenVPN != nil && n.OpenVPN.ConfigContent != ""
	if !ovpnContent {
		if n.Server == "" {
			return invalid("server is empty")
		}
		if n.Port < 1 || n.Port > 65535 {
			return invalid("port %d out of range 1..65535", n.Port)
		}
	}
	// transport enum per protocol branch
	tt := n.TransportType()
	ok := false
	for _, a := range allowed {
		if a == tt {
			ok = true
			break
		}
	}
	if !ok {
		return invalid("transport %q not allowed for protocol %s", tt, n.Protocol)
	}
	if n.Transport != nil {
		if err := validateTransport(n.Transport); err != nil {
			return err
		}
	}
	if err := n.validateSecurity(); err != nil {
		return err
	}
	if n.Source.Kind == "" || n.Source.Ref == "" || n.Source.Authorization == "" {
		return invalid("source requires kind, ref and authorization")
	}
	for _, p := range n.ExtraPorts {
		if !extraPortsRe.MatchString(p) {
			return invalid("extraPorts entry %q is malformed", p)
		}
	}
	return n.validateCredential()
}

func validateTransport(t *Transport) error {
	switch t.GRPCMode {
	case "", "gun", "multi":
	default:
		return invalid("transport.grpcMode %q invalid", t.GRPCMode)
	}
	switch t.CongestionControl {
	case "", "cubic", "new_reno", "bbr":
	default:
		return invalid("transport.congestionControl %q invalid", t.CongestionControl)
	}
	switch t.UDPRelayMode {
	case "", "native", "quic":
	default:
		return invalid("transport.udpRelayMode %q invalid", t.UDPRelayMode)
	}
	return nil
}

func (n *Node) validateSecurity() error {
	s := n.Security
	if s == nil {
		return nil
	}
	switch s.Type {
	case "", "none":
		// Schema: type=none must not carry TLS/Reality fields.
		if s.ServerName != "" || len(s.ALPN) > 0 || s.Fingerprint != "" ||
			s.AllowInsecure || s.CertificatePinSHA256 != "" ||
			s.PublicKey != "" || s.ShortID != "" || s.SpiderX != "" {
			return invalid("security.type=none must not carry TLS/Reality fields")
		}
	case "tls":
	case "reality":
		if s.PublicKey == "" {
			return invalid("security.type=reality requires publicKey")
		}
	default:
		return invalid("security.type %q invalid", s.Type)
	}
	return nil
}

func (n *Node) validateCredential() error {
	switch n.Protocol {
	case ProtocolShadowsocks:
		c := n.Shadowsocks
		if c == nil {
			return invalid("shadowsocks credential missing")
		}
		if !ssMethods[c.Method] {
			return invalid("shadowsocks method %q not in schema enum", c.Method)
		}
		if c.Password == "" {
			return invalid("shadowsocks password is empty")
		}
	case ProtocolTrojan:
		if n.Trojan == nil || n.Trojan.Password == "" {
			return invalid("trojan password is empty")
		}
	case ProtocolVMess:
		c := n.VMess
		if c == nil || !uuidRe.MatchString(c.UUID) {
			return invalid("vmess uuid invalid")
		}
		if c.AlterId != nil && *c.AlterId < 0 {
			return invalid("vmess alterId negative")
		}
		switch c.Cipher {
		case "", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
		default:
			return invalid("vmess cipher %q invalid", c.Cipher)
		}
	case ProtocolVLESS:
		c := n.VLESS
		if c == nil || !uuidRe.MatchString(c.UUID) {
			return invalid("vless uuid invalid")
		}
		switch c.Flow {
		case "", "xtls-rprx-vision", "xtls-rprx-vision-udp443":
		default:
			return invalid("vless flow %q invalid", c.Flow)
		}
	case ProtocolHysteria2:
		c := n.Hysteria2
		if c == nil || c.Auth == "" {
			return invalid("hysteria2 auth is empty")
		}
		if c.ObfsType != "" {
			if c.ObfsType != "salamander" {
				return invalid("hysteria2 obfsType %q invalid", c.ObfsType)
			}
			if c.ObfsPassword == "" {
				return invalid("hysteria2 obfsPassword required with obfsType")
			}
		}
	case ProtocolTUIC:
		c := n.TUIC
		if c == nil || !uuidRe.MatchString(c.UUID) {
			return invalid("tuic uuid invalid")
		}
		if c.Password == "" {
			return invalid("tuic password is empty")
		}
	case ProtocolWireGuard:
		c := n.WireGuard
		if c == nil {
			return invalid("wireguard credential missing")
		}
		if !base64Key32.MatchString(c.PrivateKey) {
			return invalid("wireguard privateKey is not a base64 32-byte key")
		}
		if !base64Key32.MatchString(c.PeerPublicKey) {
			return invalid("wireguard peerPublicKey is not a base64 32-byte key")
		}
		if c.PreSharedKey != "" && !base64Key32.MatchString(c.PreSharedKey) {
			return invalid("wireguard preSharedKey is not a base64 32-byte key")
		}
		if len(c.Addresses) == 0 {
			return invalid("wireguard addresses is empty")
		}
		if c.MTU != 0 && (c.MTU < 128 || c.MTU > 9000) {
			return invalid("wireguard mtu %d out of range", c.MTU)
		}
		if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
			return invalid("wireguard reserved must have exactly 3 bytes")
		}
	case ProtocolOpenVPN:
		c := n.OpenVPN
		if c == nil {
			return invalid("openvpn credential missing")
		}
		if c.ConfigContent == "" {
			switch c.Proto {
			case "udp", "tcp", "udp4", "udp6", "tcp4", "tcp6":
			default:
				return invalid("openvpn structured mode requires a valid proto")
			}
			if n.Server == "" || n.Port < 1 || n.Port > 65535 {
				return invalid("openvpn structured mode requires server and port")
			}
		}
	case ProtocolSOCKS5, ProtocolHTTP:
		if n.UserPass != nil && n.UserPass.Username != "" && n.UserPass.Password == "" {
			return invalid("password required when username is set")
		}
	}
	return nil
}
