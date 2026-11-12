package kernel

// ---------------------------------------------------------------------------
// PLACEHOLDER NODE MODEL — READ BEFORE EDITING
//
// Node below is a MINIMAL PLACEHOLDER. The authoritative unified node
// model is defined by Step 5 in the spec/ directory (JSON Schema) and is
// being finalized in parallel with this Step 6 work. The fields here are
// a strict subset of the illustrative model in proposal book 5.2, kept
// only so the adapter interface can be typed and mocked now.
//
// When Step 5 lands, this type MUST be replaced by (or generated from)
// the spec/ model. Replacement points:
//   - Node and its nested Credential / Transport / Security / Source
//     structs in this file;
//   - ValidateNode in validate.go (field rules follow the schema);
//   - the JSON tags below must match the schema field names exactly.
// Do NOT extend this placeholder with new fields on your own authority;
// field changes go through the Step 5 schema / RFC process (book 5.2).
// ---------------------------------------------------------------------------

// Protocol identifies a proxy/VPN protocol. Values match the protocol
// names used in proposal book 4.1 and in share-link schemes (4.2).
type Protocol string

const (
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolVMess       Protocol = "vmess"
	ProtocolVLESS       Protocol = "vless"
	ProtocolHysteria2   Protocol = "hysteria2"
	ProtocolTUIC        Protocol = "tuic"
	ProtocolWireGuard   Protocol = "wireguard"
	ProtocolOpenVPN     Protocol = "openvpn"
	ProtocolSOCKS5      Protocol = "socks5"
	ProtocolHTTP        Protocol = "http"
	// Second tier (book 4.1), orchestrated rather than in-kernel.
	ProtocolSoftEther Protocol = "softether"
	ProtocolL2TP      Protocol = "l2tp"
	ProtocolSSTP      Protocol = "sstp"
	ProtocolAnyTLS    Protocol = "anytls"
)

// TransportType identifies the transport layer of a node.
type TransportType string

const (
	// TransportNative is the protocol's own native transport
	// (e.g. WireGuard over UDP, plain Shadowsocks).
	TransportNative TransportType = "native"
	TransportTCP    TransportType = "tcp"
	TransportUDP    TransportType = "udp"
	TransportWS     TransportType = "ws"
	TransportHTTP2  TransportType = "http2"
	TransportGRPC   TransportType = "grpc"
	TransportQUIC   TransportType = "quic"
)

// SecurityType identifies the security / camouflage layer of a node.
type SecurityType string

const (
	SecurityNone       SecurityType = "none"
	SecurityTLS        SecurityType = "tls"
	SecurityAEAD       SecurityType = "aead" // protocol-native AEAD (SS, VMess)
	SecurityReality    SecurityType = "reality"
	SecurityXTLSVision SecurityType = "xtls-vision"
)

// Credential carries node secrets. Treat as a password at all times
// (proposal book 9.1): never log it, never send it anywhere.
type Credential struct {
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"` // e.g. Shadowsocks cipher
	Flow     string `json:"flow,omitempty"`   // e.g. "xtls-rprx-vision"
}

// Transport is the placeholder transport block (book 5.2 "transport").
type Transport struct {
	Type TransportType `json:"type"`
	Path string        `json:"path,omitempty"`
	Host string        `json:"host,omitempty"`
}

// Security is the placeholder security block (book 5.2 "security").
type Security struct {
	Type        SecurityType `json:"type"`
	ServerName  string       `json:"serverName,omitempty"`
	PublicKey   string       `json:"publicKey,omitempty"` // Reality
	ShortID     string       `json:"shortId,omitempty"`   // Reality
	Fingerprint string       `json:"fingerprint,omitempty"`
}

// Source identifies where a node came from (book 5.2 "source", ch. 7).
type Source struct {
	Kind          string `json:"kind"` // "subscription" | "manual" | "plugin"
	Ref           string `json:"ref,omitempty"`
	Authorization string `json:"authorization,omitempty"`
}

// Node is the placeholder unified node (see the placeholder notice at
// the top of this file).
type Node struct {
	ID         string     `json:"id"`
	Name       string     `json:"name,omitempty"`
	Protocol   Protocol   `json:"protocol"`
	Server     string     `json:"server"`
	Port       int        `json:"port"`
	Credential Credential `json:"credential"`
	Transport  Transport  `json:"transport"`
	Security   Security   `json:"security"`
	UDP        bool       `json:"udp"`
	Source     Source     `json:"source"`
	Group      string     `json:"group,omitempty"`
}

// Config is a complete configuration handed to an adapter: the active
// outbound node plus, in future revisions, routing and DNS sections.
// Routing/DNS fields are deliberately absent until the Step 5 model and
// the Step 11 (routing & DNS) design land; add them here, not ad hoc in
// individual adapters.
type Config struct {
	Node *Node `json:"node"`
}

// RunMode selects how traffic enters the kernel (book 5.4).
type RunMode string

const (
	// ModeTUN routes all system traffic through a TUN device
	// (Windows: Wintun; Android: VpnService).
	ModeTUN RunMode = "tun"
	// ModeSystemProxy sets the OS system proxy (driverless fallback).
	ModeSystemProxy RunMode = "system-proxy"
	// ModeManual starts only a local listener; the user/OS routes
	// traffic to it explicitly.
	ModeManual RunMode = "manual"
)

// PlatformOptions are the platform network options of proposal book
// 5.3's Start(model, platformOptions) and 5.4's platform layer.
type PlatformOptions struct {
	Mode RunMode `json:"mode"`
	// KillSwitch requests the global kill switch (book 5.4): block
	// direct traffic if the tunnel drops. If requested but not
	// available on this platform (Capabilities.Platform.KillSwitch
	// is false), Start must fail with KindPlatformUnavailable
	// rather than silently running unprotected.
	KillSwitch bool `json:"killSwitch"`
	// IPv6 enables IPv6 routing through the tunnel.
	IPv6 bool `json:"ipv6"`
	// MTU optionally overrides the TUN MTU (0 = adapter default).
	MTU int `json:"mtu,omitempty"`
}
