// Package specnode is the Go type layer for the project's unified
// node model, whose authoritative definition is the frozen JSON
// Schema in spec/unified-node-model.schema.json (Step 5, model v1,
// frozen 2026-11-12). Field names, enums and per-protocol credential
// shapes in this package mirror that schema exactly; any change must
// go through the schema's RFC process first (proposal book 5.2).
//
// Why this package exists (Step 7 docking decision, see
// docs/step7-sing-box集成.md): the Step 6 adapter interface in
// package kernel still carries a MINIMAL PLACEHOLDER Node (a flat
// credential union that cannot express e.g. WireGuard keys, SS
// plugins, Hysteria2 obfs or gRPC service names). Rather than
// rewriting the reviewed kernel package and its tests, Step 7 keeps
// the kernel interface untouched and puts the full-fidelity model
// here:
//
//   - Parsers and source plugins (book 5.1) produce specnode.Node.
//   - Kernel adapters compile configurations FROM specnode.Node.
//   - A documented projection (ProjectKernel) maps a spec node onto
//     the placeholder kernel.Node so interface-level validation
//     (kernel.ValidateAgainst) keeps working; the projection is
//     lossy in enumerated places and is NOT used for compilation.
//   - The reverse conversion (FromKernel) lets callers that only
//     hold a placeholder kernel.Node still drive a real adapter;
//     fields the placeholder cannot carry are simply absent, and
//     protocols that require them (WireGuard, OpenVPN) fail with a
//     precise invalid_config error instead of a silent wrong config.
package specnode

import (
	"encoding/json"
	"fmt"

	"openproxy/core/kernel"
)

// Protocol names, identical to the schema's Node.protocol enum
// (first tier of proposal book 4.1).
const (
	ProtocolShadowsocks = "shadowsocks"
	ProtocolTrojan      = "trojan"
	ProtocolVMess       = "vmess"
	ProtocolVLESS       = "vless"
	ProtocolHysteria2   = "hysteria2"
	ProtocolTUIC        = "tuic"
	ProtocolWireGuard   = "wireguard"
	ProtocolOpenVPN     = "openvpn"
	ProtocolSOCKS5      = "socks5"
	ProtocolHTTP        = "http"
)

// Transport mirrors the schema's Transport definition. Type values:
// raw, tcp, ws, http, httpupgrade, grpc, xhttp, kcp, quic. An absent
// Transport on a Node means the protocol's native transport.
type Transport struct {
	Type              string            `json:"type"`
	Path              string            `json:"path,omitempty"`
	Host              string            `json:"host,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	HeaderType        string            `json:"headerType,omitempty"`
	ServiceName       string            `json:"serviceName,omitempty"`
	GRPCMode          string            `json:"grpcMode,omitempty"`
	Seed              string            `json:"seed,omitempty"`
	Mode              string            `json:"mode,omitempty"`
	CongestionControl string            `json:"congestionControl,omitempty"`
	UDPRelayMode      string            `json:"udpRelayMode,omitempty"`
}

// Security mirrors the schema's Security definition. Type values:
// none, tls, reality. Reality requires PublicKey.
type Security struct {
	Type                 string   `json:"type"`
	ServerName           string   `json:"serverName,omitempty"`
	ALPN                 []string `json:"alpn,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	AllowInsecure        bool     `json:"allowInsecure,omitempty"`
	CertificatePinSHA256 string   `json:"certificatePinSha256,omitempty"`
	PublicKey            string   `json:"publicKey,omitempty"`
	ShortID              string   `json:"shortId,omitempty"`
	SpiderX              string   `json:"spiderX,omitempty"`
}

// SourceRef mirrors the schema's NodeSourceRef (book 5.2 / 7.2).
type SourceRef struct {
	Kind          string `json:"kind"`
	Ref           string `json:"ref"`
	Authorization string `json:"authorization"`
}

// LastTest mirrors the schema's LastTest (book 5.2).
type LastTest struct {
	At        string   `json:"at"`
	LatencyMs *float64 `json:"latencyMs,omitempty"`
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
}

// --- Per-protocol credentials (schema $defs Cred*) -----------------

type CredShadowsocks struct {
	Method     string `json:"method"`
	Password   string `json:"password"`
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"pluginOpts,omitempty"`
}

type CredTrojan struct {
	Password string `json:"password"`
}

type CredVMess struct {
	UUID    string `json:"uuid"`
	AlterId *int   `json:"alterId,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
}

type CredVLESS struct {
	UUID       string `json:"uuid"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption,omitempty"`
}

type CredHysteria2 struct {
	Auth         string `json:"auth"`
	ObfsType     string `json:"obfsType,omitempty"`
	ObfsPassword string `json:"obfsPassword,omitempty"`
}

type CredTUIC struct {
	UUID     string `json:"uuid"`
	Password string `json:"password"`
}

type CredWireGuard struct {
	PrivateKey          string   `json:"privateKey"`
	PeerPublicKey       string   `json:"peerPublicKey"`
	PreSharedKey        string   `json:"preSharedKey,omitempty"`
	Addresses           []string `json:"addresses"`
	AllowedIPs          []string `json:"allowedIPs,omitempty"`
	DNS                 []string `json:"dns,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
	Reserved            []int    `json:"reserved,omitempty"`
}

// CredOpenVPN covers both schema modes: full-text (ConfigContent
// set) and structured (Proto set). Username/Password are shared.
type CredOpenVPN struct {
	// Full-text mode
	ConfigContent string `json:"configContent,omitempty"`
	// Structured mode
	Proto           string `json:"proto,omitempty"`
	Cipher          string `json:"cipher,omitempty"`
	DataCiphers     string `json:"dataCiphers,omitempty"`
	AuthDigest      string `json:"authDigest,omitempty"`
	CACert          string `json:"caCert,omitempty"`
	ClientCert      string `json:"clientCert,omitempty"`
	ClientKey       string `json:"clientKey,omitempty"`
	TLSAuthKey      string `json:"tlsAuthKey,omitempty"`
	TLSCryptKey     string `json:"tlsCryptKey,omitempty"`
	KeyDirection    *int   `json:"keyDirection,omitempty"`
	RedirectGateway bool   `json:"redirectGateway,omitempty"`
	BlockOutsideDNS bool   `json:"blockOutsideDns,omitempty"`
	// Shared
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type CredUserPass struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Node is one unified node document (schema $defs Node). Exactly one
// of the credential fields is populated, selected by Protocol; use
// the typed accessors or switch on Protocol.
type Node struct {
	SchemaVersion string     `json:"schemaVersion"`
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Protocol      string     `json:"protocol"`
	Server        string     `json:"server,omitempty"`
	Port          int        `json:"port,omitempty"`
	Transport     *Transport `json:"transport,omitempty"`
	Security      *Security  `json:"security,omitempty"`
	UDP           bool       `json:"udp,omitempty"`
	ExtraPorts    []string   `json:"extraPorts,omitempty"`
	Source        SourceRef  `json:"source"`
	Group         string     `json:"group,omitempty"`
	LastTest      *LastTest  `json:"lastTest,omitempty"`
	Tags          []string   `json:"tags,omitempty"`
	Remarks       string     `json:"remarks,omitempty"`

	// RawCredential is the verbatim credential object from the
	// source document, kept for lossless round-tripping.
	RawCredential json.RawMessage `json:"-"`

	Shadowsocks *CredShadowsocks `json:"-"`
	Trojan      *CredTrojan      `json:"-"`
	VMess       *CredVMess       `json:"-"`
	VLESS       *CredVLESS       `json:"-"`
	Hysteria2   *CredHysteria2   `json:"-"`
	TUIC        *CredTUIC        `json:"-"`
	WireGuard   *CredWireGuard   `json:"-"`
	OpenVPN     *CredOpenVPN     `json:"-"`
	UserPass    *CredUserPass    `json:"-"` // socks5 / http
}

type nodeAlias Node // avoid recursion in UnmarshalJSON

type nodeWire struct {
	*nodeAlias
	Credential json.RawMessage `json:"credential"`
}

// UnmarshalJSON decodes a unified node document, dispatching the
// credential object to the per-protocol struct named by the schema's
// discriminated union.
func (n *Node) UnmarshalJSON(data []byte) error {
	var wire nodeWire
	wire.nodeAlias = (*nodeAlias)(n)
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	n.RawCredential = wire.Credential
	if len(wire.Credential) == 0 {
		return nil // Validate() reports the missing credential
	}
	return n.decodeCredential(wire.Credential)
}

func (n *Node) decodeCredential(raw json.RawMessage) error {
	var err error
	switch n.Protocol {
	case ProtocolShadowsocks:
		n.Shadowsocks = &CredShadowsocks{}
		err = json.Unmarshal(raw, n.Shadowsocks)
	case ProtocolTrojan:
		n.Trojan = &CredTrojan{}
		err = json.Unmarshal(raw, n.Trojan)
	case ProtocolVMess:
		n.VMess = &CredVMess{}
		err = json.Unmarshal(raw, n.VMess)
	case ProtocolVLESS:
		n.VLESS = &CredVLESS{}
		err = json.Unmarshal(raw, n.VLESS)
	case ProtocolHysteria2:
		n.Hysteria2 = &CredHysteria2{}
		err = json.Unmarshal(raw, n.Hysteria2)
	case ProtocolTUIC:
		n.TUIC = &CredTUIC{}
		err = json.Unmarshal(raw, n.TUIC)
	case ProtocolWireGuard:
		n.WireGuard = &CredWireGuard{}
		err = json.Unmarshal(raw, n.WireGuard)
	case ProtocolOpenVPN:
		n.OpenVPN = &CredOpenVPN{}
		err = json.Unmarshal(raw, n.OpenVPN)
	case ProtocolSOCKS5, ProtocolHTTP:
		n.UserPass = &CredUserPass{}
		err = json.Unmarshal(raw, n.UserPass)
	default:
		return fmt.Errorf("specnode: unknown protocol %q", n.Protocol)
	}
	if err != nil {
		return fmt.Errorf("specnode: credential for %s: %w", n.Protocol, err)
	}
	return nil
}

// MarshalJSON re-emits the node with its typed credential, so a
// parsed node round-trips to an equivalent document.
func (n *Node) MarshalJSON() ([]byte, error) {
	cred, err := n.credentialJSON()
	if err != nil {
		return nil, err
	}
	wire := nodeWire{nodeAlias: (*nodeAlias)(n), Credential: cred}
	return json.Marshal(wire)
}

func (n *Node) credentialJSON() (json.RawMessage, error) {
	var v any
	switch n.Protocol {
	case ProtocolShadowsocks:
		v = n.Shadowsocks
	case ProtocolTrojan:
		v = n.Trojan
	case ProtocolVMess:
		v = n.VMess
	case ProtocolVLESS:
		v = n.VLESS
	case ProtocolHysteria2:
		v = n.Hysteria2
	case ProtocolTUIC:
		v = n.TUIC
	case ProtocolWireGuard:
		v = n.WireGuard
	case ProtocolOpenVPN:
		v = n.OpenVPN
	case ProtocolSOCKS5, ProtocolHTTP:
		v = n.UserPass
	}
	if v == nil {
		return n.RawCredential, nil
	}
	return json.Marshal(v)
}

// Parse decodes and validates one unified node JSON document.
func Parse(data []byte) (*Node, error) {
	var n Node
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, err
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return &n, nil
}

// TransportType returns the effective transport type: "raw" when the
// transport block is omitted (schema: native transport).
func (n *Node) TransportType() string {
	if n.Transport == nil || n.Transport.Type == "" {
		return "raw"
	}
	return n.Transport.Type
}

// SecurityType returns the effective security type: "none" when the
// security block is omitted.
func (n *Node) SecurityType() string {
	if n.Security == nil || n.Security.Type == "" {
		return "none"
	}
	return n.Security.Type
}

var _ = kernel.KindInvalidConfig // error kinds are produced in validate.go
