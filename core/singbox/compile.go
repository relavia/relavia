package singbox

import (
	"encoding/json"
	"fmt"
	"strings"

	"openproxy/core/kernel"
	"openproxy/core/routecfg"
	"openproxy/core/specnode"
)

// Config compilation: unified node (specnode) -> sing-box JSON
// configuration. The generated document is deliberately minimal:
//
//	log (level from options) + one mixed inbound on loopback +
//	the node's outbound (or WireGuard endpoint) + a direct
//	outbound + route.final pointing at the node.
//
// With no routing policy attached, no DNS section is emitted:
// all addressing is by literal IP or the kernel's defaults.
// Step 11 (package routecfg) supplies the routing/DNS policy
// layer: when compileOptions.fragment is set, the fragment's
// route and dns sections replace the bare route.final below.
//
// The map-based generation (instead of sing-box's option structs)
// keeps the compiler readable against the JSON format users and
// subscriptions already speak (book 4.2: sing-box JSON is a
// first-class subscription format); sing-box's own extended-JSON
// parser validates the result when an instance is created, and
// the loopback tests exercise every emitted shape end-to-end.

type compileOptions struct {
	listenHost string
	listenPort int
	logLevel   string
	// cachePath is a per-instance cache-file path. sing-box
	// 1.14 force-enables its bbolt cache file whenever a
	// platform log writer is present (box.go: needCacheFile),
	// and the default path (cache.db in the working directory)
	// makes concurrent instances — e.g. a client instance next
	// to a server instance in loopback tests — contend on the
	// file lock and time out at startup. Every instance
	// therefore gets its own cache file in a private temp dir.
	cachePath string
	// fragment, when non-nil, is the Step 11 routing/DNS
	// policy compiled by package routecfg. Its route section
	// references this compiler's outbound tags ("out",
	// "direct") by construction.
	fragment *routecfg.Fragment
}

// compileConfig compiles a full client configuration for one node.
// Callers must have run checkSupported + checkCompileInputs first.
func compileConfig(n *specnode.Node, opts compileOptions) ([]byte, error) {
	cfg := map[string]any{
		"log": map[string]any{
			"level":     opts.logLevel,
			"timestamp": true,
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled": true,
				"path":    opts.cachePath,
			},
		},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "in",
				"listen":      opts.listenHost,
				"listen_port": opts.listenPort,
			},
		},
		"route": map[string]any{"final": "out"},
	}

	if opts.fragment != nil {
		opts.fragment.ApplyTo(cfg)
	}

	direct := map[string]any{"type": "direct", "tag": "direct"}

	if n.Protocol == specnode.ProtocolWireGuard {
		ep, err := buildWireGuardEndpoint(n)
		if err != nil {
			return nil, err
		}
		cfg["endpoints"] = []any{ep}
		cfg["outbounds"] = []any{direct}
	} else {
		ob, err := buildOutbound(n)
		if err != nil {
			return nil, err
		}
		cfg["outbounds"] = []any{ob, direct}
	}
	return json.Marshal(cfg)
}

func compileErr(format string, args ...any) error {
	return kernel.NewError(kernel.KindInternal, "Compile",
		fmt.Sprintf(format, args...), nil)
}

func buildOutbound(n *specnode.Node) (map[string]any, error) {
	base := map[string]any{
		"tag":         "out",
		"server":      n.Server,
		"server_port": n.Port,
	}
	var err error
	switch n.Protocol {
	case specnode.ProtocolShadowsocks:
		base["type"] = "shadowsocks"
		base["method"] = n.Shadowsocks.Method
		base["password"] = n.Shadowsocks.Password
		if n.Shadowsocks.Plugin != "" {
			base["plugin"] = n.Shadowsocks.Plugin
			if n.Shadowsocks.PluginOpts != "" {
				base["plugin_opts"] = n.Shadowsocks.PluginOpts
			}
		}
		if !n.UDP {
			base["network"] = "tcp"
		}
	case specnode.ProtocolTrojan:
		base["type"] = "trojan"
		base["password"] = n.Trojan.Password
		err = applyTLSAndTransport(n, base)
	case specnode.ProtocolVMess:
		base["type"] = "vmess"
		base["uuid"] = n.VMess.UUID
		if n.VMess.AlterId != nil {
			base["alter_id"] = *n.VMess.AlterId
		}
		cipher := n.VMess.Cipher
		if cipher == "" {
			cipher = "auto"
		}
		base["security"] = cipher
		err = applyTLSAndTransport(n, base)
	case specnode.ProtocolVLESS:
		base["type"] = "vless"
		base["uuid"] = n.VLESS.UUID
		if n.VLESS.Flow != "" {
			base["flow"] = n.VLESS.Flow
		}
		// VLESS Encryption other than "none" is an evolving
		// upstream feature with no sing-box support; checkSupported
		// lets "none"/"" through and compilation rejects the rest.
		if enc := n.VLESS.Encryption; enc != "" && enc != "none" {
			return nil, kernel.NewError(kernel.KindUnsupported, "Compile",
				"vless encryption "+enc+" is not supported by sing-box", nil)
		}
		err = applyTLSAndTransport(n, base)
	case specnode.ProtocolHysteria2:
		base["type"] = "hysteria2"
		base["password"] = n.Hysteria2.Auth
		if n.Hysteria2.ObfsType != "" {
			base["obfs"] = map[string]any{
				"type":     n.Hysteria2.ObfsType,
				"password": n.Hysteria2.ObfsPassword,
			}
		}
		if ports := convertServerPorts(n.ExtraPorts); len(ports) > 0 {
			base["server_ports"] = ports
		}
		if tls := buildClientTLS(n); tls != nil {
			base["tls"] = tls
		}
	case specnode.ProtocolTUIC:
		base["type"] = "tuic"
		base["uuid"] = n.TUIC.UUID
		base["password"] = n.TUIC.Password
		if n.Transport != nil {
			if n.Transport.CongestionControl != "" {
				base["congestion_control"] = n.Transport.CongestionControl
			}
			if n.Transport.UDPRelayMode != "" {
				base["udp_relay_mode"] = n.Transport.UDPRelayMode
			}
		}
		if tls := buildClientTLS(n); tls != nil {
			base["tls"] = tls
		}
	case specnode.ProtocolSOCKS5:
		base["type"] = "socks"
		base["version"] = "5"
		if n.UserPass != nil && n.UserPass.Username != "" {
			base["username"] = n.UserPass.Username
			base["password"] = n.UserPass.Password
		}
	case specnode.ProtocolHTTP:
		base["type"] = "http"
		if n.UserPass != nil && n.UserPass.Username != "" {
			base["username"] = n.UserPass.Username
			base["password"] = n.UserPass.Password
		}
		if tls := buildClientTLS(n); tls != nil {
			base["tls"] = tls
		}
	default:
		return nil, compileErr("no outbound builder for protocol %s", n.Protocol)
	}
	if err != nil {
		return nil, err
	}
	return base, nil
}

func buildWireGuardEndpoint(n *specnode.Node) (map[string]any, error) {
	c := n.WireGuard
	allowed := c.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	peer := map[string]any{
		"address":     n.Server,
		"port":        n.Port,
		"public_key":  c.PeerPublicKey,
		"allowed_ips": allowed,
	}
	if c.PreSharedKey != "" {
		peer["pre_shared_key"] = c.PreSharedKey
	}
	if c.PersistentKeepalive > 0 {
		peer["persistent_keepalive_interval"] = c.PersistentKeepalive
	}
	if len(c.Reserved) == 3 {
		peer["reserved"] = c.Reserved
	}
	ep := map[string]any{
		"type":        "wireguard",
		"tag":         "out",
		"address":     c.Addresses,
		"private_key": c.PrivateKey,
		"peers":       []any{peer},
	}
	if c.MTU > 0 {
		ep["mtu"] = c.MTU
	}
	return ep, nil
}

// applyTLSAndTransport attaches the tls block (when the security
// layer calls for one) and the v2ray transport block.
func applyTLSAndTransport(n *specnode.Node, ob map[string]any) error {
	if tls := buildClientTLS(n); tls != nil {
		ob["tls"] = tls
	}
	tr, err := buildTransport(n)
	if err != nil {
		return err
	}
	if tr != nil {
		ob["transport"] = tr
	}
	return nil
}

// buildClientTLS renders the sing-box outbound TLS block from the
// unified Security object; nil when the layer is "none".
func buildClientTLS(n *specnode.Node) map[string]any {
	st := n.SecurityType()
	if st == "none" {
		return nil
	}
	sec := n.Security
	tls := map[string]any{"enabled": true}
	if sec.ServerName != "" {
		tls["server_name"] = sec.ServerName
	}
	if sec.AllowInsecure {
		tls["insecure"] = true
	}
	if len(sec.ALPN) > 0 {
		tls["alpn"] = sec.ALPN
	}
	if sec.CertificatePinSHA256 != "" {
		// sing-box expects the pin as base64 SHA-256 of the
		// certificate public key — the same representation the
		// unified model carries (Hysteria2 pinSHA256 lineage).
		tls["certificate_public_key_sha256"] = []string{sec.CertificatePinSHA256}
	}
	fp := sec.Fingerprint
	if st == "reality" {
		if fp == "" {
			fp = "chrome" // Reality requires a uTLS fingerprint; chrome is the ecosystem default
		}
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": sec.PublicKey,
			"short_id":   sec.ShortID,
		}
	}
	if fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	// Note: Security.SpiderX has no sing-box counterpart (it is an
	// Xray client behaviour); it is accepted by the model and
	// intentionally not compiled.
	return tls
}

// buildTransport renders the sing-box v2ray transport block; nil
// for the native/raw transport.
func buildTransport(n *specnode.Node) (map[string]any, error) {
	t := n.Transport
	tt := n.TransportType()
	// TCP-family header camouflage (vmess/vless link param
	// type=http) is expressed in the unified model as
	// transport.headerType, not as the "http" transport.
	if (tt == "raw" || tt == "tcp") && t != nil && t.HeaderType == "http" {
		tr := map[string]any{"type": "http"}
		if t.Path != "" {
			tr["path"] = t.Path
		}
		if t.Host != "" {
			tr["host"] = []string{t.Host}
		}
		return tr, nil
	}
	switch tt {
	case "raw", "tcp":
		return nil, nil
	case "ws":
		tr := map[string]any{"type": "ws"}
		if t.Path != "" {
			tr["path"] = t.Path
		}
		headers := map[string]string{}
		for k, v := range t.Headers {
			headers[k] = v
		}
		if t.Host != "" {
			if _, ok := headers["Host"]; !ok {
				headers["Host"] = t.Host
			}
		}
		if len(headers) > 0 {
			tr["headers"] = headers
		}
		return tr, nil
	case "http":
		tr := map[string]any{"type": "http"}
		if t.Host != "" {
			tr["host"] = []string{t.Host}
		}
		if t.Path != "" {
			tr["path"] = t.Path
		}
		if len(t.Headers) > 0 {
			tr["headers"] = t.Headers
		}
		return tr, nil
	case "httpupgrade":
		tr := map[string]any{"type": "httpupgrade"}
		if t.Host != "" {
			tr["host"] = t.Host
		}
		if t.Path != "" {
			tr["path"] = t.Path
		}
		return tr, nil
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if t.ServiceName != "" {
			tr["service_name"] = t.ServiceName
		}
		// The unified model's grpcMode (gun/multi) has no sing-box
		// counterpart; sing-box's gRPC transport behaviour is
		// fixed. Accepted and not compiled (documented).
		return tr, nil
	}
	return nil, kernel.NewError(kernel.KindUnsupported, "Compile",
		fmt.Sprintf("transport %s cannot be compiled by sing-box", tt), nil)
}

// convertServerPorts converts unified-model port entries
// ("20000-30000", "8443") to sing-box server_ports form
// ("20000:30000", "8443").
func convertServerPorts(extra []string) []string {
	out := make([]string, 0, len(extra))
	for _, p := range extra {
		out = append(out, strings.Replace(p, "-", ":", 1))
	}
	return out
}
