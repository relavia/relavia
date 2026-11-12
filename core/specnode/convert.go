package specnode

import (
	"openproxy/core/kernel"
)

// Conversions between the unified model (this package) and the
// Step 6 placeholder model in package kernel. The kernel.Adapter
// interface is typed on the placeholder, so these conversions are
// the docking surface defined by core/README (Step 5 docking
// points). Compilation of real kernel configurations always uses
// THIS package's model; the conversions exist for interface
// interop and capability coordination only.
//
// Projection table (spec -> kernel coordinates), used by
// ProjectKernel for kernel.ValidateAgainst / Capabilities greying:
//
//	protocol        same name in both models
//	transport raw   -> native for shadowsocks/wireguard/openvpn/
//	                   socks5/http (their kernel rows key on native),
//	                   tcp for trojan/vmess/vless (raw = plain TCP)
//	transport tcp   -> tcp;  ws -> ws;  grpc -> grpc;  quic -> quic
//	transport http  -> http2 (kernel has no plain-HTTP transport
//	                   coordinate; http2 is the closest cell and the
//	                   compiler still compiles real HTTP transport)
//	transport httpupgrade -> ws (closest kernel cell; see above)
//	transport xhttp -> http2 (closest kernel cell; see above)
//	transport kcp   -> udp (mKCP runs over UDP; no kernel cell)
//	security none   -> aead for shadowsocks/vmess (their native
//	                   crypto IS the security layer in the kernel
//	                   matrix), none otherwise
//	security tls    -> tls;  reality -> reality
//
// Lossy in projection (fields with no placeholder home): WireGuard
// keys/addresses/allowedIPs, OpenVPN config bodies, SS plugin,
// Hysteria2 obfs, TUIC congestion/udp-relay modes, gRPC serviceName,
// header maps, ALPN, certificate pins, extra ports. A projected node
// therefore validates structurally, but a real adapter MUST compile
// from the spec node, not from its projection.

// ProjectKernel maps this spec node onto the placeholder kernel
// model for interface-level validation and capability checks.
func (n *Node) ProjectKernel() *kernel.Node {
	kn := &kernel.Node{
		ID:       n.ID,
		Name:     n.Name,
		Protocol: kernel.Protocol(n.Protocol),
		Server:   n.Server,
		Port:     n.Port,
		UDP:      n.UDP,
		Group:    n.Group,
		Source: kernel.Source{
			Kind:          n.Source.Kind,
			Ref:           n.Source.Ref,
			Authorization: n.Source.Authorization,
		},
	}
	kn.Transport.Type = projectTransport(n)
	kn.Security.Type = projectSecurity(n)
	if n.Security != nil {
		kn.Security.ServerName = n.Security.ServerName
		kn.Security.PublicKey = n.Security.PublicKey
		kn.Security.ShortID = n.Security.ShortID
		kn.Security.Fingerprint = n.Security.Fingerprint
	}
	if n.Transport != nil {
		kn.Transport.Path = n.Transport.Path
		kn.Transport.Host = n.Transport.Host
	}
	switch {
	case n.Shadowsocks != nil:
		kn.Credential.Method = n.Shadowsocks.Method
		kn.Credential.Password = n.Shadowsocks.Password
	case n.Trojan != nil:
		kn.Credential.Password = n.Trojan.Password
	case n.VMess != nil:
		kn.Credential.UUID = n.VMess.UUID
	case n.VLESS != nil:
		kn.Credential.UUID = n.VLESS.UUID
		kn.Credential.Flow = n.VLESS.Flow
	case n.Hysteria2 != nil:
		kn.Credential.Password = n.Hysteria2.Auth
	case n.TUIC != nil:
		kn.Credential.UUID = n.TUIC.UUID
		kn.Credential.Password = n.TUIC.Password
	case n.UserPass != nil:
		// The placeholder Credential has no username field; the
		// password alone is projected (documented lossy point).
		kn.Credential.Password = n.UserPass.Password
	case n.OpenVPN != nil:
		kn.Credential.Password = n.OpenVPN.Password
	}
	return kn
}

func projectTransport(n *Node) kernel.TransportType {
	tt := n.TransportType()
	switch tt {
	case "raw":
		switch n.Protocol {
		case ProtocolShadowsocks, ProtocolWireGuard, ProtocolOpenVPN,
			ProtocolSOCKS5, ProtocolHTTP:
			return kernel.TransportNative
		default:
			return kernel.TransportTCP
		}
	case "tcp":
		return kernel.TransportTCP
	case "ws":
		return kernel.TransportWS
	case "http":
		return kernel.TransportHTTP2
	case "httpupgrade":
		return kernel.TransportWS
	case "grpc":
		return kernel.TransportGRPC
	case "xhttp":
		return kernel.TransportHTTP2
	case "kcp":
		return kernel.TransportUDP
	case "quic":
		return kernel.TransportQUIC
	}
	return kernel.TransportType(tt)
}

func projectSecurity(n *Node) kernel.SecurityType {
	st := n.SecurityType()
	switch st {
	case "none":
		switch n.Protocol {
		case ProtocolShadowsocks, ProtocolVMess:
			return kernel.SecurityAEAD
		}
		return kernel.SecurityNone
	case "tls":
		return kernel.SecurityTLS
	case "reality":
		return kernel.SecurityReality
	}
	return kernel.SecurityType(st)
}

// FromKernel converts a placeholder kernel node into a spec node.
// It is the entry point for callers that only hold the placeholder
// (the kernel.Adapter interface methods). Fields the placeholder
// cannot carry stay unset; protocols whose required data lives in
// those fields (WireGuard keys, OpenVPN bodies) produce a node that
// fails spec validation with a precise message instead of compiling
// into a wrong configuration.
func FromKernel(kn *kernel.Node) *Node {
	if kn == nil {
		return nil
	}
	n := &Node{
		SchemaVersion: "1.0",
		ID:            kn.ID,
		Name:          kn.Name,
		Protocol:      string(kn.Protocol),
		Server:        kn.Server,
		Port:          kn.Port,
		UDP:           kn.UDP,
		Group:         kn.Group,
		Source: SourceRef{
			Kind:          kn.Source.Kind,
			Ref:           kn.Source.Ref,
			Authorization: kn.Source.Authorization,
		},
	}
	n.Transport = fromKernelTransport(kn)
	n.Security = fromKernelSecurity(kn)
	cred := kn.Credential
	switch kn.Protocol {
	case kernel.ProtocolShadowsocks:
		n.Shadowsocks = &CredShadowsocks{Method: cred.Method, Password: cred.Password}
	case kernel.ProtocolTrojan:
		n.Trojan = &CredTrojan{Password: cred.Password}
	case kernel.ProtocolVMess:
		n.VMess = &CredVMess{UUID: cred.UUID, Cipher: "auto"}
	case kernel.ProtocolVLESS:
		n.VLESS = &CredVLESS{UUID: cred.UUID, Flow: cred.Flow}
	case kernel.ProtocolHysteria2:
		n.Hysteria2 = &CredHysteria2{Auth: cred.Password}
	case kernel.ProtocolTUIC:
		n.TUIC = &CredTUIC{UUID: cred.UUID, Password: cred.Password}
	case kernel.ProtocolWireGuard:
		// Keys cannot be carried by the placeholder; leave the
		// credential empty so validation names the gap.
		n.WireGuard = &CredWireGuard{}
	case kernel.ProtocolOpenVPN:
		n.OpenVPN = &CredOpenVPN{Password: cred.Password}
	case kernel.ProtocolSOCKS5, kernel.ProtocolHTTP:
		n.UserPass = &CredUserPass{Password: cred.Password}
	}
	return n
}

func fromKernelTransport(kn *kernel.Node) *Transport {
	t := &Transport{}
	switch kn.Transport.Type {
	case kernel.TransportNative:
		t.Type = "raw"
	case kernel.TransportTCP:
		t.Type = "tcp"
	case kernel.TransportWS:
		t.Type = "ws"
	case kernel.TransportHTTP2:
		t.Type = "http"
	case kernel.TransportGRPC:
		t.Type = "grpc"
	case kernel.TransportQUIC:
		t.Type = "quic"
	case kernel.TransportUDP:
		t.Type = "raw"
	default:
		t.Type = string(kn.Transport.Type)
	}
	t.Path = kn.Transport.Path
	t.Host = kn.Transport.Host
	if t.Type == "" && t.Path == "" && t.Host == "" {
		return nil
	}
	return t
}

func fromKernelSecurity(kn *kernel.Node) *Security {
	sec := kn.Security
	s := &Security{
		ServerName:  sec.ServerName,
		PublicKey:   sec.PublicKey,
		ShortID:     sec.ShortID,
		Fingerprint: sec.Fingerprint,
	}
	switch sec.Type {
	case kernel.SecurityNone:
		s.Type = "none"
	case kernel.SecurityTLS:
		s.Type = "tls"
	case kernel.SecurityReality:
		s.Type = "reality"
	case kernel.SecurityAEAD:
		// Protocol-native crypto: no separate security layer.
		return nil
	case kernel.SecurityXTLSVision:
		// Vision is a flow, not a layer, in the spec model; the
		// flow itself travels in the credential. The layer is TLS
		// (or Reality when a public key is present).
		if sec.PublicKey != "" {
			s.Type = "reality"
		} else {
			s.Type = "tls"
		}
	default:
		s.Type = string(sec.Type)
	}
	return s
}
