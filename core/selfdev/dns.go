package selfdev

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"openproxy/core/kernel"
	"openproxy/core/routecfg"
	"openproxy/core/selfdev/shadowsocks"
)

// The forwarding plane's resolver: Step 11's two resolution
// paths, reproduced for the self-developed data plane.
//
//   - Names the policy sends direct are resolved LOCALLY (the
//     system resolver, or the policy's explicit local server).
//     Only mirrored pure-domain direct rules ever cause this
//     (policyEval.dnsRoute).
//   - Every other name the plane must resolve itself (for an
//     IP-dependent routing decision or a direct dial after
//     remote resolution) is resolved through the REMOTE server
//     TRANSPORTED THROUGH THE TUNNEL: the query leaves via the
//     Shadowsocks node, exactly like the sing-box fragment's
//     detour: out on its remote server. A remote query that
//     bypassed the tunnel would itself be the leak Step 11
//     exists to prevent.
//   - Names the connection carries to the egress (the proxy
//     path) are not resolved by the plane at all unless a
//     routing decision needs the IP (see forward.go's target
//     routing); the tunnel carries the NAME.
//
// DNS strategy follows the IPv6 posture: "off" -> ipv4_only
// (no AAAA queries, v6 answers dropped); otherwise prefer_ipv4
// (both families queried, v4 answers preferred).
//
// Deliberate divergences from the sing-box plane, recorded in
// the phase-2 run record: no DNS response cache (extra queries,
// no semantic difference), and no fake-ip serving (a TUN-mode
// surface; in manual mode sing-box itself resolves for real at
// connect time through the remote server, which is what this
// resolver does).

type dnsResolver struct {
	eval *policyEval

	// Tunnel transports, supplied by the plane.
	dialTunnelTCP func(ctx context.Context, target shadowsocks.Addr) (net.Conn, error)
	openTunnelUDP func(ctx context.Context) (*shadowsocks.PacketConn, error)

	udpMu sync.Mutex // guards udpPC creation/close
	pcMu  sync.Mutex // serializes whole exchanges on the shared DNS PacketConn: a reader that drops a mismatched-ID datagram would eat another exchange's answer
	udpPC *shadowsocks.PacketConn
}

func (r *dnsResolver) close() {
	r.udpMu.Lock()
	defer r.udpMu.Unlock()
	if r.udpPC != nil {
		_ = r.udpPC.Close()
		r.udpPC = nil
	}
}

// resolve returns the addresses for host under the policy's
// DNS rules, in preference order. A policy-rejected name
// returns errDNSRejected; callers map it to a block decision.
var errDNSRejected = fmt.Errorf("dns: name rejected by a mirrored block rule")

func (r *dnsResolver) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	class := dnsRemote
	if r.eval != nil {
		class = r.eval.dnsRoute(host)
	}
	switch class {
	case dnsReject:
		return nil, errDNSRejected
	case dnsLocal:
		return r.resolveLocal(ctx, host)
	default:
		return r.resolveRemote(ctx, host)
	}
}

// applyStrategy filters/orders addresses per the IPv6 posture.
func (r *dnsResolver) applyStrategy(addrs []netip.Addr) []netip.Addr {
	v6off := r.eval != nil && r.eval.ipv6 == routecfg.IPv6Off
	out := make([]netip.Addr, 0, len(addrs))
	var v6 []netip.Addr
	for _, a := range addrs {
		if isV6(a) {
			if v6off {
				continue
			}
			v6 = append(v6, a)
			continue
		}
		out = append(out, a)
	}
	// prefer_ipv4: v4 answers first, v6 after (never dropped
	// unless the posture is off, handled above).
	return append(out, v6...)
}

func (r *dnsResolver) resolveLocal(ctx context.Context, host string) ([]netip.Addr, error) {
	spec := r.eval.dns.Local
	if spec.Type == "local" {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, kernel.NewError(kernel.KindNetwork, "selfdev.dns",
				"local resolution failed", err)
		}
		out := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if a, ok := netipxFromIP(ip); ok {
				out = append(out, a)
			}
		}
		return r.finish(host, out)
	}
	// Explicit local server: plain UDP/TCP, reached directly.
	port := spec.Port
	if port == 0 {
		port = 53
	}
	server := shadowsocks.Addr{Host: spec.Server, Port: port}
	exchange := func(ctx context.Context, wire []byte, id uint16) ([]byte, error) {
		if spec.Type == "tcp" {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.String())
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			return tcpExchange(ctx, conn, wire)
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", server.String())
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return udpConnExchange(ctx, conn, wire, id)
	}
	return r.queryAll(ctx, host, exchange)
}

func (r *dnsResolver) resolveRemote(ctx context.Context, host string) ([]netip.Addr, error) {
	spec := r.eval.dns.Remote
	port := spec.Port
	if port == 0 {
		switch spec.Type {
		case "tls":
			port = 853
		case "https":
			port = 443
		default:
			port = 53
		}
	}
	server := shadowsocks.Addr{Host: spec.Server, Port: port}
	var exchange func(ctx context.Context, wire []byte, id uint16) ([]byte, error)
	switch spec.Type {
	case "udp":
		exchange = func(ctx context.Context, wire []byte, id uint16) ([]byte, error) {
			r.pcMu.Lock()
			defer r.pcMu.Unlock()
			pc, err := r.tunnelUDP(ctx)
			if err != nil {
				return nil, err
			}
			return packetExchange(ctx, pc, server, wire, id)
		}
	case "tcp", "tls":
		exchange = func(ctx context.Context, wire []byte, id uint16) ([]byte, error) {
			conn, err := r.dialTunnelTCP(ctx, server)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			if spec.Type == "tls" {
				tconn, err := tlsHandshake(ctx, conn, tlsServerName(spec))
				if err != nil {
					return nil, err
				}
				conn = tconn
			}
			return tcpExchange(ctx, conn, wire)
		}
	case "https":
		exchange = func(ctx context.Context, wire []byte, id uint16) ([]byte, error) {
			return r.dohExchange(ctx, spec, server, wire)
		}
	default:
		return nil, kernel.NewError(kernel.KindInvalidConfig, "selfdev.dns",
			"unknown remote DNS server type "+spec.Type, nil)
	}
	return r.queryAll(ctx, host, exchange)
}

func tlsServerName(spec routecfg.DNSServerSpec) string {
	if spec.ServerName != "" {
		return spec.ServerName
	}
	return spec.Server
}

// tunnelUDP returns the shared PacketConn used for DNS over the
// tunnel, opening it on first use.
func (r *dnsResolver) tunnelUDP(ctx context.Context) (*shadowsocks.PacketConn, error) {
	r.udpMu.Lock()
	defer r.udpMu.Unlock()
	if r.udpPC != nil {
		return r.udpPC, nil
	}
	pc, err := r.openTunnelUDP(ctx)
	if err != nil {
		return nil, err
	}
	r.udpPC = pc
	return pc, nil
}

// queryAll runs the A and AAAA queries for host through
// exchange and merges the answers.
func (r *dnsResolver) queryAll(ctx context.Context, host string,
	exchange func(ctx context.Context, wire []byte, id uint16) ([]byte, error)) ([]netip.Addr, error) {
	v6off := r.eval != nil && r.eval.ipv6 == routecfg.IPv6Off
	qtypes := []uint16{mdns.TypeA}
	if !v6off {
		qtypes = append(qtypes, mdns.TypeAAAA)
	}
	var out []netip.Addr
	var firstErr error
	for _, qt := range qtypes {
		addrs, err := r.queryOne(ctx, host, qt, exchange, 0)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("no addresses for %s", host)
		}
		return nil, kernel.NewError(kernel.KindNetwork, "selfdev.dns",
			"remote resolution failed", firstErr)
	}
	return r.finish(host, out)
}

func (r *dnsResolver) finish(host string, addrs []netip.Addr) ([]netip.Addr, error) {
	addrs = r.applyStrategy(addrs)
	if len(addrs) == 0 {
		return nil, kernel.NewError(kernel.KindNetwork, "selfdev.dns",
			"no usable addresses for "+host+" under the policy's IPv6 posture", nil)
	}
	return addrs, nil
}

// queryOne performs one qtype query, following a bare CNAME
// answer once (depth guard).
func (r *dnsResolver) queryOne(ctx context.Context, name string, qtype uint16,
	exchange func(ctx context.Context, wire []byte, id uint16) ([]byte, error), depth int) ([]netip.Addr, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	respWire, err := exchange(ctx, wire, msg.Id)
	if err != nil {
		return nil, err
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(respWire); err != nil {
		return nil, err
	}
	var out []netip.Addr
	var cname string
	for _, rr := range resp.Answer {
		switch rec := rr.(type) {
		case *mdns.A:
			if a, ok := netipxFromIP(rec.A); ok {
				out = append(out, a)
			}
		case *mdns.AAAA:
			if a, ok := netipxFromIP(rec.AAAA); ok {
				out = append(out, a)
			}
		case *mdns.CNAME:
			cname = rec.Target
		}
	}
	if len(out) == 0 && cname != "" && depth == 0 {
		return r.queryOne(ctx, cname, qtype, exchange, depth+1)
	}
	return out, nil
}

// --- wire exchanges -------------------------------------------------

func setConnDeadline(ctx context.Context, conn net.Conn) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
}

// tcpExchange speaks RFC 7766 length-prefixed DNS over conn.
func tcpExchange(ctx context.Context, conn net.Conn, wire []byte) ([]byte, error) {
	setConnDeadline(ctx, conn)
	var lb [2]byte
	lb[0] = byte(len(wire) >> 8)
	lb[1] = byte(len(wire))
	if _, err := conn.Write(append(lb[:], wire...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	n := int(lb[0])<<8 | int(lb[1])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// udpConnExchange speaks plain UDP DNS over a connected socket.
func udpConnExchange(ctx context.Context, conn net.Conn, wire []byte, id uint16) ([]byte, error) {
	setConnDeadline(ctx, conn)
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && uint16(buf[0])<<8|uint16(buf[1]) == id {
			return buf[:n], nil
		}
	}
}

// packetExchange speaks UDP DNS through the Shadowsocks packet
// session: the query rides the tunnel as one datagram to the
// DNS server, the answer comes back the same way.
func packetExchange(ctx context.Context, pc *shadowsocks.PacketConn, server shadowsocks.Addr, wire []byte, id uint16) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(dl)
	} else {
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if _, err := pc.WriteTo(wire, server); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && uint16(buf[0])<<8|uint16(buf[1]) == id {
			return buf[:n], nil
		}
	}
}

// dohExchange performs an RFC 8484 POST through the tunnel.
func (r *dnsResolver) dohExchange(ctx context.Context, spec routecfg.DNSServerSpec, server shadowsocks.Addr, wire []byte) ([]byte, error) {
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := r.dialTunnelTCP(ctx, server)
			if err != nil {
				return nil, err
			}
			return tlsHandshake(ctx, conn, tlsServerName(spec))
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	path := spec.Path
	if path == "" {
		path = "/dns-query"
	}
	url := "https://" + server.String() + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: server answered %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

// tlsHandshake wraps conn in TLS and completes the handshake
// under ctx.
func tlsHandshake(ctx context.Context, conn net.Conn, serverName string) (net.Conn, error) {
	tconn := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tconn, nil
}

func netipxFromIP(ip net.IP) (netip.Addr, bool) {
	a, ok := netipxFromSlice(ip)
	return a, ok
}

func netipxFromSlice(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4)), true
	}
	v16 := ip.To16()
	if v16 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16([16]byte(v16)), true
}
