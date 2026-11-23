package selfdev

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/routecfg"
	"openproxy/core/selfdev/shadowsocks"
	"openproxy/core/specnode"
)

// The self-developed forwarding plane (spec section 3.2, phase
// 2): a loopback mixed inbound (SOCKS5 + HTTP, the same surface
// as the sing-box adapter's mixed inbound) whose sessions are
// served by the self-developed Shadowsocks engine under the
// Step 11 routing/DNS policy and the Step 12 kill-switch gate
// (both enforced by the composite adapter around this plane;
// the routing/DNS decisions themselves live in policy.go and
// dns.go).
//
// The plane serves ONE node (the composite's Start contract is
// one active node per adapter). Non-Shadowsocks nodes and
// Shadowsocks nodes the policy routes away never reach it.

// socks reply codes used by the plane (RFC 1928). The mapping
// from failure causes mirrors the control implementation's
// observable behaviour and is exercised by the differential rig.
const (
	socksRepSuccess            = 0
	socksRepGeneralFailure     = 1
	socksRepNotAllowed         = 2
	socksRepNetworkUnreachable = 3
	socksRepHostUnreachable    = 4
	socksRepRefused            = 5
	socksRepCommandUnsupported = 7
)

type plane struct {
	client     *shadowsocks.Client
	node       *specnode.Node
	serverAddr string
	eval       *policyEval
	dns        *dnsResolver
	logf       func(format string, args ...any)

	host string
	port int

	tcpLn net.Listener
	udpLn *net.UDPConn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	startedAt time.Time
	up        atomic.Uint64 // payload bytes, client -> target
	down      atomic.Uint64 // payload bytes, target -> client

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}

	udpMu     sync.Mutex
	udpAssocs map[string]*udpAssoc
}

func newPlane(client *shadowsocks.Client, node *specnode.Node, eval *policyEval,
	logf func(format string, args ...any), listenHost string, listenPort int) *plane {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	p := &plane{
		client:     client,
		node:       node,
		serverAddr: net.JoinHostPort(node.Server, strconv.Itoa(node.Port)),
		eval:       eval,
		logf:       logf,
		host:       listenHost,
		port:       listenPort,
		conns:      map[net.Conn]struct{}{},
		udpAssocs:  map[string]*udpAssoc{},
	}
	p.dns = &dnsResolver{
		eval: eval,
		dialTunnelTCP: func(ctx context.Context, target shadowsocks.Addr) (net.Conn, error) {
			return client.DialTCP(ctx, p.serverAddr, target)
		},
		openTunnelUDP: func(ctx context.Context) (*shadowsocks.PacketConn, error) {
			return client.DialUDP(ctx, p.serverAddr)
		},
	}
	return p
}

// start binds the TCP and UDP listeners on the same loopback
// port (a mixed inbound serves both from one port).
func (p *plane) start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	for attempt := 0; attempt < 8; attempt++ {
		tcpLn, err := (&net.ListenConfig{}).Listen(p.ctx, "tcp", net.JoinHostPort(p.host, strconv.Itoa(p.port)))
		if err != nil {
			return kernel.NewError(kernel.KindNetwork, "selfdev.Start", "bind forwarding plane TCP listener", err)
		}
		port := tcpLn.Addr().(*net.TCPAddr).Port
		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.host, strconv.Itoa(port)))
		if err != nil {
			_ = tcpLn.Close()
			return kernel.NewError(kernel.KindInternal, "selfdev.Start", "resolve plane UDP address", err)
		}
		udpLn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			_ = tcpLn.Close()
			if p.port != 0 {
				return kernel.NewError(kernel.KindNetwork, "selfdev.Start", "bind forwarding plane UDP listener", err)
			}
			continue // allocated TCP port's UDP twin is taken; retry with a fresh pair
		}
		p.tcpLn, p.udpLn, p.port = tcpLn, udpLn, port
		p.startedAt = time.Now()
		p.wg.Add(3)
		go p.acceptLoop()
		go p.udpLoop()
		go p.sweeper()
		return nil
	}
	return kernel.NewError(kernel.KindNetwork, "selfdev.Start", "no free loopback port pair for the forwarding plane", nil)
}

func (p *plane) addr() string {
	if p.tcpLn == nil {
		return ""
	}
	return net.JoinHostPort(p.host, strconv.Itoa(p.port))
}

func (p *plane) totals() (up, down uint64) { return p.up.Load(), p.down.Load() }

// close tears the plane down: listeners, associations, the DNS
// session and every tracked connection.
func (p *plane) close() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.tcpLn != nil {
		_ = p.tcpLn.Close()
	}
	if p.udpLn != nil {
		_ = p.udpLn.Close()
	}
	p.udpMu.Lock()
	for _, a := range p.udpAssocs {
		a.close()
	}
	p.udpAssocs = map[string]*udpAssoc{}
	p.udpMu.Unlock()
	p.connsMu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.connsMu.Unlock()
	p.dns.close()
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.logf("selfdev: forwarding plane close timed out waiting for sessions")
	}
}

func (p *plane) track(c net.Conn) {
	p.connsMu.Lock()
	p.conns[c] = struct{}{}
	p.connsMu.Unlock()
}

func (p *plane) untrack(c net.Conn) {
	p.connsMu.Lock()
	delete(p.conns, c)
	p.connsMu.Unlock()
}

// --- TCP ------------------------------------------------------------

func (p *plane) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.tcpLn.Accept()
		if err != nil {
			return // listener closed
		}
		p.track(conn)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(conn)
			defer conn.Close()
			p.handleTCP(conn)
		}()
	}
}

// bufferedConn lets protocol parsing consume from a bufio.Reader
// without losing bytes it buffered past the headers.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.br.Read(b) }

func (p *plane) handleTCP(conn net.Conn) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	bc := &bufferedConn{Conn: conn, br: br}
	if first[0] == 0x05 {
		p.handleSOCKS(bc, br)
		return
	}
	p.handleHTTP(bc, br)
}

// routeTarget decides what happens to one connection target
// under the Step 11 policy. It returns the action and, for
// direct connections, the resolved IP to dial (nil for the
// proxy action: proxied names are carried to the egress
// unresolved, so nothing leaks locally).
func (p *plane) routeTarget(ctx context.Context, target shadowsocks.Addr) (routecfg.Action, *netip.Addr, error) {
	host := target.Host
	if ip, err := netip.ParseAddr(host); err == nil {
		action := p.eval.decide("", &ip, target.Port)
		if action == routecfg.ActionDirect {
			return action, &ip, nil
		}
		return action, nil, nil
	}
	// Name target.
	if p.eval == nil || !p.eval.needsIPPhase {
		action := p.eval.decide(host, nil, target.Port)
		if action != routecfg.ActionDirect {
			return action, nil, nil
		}
		// Direct by a name-phase rule: resolve under the DNS
		// mirror (local for mirrored direct rules, remote for
		// rules the mirror does not cover) and dial the address.
		ips, err := p.dns.resolve(ctx, host)
		if err != nil {
			return routecfg.ActionDirect, nil, err
		}
		return routecfg.ActionDirect, &ips[0], nil
	}
	// Decisions may depend on the resolved IP: resolve first
	// (the DNS mirror picks the resolver; a mirrored block
	// rejects the name outright), then decide with the address
	// in hand - the same resolve-then-route shape sing-box
	// takes.
	ips, err := p.dns.resolve(ctx, host)
	if err != nil {
		if errors.Is(err, errDNSRejected) {
			return routecfg.ActionBlock, nil, nil
		}
		return routecfg.ActionProxy, nil, err
	}
	action := p.eval.decide(host, &ips[0], target.Port)
	if action == routecfg.ActionDirect {
		return action, &ips[0], nil
	}
	return action, nil, nil
}

// dialTarget establishes the outbound side for a routed target.
func (p *plane) dialTarget(ctx context.Context, target shadowsocks.Addr) (net.Conn, int, error) {
	action, directIP, err := p.routeTarget(ctx, target)
	if err != nil {
		return nil, socksRepGeneralFailure, err
	}
	switch action {
	case routecfg.ActionBlock:
		p.logf("selfdev: plane blocked %s by routing policy", target)
		return nil, socksRepNotAllowed, fmt.Errorf("target blocked by routing policy")
	case routecfg.ActionDirect:
		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(directIP.String(), strconv.Itoa(target.Port)))
		if err != nil {
			return nil, socksRepFor(err), err
		}
		return conn, socksRepSuccess, nil
	default: // proxy through the self-developed engine; the NAME is carried to the egress
		conn, err := p.client.DialTCP(ctx, p.serverAddr, target)
		if err != nil {
			return nil, socksRepFor(err), err
		}
		return conn, socksRepSuccess, nil
	}
}

// socksRepFor maps a dial failure to a SOCKS reply code.
func socksRepFor(err error) int {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return socksRepRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return socksRepHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return socksRepNetworkUnreachable
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return socksRepHostUnreachable
	}
	return socksRepGeneralFailure
}

// relay copies both directions with half-close propagation: when
// one direction ends, the peer's write side is closed (when it
// supports it) so protocols that signal end-of-request with a
// write-side EOF still get their full response.
func (p *plane) relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyDir := func(dst, src net.Conn, counter *atomic.Uint64) {
		defer wg.Done()
		copyCount(dst, src, counter)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go copyDir(b, a, &p.up)
	go copyDir(a, b, &p.down)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// relayBufPool recycles relay copy buffers. 64 KiB keeps the
// engine's chunk writer fed in cap-sized pieces (four chunks
// per write) instead of the 32 KiB io.Copy default.
var relayBufPool = sync.Pool{New: func() any {
	b := make([]byte, 64*1024)
	return &b
}}

// copyCount is a counting copy loop: same shape as io.Copy but
// with pooled buffers and the byte counter inline (a writer
// wrapper would defeat buffer reuse and fast paths).
func copyCount(dst io.Writer, src io.Reader, counter *atomic.Uint64) {
	bp := relayBufPool.Get().(*[]byte)
	buf := *bp
	defer relayBufPool.Put(bp)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				counter.Add(uint64(nw))
			}
			if ew != nil || nw != nr {
				return
			}
		}
		if er != nil {
			return
		}
	}
}

// --- SOCKS5 -----------------------------------------------------------

func (p *plane) handleSOCKS(conn *bufferedConn, br *bufio.Reader) {
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	target, err := readSocksAddr(br, req[3])
	if err != nil {
		_ = p.socksReply(conn, socksRepGeneralFailure)
		return
	}
	switch req[1] {
	case 0x01: // CONNECT
		out, rep, err := p.dialTarget(p.ctx, target)
		if err != nil {
			_ = p.socksReply(conn, rep)
			return
		}
		p.track(out)
		defer p.untrack(out)
		if err := p.socksReply(conn, socksRepSuccess); err != nil {
			_ = out.Close()
			return
		}
		p.relay(conn, out)
	case 0x03: // UDP ASSOCIATE
		if err := p.socksReplyAddr(conn, socksRepSuccess, p.udpLn.LocalAddr().(*net.UDPAddr)); err != nil {
			return
		}
		// The association lives until the control connection
		// closes (RFC 1928); associations themselves are keyed
		// by UDP source and expire by idle timeout.
		_, _ = io.Copy(io.Discard, br)
	default:
		_ = p.socksReply(conn, socksRepCommandUnsupported)
	}
}

func readSocksAddr(br *bufio.Reader, atyp byte) (shadowsocks.Addr, error) {
	switch atyp {
	case 0x01:
		var b [4 + 2]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return shadowsocks.Addr{}, err
		}
		return shadowsocks.Addr{Host: net.IP(b[:4]).String(), Port: int(binary.BigEndian.Uint16(b[4:]))}, nil
	case 0x04:
		var b [16 + 2]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return shadowsocks.Addr{}, err
		}
		return shadowsocks.Addr{Host: net.IP(b[:16]).String(), Port: int(binary.BigEndian.Uint16(b[16:]))}, nil
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(br, lb[:]); err != nil {
			return shadowsocks.Addr{}, err
		}
		b := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return shadowsocks.Addr{}, err
		}
		return shadowsocks.Addr{Host: string(b[:len(b)-2]), Port: int(binary.BigEndian.Uint16(b[len(b)-2:]))}, nil
	}
	return shadowsocks.Addr{}, fmt.Errorf("unknown socks address type 0x%02x", atyp)
}

func (p *plane) socksReply(conn net.Conn, rep int) error {
	return p.socksReplyAddr(conn, rep, nil)
}

func (p *plane) socksReplyAddr(conn net.Conn, rep int, addr *net.UDPAddr) error {
	out := []byte{0x05, byte(rep), 0x00}
	if addr != nil && addr.IP != nil && addr.IP.To4() != nil {
		out = append(out, 0x01)
		out = append(out, addr.IP.To4()...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], uint16(addr.Port))
		out = append(out, pb[:]...)
	} else {
		out = append(out, 0x01, 0, 0, 0, 0, 0, 0)
	}
	_, err := conn.Write(out)
	return err
}

// --- HTTP proxy -------------------------------------------------------

func (p *plane) handleHTTP(conn *bufferedConn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		target, err := parseHostPort(req.URL.Host, 443)
		if err != nil {
			httpError(conn, http.StatusBadRequest)
			return
		}
		out, _, err := p.dialTarget(p.ctx, target)
		if err != nil {
			httpError(conn, http.StatusBadGateway)
			return
		}
		p.track(out)
		defer p.untrack(out)
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = out.Close()
			return
		}
		p.relay(conn, out)
		return
	}
	// Absolute-form proxy request.
	if req.URL == nil || req.URL.Host == "" {
		httpError(conn, http.StatusBadRequest)
		return
	}
	target, err := parseHostPort(req.URL.Host, 80)
	if err != nil {
		httpError(conn, http.StatusBadRequest)
		return
	}
	out, _, err := p.dialTarget(p.ctx, target)
	if err != nil {
		httpError(conn, http.StatusBadGateway)
		return
	}
	p.track(out)
	defer p.untrack(out)
	// Rewrite to origin form and forward, body included.
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.RequestURI = req.URL.RequestURI()
	if err := req.Write(out); err != nil {
		_ = out.Close()
		return
	}
	p.relay(conn, out)
}

func parseHostPort(hostport string, defaultPort int) (shadowsocks.Addr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port present.
		if hostport == "" {
			return shadowsocks.Addr{}, fmt.Errorf("empty authority")
		}
		return shadowsocks.Addr{Host: hostport, Port: defaultPort}, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return shadowsocks.Addr{}, err
	}
	return shadowsocks.Addr{Host: host, Port: port}, nil
}

func httpError(conn net.Conn, status int) {
	body := http.StatusText(status)
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
		status, body, len(body), body)
}

// --- UDP (SOCKS5 UDP ASSOCIATE data path) ------------------------------

type udpAssoc struct {
	key      string
	plane    *plane
	clientSrc *net.UDPAddr

	mu       sync.Mutex
	enginePC *shadowsocks.PacketConn
	directLn *net.UDPConn
	closed   bool

	lastSeen atomic.Int64
	udpDenyLogged atomic.Bool
}

func (a *udpAssoc) touch() { a.lastSeen.Store(time.Now().UnixNano()) }

func (a *udpAssoc) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.enginePC != nil {
		_ = a.enginePC.Close()
		a.enginePC = nil
	}
	if a.directLn != nil {
		_ = a.directLn.Close()
		a.directLn = nil
	}
}

func (p *plane) sweeper() {
	defer p.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			p.udpMu.Lock()
			for key, a := range p.udpAssocs {
				if now.Sub(time.Unix(0, a.lastSeen.Load())) > 2*time.Minute {
					a.close()
					delete(p.udpAssocs, key)
				}
			}
			p.udpMu.Unlock()
		}
	}
}

func (p *plane) udpLoop() {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := p.udpLn.ReadFromUDP(buf)
		if err != nil {
			return // listener closed
		}
		packet := append([]byte(nil), buf[:n]...)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handleUDPPacket(packet, src)
		}()
	}
}

func (p *plane) assocFor(src *net.UDPAddr) *udpAssoc {
	key := src.String()
	p.udpMu.Lock()
	defer p.udpMu.Unlock()
	a, ok := p.udpAssocs[key]
	if !ok {
		a = &udpAssoc{key: key, plane: p, clientSrc: src}
		a.touch()
		p.udpAssocs[key] = a
	}
	return a
}

func (p *plane) handleUDPPacket(packet []byte, src *net.UDPAddr) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return
	}
	if packet[2] != 0 {
		return // fragmentation is not supported (dropped, as in the control implementation)
	}
	br := bufio.NewReader(bytesReader(packet[4:]))
	target, err := readSocksAddr(br, packet[3])
	if err != nil {
		return
	}
	payload := packet[len(packet)-br.Buffered():]
	a := p.assocFor(src)
	a.touch()

	action, directIP, err := p.routeTarget(p.ctx, target)
	if err != nil || action == routecfg.ActionBlock {
		return // blocked or unresolvable: datagrams are dropped, never leaked
	}
	if action == routecfg.ActionDirect {
		a.sendDirect(payload, net.JoinHostPort(directIP.String(), strconv.Itoa(target.Port)))
		return
	}
	// Proxy path.
	if !p.node.UDP {
		if a.udpDenyLogged.CompareAndSwap(false, true) {
			p.logf("selfdev: plane dropped UDP datagram for %s: node has UDP disabled (udp=false)", target)
		}
		return
	}
	pc, err := a.engine(p.ctx)
	if err != nil {
		return
	}
	if _, err := pc.WriteTo(payload, target); err == nil {
		p.up.Add(uint64(len(payload)))
	}
}

// engine returns the association's Shadowsocks packet session,
// opening it (and its reply pump) on first use.
func (a *udpAssoc) engine(ctx context.Context) (*shadowsocks.PacketConn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, fmt.Errorf("association closed")
	}
	if a.enginePC != nil {
		return a.enginePC, nil
	}
	pc, err := a.plane.client.DialUDP(ctx, a.plane.serverAddr)
	if err != nil {
		return nil, err
	}
	a.enginePC = pc
	a.plane.wg.Add(1)
	go a.enginePump(pc)
	return pc, nil
}

func (a *udpAssoc) enginePump(pc *shadowsocks.PacketConn) {
	defer a.plane.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		a.touch()
		a.plane.down.Add(uint64(n))
		a.plane.sendUDPReply(a.clientSrc, addr, buf[:n])
	}
}

func (a *udpAssoc) sendDirect(payload []byte, addr string) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	if a.directLn == nil {
		ln, err := net.ListenUDP("udp", nil)
		if err != nil {
			a.mu.Unlock()
			return
		}
		a.directLn = ln
		a.plane.wg.Add(1)
		go a.directPump(ln)
	}
	ln := a.directLn
	a.mu.Unlock()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	a.plane.up.Add(uint64(len(payload)))
	_, _ = ln.WriteToUDP(payload, ua)
}

func (a *udpAssoc) directPump(ln *net.UDPConn) {
	defer a.plane.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.touch()
		a.plane.down.Add(uint64(n))
		a.plane.sendUDPReply(a.clientSrc, shadowsocks.Addr{Host: src.IP.String(), Port: src.Port}, buf[:n])
	}
}

// sendUDPReply wraps payload in a SOCKS5 UDP header naming the
// responder and sends it to the associated client.
func (p *plane) sendUDPReply(dst *net.UDPAddr, from shadowsocks.Addr, payload []byte) {
	hdr := []byte{0, 0, 0}
	hdr = from.AppendSocks(hdr)
	out := append(hdr, payload...)
	_, _ = p.udpLn.WriteToUDP(out, dst)
}

// bytesReader adapts a byte slice to a buffered reader source.
type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }
