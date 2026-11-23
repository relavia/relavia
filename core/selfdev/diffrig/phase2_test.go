//go:build with_quic && with_utls && with_wireguard

package diffrig

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"openproxy/core/kernel"
	"openproxy/core/killswitch"
	"openproxy/core/routecfg"
	"openproxy/core/selfdev"
	"openproxy/core/selfdev/shadowsocks"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// Phase-2 rig: the self-developed DATA PLANE (composite Start
// -> own forwarding layer) against the sing-box adapter's data
// plane as control, over the same reference servers as phase 1.
// Gate mapping (spec 4.6): G1/G2 re-run on the data plane, G4
// data-plane error/termination layer, G6 retest, plus the
// Step 11/12 semantic behaviours the plane must preserve.

// startPlane starts the composite adapter with the selfdev
// gear for one node and returns its mixed inbound address.
func startPlane(t *testing.T, serverAddr, method, password string, routing *routecfg.Policy) (*selfdev.Adapter, string) {
	t.Helper()
	node := ssSpecNode("plane", serverAddr, method, password)
	node.UDP = true
	return startPlaneNode(t, node, routing, selfdev.PolicySelfdev)
}

func startPlaneNode(t *testing.T, node *specnode.Node, routing *routecfg.Policy, gear selfdev.Policy) (*selfdev.Adapter, string) {
	t.Helper()
	sb := singbox.New(singbox.Options{Routing: routing})
	comp := selfdev.New(sb, selfdev.Options{Policy: gear, Routing: routing})
	if err := comp.StartNode(context.Background(), node, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
		t.Fatalf("plane start: %v", err)
	}
	t.Cleanup(func() { _ = comp.Stop(context.Background()) })
	addr := comp.MixedAddr()
	if addr == "" {
		t.Fatal("plane reports no mixed address")
	}
	return comp, addr
}

// startControlPlane starts the sing-box adapter itself for one
// node (the control data plane).
func startControlPlane(t *testing.T, serverAddr, method, password string, routing *routecfg.Policy) (*singbox.Adapter, string) {
	t.Helper()
	node := ssSpecNode("control", serverAddr, method, password)
	node.UDP = true
	sb := singbox.New(singbox.Options{Routing: routing})
	if err := sb.StartNode(context.Background(), node, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
		t.Fatalf("control start: %v", err)
	}
	t.Cleanup(func() { _ = sb.Stop(context.Background()) })
	return sb, sb.MixedAddr()
}

// --- G1/G2 on the data plane ------------------------------------

func TestRigDataPlaneTCP(t *testing.T) {
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)

	fullMethods := map[string]bool{"aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true}
	servers := []struct {
		name    string
		start   func(t *testing.T, method, password string) string
		fullSet bool // run the full scenario set (else the reduced set)
	}{
		{"singbox-inbound", startSingboxServer, false},
		{"rust", startRustServer, true},
	}
	for _, srv := range servers {
		for _, m := range rigMethods {
			full := srv.fullSet || fullMethods[m.method]
			t.Run(fmt.Sprintf("%s/%s", srv.name, m.method), func(t *testing.T) {
				if srv.name == "rust" {
					if why, ok := rustUnsupported[m.method]; ok {
						t.Skip("diffrig: " + why)
					}
				}
				serverAddr := srv.start(t, m.method, m.password)
				_, planeAddr := startPlane(t, serverAddr, m.method, m.password, nil)
				_, ctrlAddr := startControlPlane(t, serverAddr, m.method, m.password, nil)

				// Multi-round request/response on ONE connection.
				for _, base := range []string{planeAddr, ctrlAddr} {
					conn := socks5Connect(t, base, echoTarget)
					for i := 0; i < 20; i++ {
						payload := pattern(4096, byte(i))
						if got := echoRoundTrip(t, conn, payload); !bytes.Equal(got, payload) {
							t.Fatalf("multi-round %d corrupted via %s", i, base)
						}
					}
					_ = conn.Close()
				}

				if !full {
					// Reduced set: one 256 KiB transfer.
					payload := pattern(256*1024, 0x2a)
					conn := socks5Connect(t, planeAddr, echoTarget)
					if got := echoRoundTrip(t, conn, payload); !bytes.Equal(got, payload) {
						t.Fatal("reduced-set transfer corrupted via plane")
					}
					_ = conn.Close()
					return
				}

				// Large payload, byte-identical both planes.
				big := pattern(4<<20, 0x66)
				bigHash := sha256.Sum256(big)
				for _, base := range []string{planeAddr, ctrlAddr} {
					conn := socks5Connect(t, base, echoTarget)
					got := echoRoundTrip(t, conn, big)
					if sha256.Sum256(got) != bigHash {
						t.Fatalf("4 MiB transfer corrupted via %s", base)
					}
					_ = conn.Close()
				}

				// Half-close: write side EOF must not truncate
				// the response.
				payload := pattern(64*1024, 0x19)
				conn := socks5Connect(t, planeAddr, echoTarget)
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				if _, err := conn.Write(payload); err != nil {
					t.Fatalf("half-close write: %v", err)
				}
				cw, ok := conn.(interface{ CloseWrite() error })
				if !ok {
					t.Fatal("socks conn cannot half-close")
				}
				if err := cw.CloseWrite(); err != nil {
					t.Fatalf("half-close: %v", err)
				}
				gotAll, err := io.ReadAll(conn)
				if err != nil {
					t.Fatalf("half-close read: %v", err)
				}
				if !bytes.Equal(gotAll, payload) {
					t.Fatalf("half-close response truncated: %d of %d bytes", len(gotAll), len(payload))
				}
				_ = conn.Close()

				// Concurrency: 32 simultaneous connections.
				var wg sync.WaitGroup
				errs := make(chan error, 32)
				for i := 0; i < 32; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						p := pattern(64*1024, byte(i))
						c := socks5Connect(t, planeAddr, echoTarget)
						defer c.Close()
						if got := echoRoundTrip(t, c, p); !bytes.Equal(got, p) {
							errs <- fmt.Errorf("conn %d corrupted", i)
						}
					}(i)
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					t.Fatal(err)
				}
			})
		}
	}
}

// --- Step 11 behaviours on the data plane -------------------------

func socksConnectErr(t *testing.T, socksAddr string, target shadowsocks.Addr) (rep int, conn net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(target.Host)
	switch {
	case ip != nil && ip.To4() != nil:
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	case ip != nil:
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	default:
		req = append(req, 0x03, byte(len(target.Host)))
		req = append(req, target.Host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(target.Port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	// Drain the bound address.
	switch head[3] {
	case 0x01:
		_, _ = io.ReadFull(c, make([]byte, 6))
	case 0x03:
		lb := make([]byte, 1)
		_, _ = io.ReadFull(c, lb)
		_, _ = io.ReadFull(c, make([]byte, int(lb[0])+2))
	case 0x04:
		_, _ = io.ReadFull(c, make([]byte, 18))
	}
	return int(head[1]), c
}

func TestRigDataPlaneRouting(t *testing.T) {
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)
	serverAddr := startSingboxServer(t, "aes-256-gcm", "relavia-test-2017")
	deadServer := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	t.Run("block rule refuses on both planes", func(t *testing.T) {
		policy := &routecfg.Policy{
			Mode: routecfg.ModeRule,
			Rules: []routecfg.Rule{
				{Match: routecfg.Match{DomainSuffixes: []string{"blocked.test"}}, Action: routecfg.ActionBlock},
			},
			DNS: routecfg.DNSPolicy{
				Remote: routecfg.DNSServerSpec{Type: "tls", Server: "1.1.1.1"},
				Local:  routecfg.DNSServerSpec{Type: "local"},
			},
		}
		_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", policy)
		rep, conn := socksConnectErr(t, planeAddr, shadowsocks.Addr{Host: "www.blocked.test", Port: 80})
		_ = conn.Close()
		if rep != 2 {
			t.Fatalf("plane block reply = %d, want 2 (not allowed)", rep)
		}
		_, ctrlAddr := startControlPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", policy)
		repC := socksConnectErrSoft(ctrlAddr, shadowsocks.Addr{Host: "www.blocked.test", Port: 80})
		if repC == 0 {
			t.Fatal("control plane accepted a blocked target")
		}
		t.Logf("block replies: plane=%d control=%d (-1 = refused by connection close)", rep, repC)
	})

	t.Run("direct rule bypasses a dead node", func(t *testing.T) {
		policy := &routecfg.Policy{
			Mode: routecfg.ModeRule,
			Rules: []routecfg.Rule{
				{Match: routecfg.Match{IPCIDRs: []string{"127.0.0.0/8"}}, Action: routecfg.ActionDirect},
			},
			DNS: routecfg.DNSPolicy{
				Remote: routecfg.DNSServerSpec{Type: "tls", Server: "1.1.1.1"},
				Local:  routecfg.DNSServerSpec{Type: "local"},
			},
		}
		_, planeAddr := startPlane(t, deadServer, "aes-256-gcm", "relavia-test-2017", policy)
		conn := socks5Connect(t, planeAddr, echoTarget)
		payload := pattern(1024, 0x44)
		if got := echoRoundTrip(t, conn, payload); !bytes.Equal(got, payload) {
			t.Fatal("direct echo corrupted via plane")
		}
		_ = conn.Close()
		// An unlisted target must take the (dead) node and fail.
		rep, conn2 := socksConnectErr(t, planeAddr, shadowsocks.Addr{Host: "192.0.2.1", Port: 80})
		_ = conn2.Close()
		if rep == 0 {
			t.Fatal("unlisted target unexpectedly connected through a dead node")
		}
	})

	t.Run("ipv6 off refuses literal v6", func(t *testing.T) {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback here: %v", err)
		}
		_ = ln.Close()
		policy := &routecfg.Policy{
			Mode: routecfg.ModeRule,
			IPv6: routecfg.IPv6Off,
			DNS: routecfg.DNSPolicy{
				Remote: routecfg.DNSServerSpec{Type: "tls", Server: "1.1.1.1"},
				Local:  routecfg.DNSServerSpec{Type: "local"},
			},
		}
		_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", policy)
		rep, conn := socksConnectErr(t, planeAddr, shadowsocks.Addr{Host: "::1", Port: echoTarget.Port})
		_ = conn.Close()
		if rep != 2 {
			t.Fatalf("ipv6-off reply = %d, want 2", rep)
		}
	})
}

// --- fake DNS + DNS separation (Step 11 acceptance, plane edition)

type fakeDNS struct {
	mu    sync.Mutex
	seen  map[string]int
	addr  string
	udpLn *mdns.Server
	tcpLn *mdns.Server
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	f := &fakeDNS{seen: map[string]int{}}
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		f.mu.Lock()
		for _, q := range r.Question {
			f.seen[strings.TrimSuffix(q.Name, ".")]++
		}
		f.mu.Unlock()
		for _, q := range r.Question {
			switch q.Qtype {
			case mdns.TypeA:
				m.Answer = append(m.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("127.0.0.1"),
				})
			case mdns.TypeAAAA:
				m.Answer = append(m.Answer, &mdns.AAAA{
					Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP("::1"),
				})
			}
		}
		_ = w.WriteMsg(m)
	})
	// One port for both transports.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	laddr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	f.addr = laddr
	f.udpLn = &mdns.Server{PacketConn: pc.(net.PacketConn), Handler: handler}
	f.tcpLn = &mdns.Server{Listener: ln, Handler: handler}
	go func() { _ = f.udpLn.ActivateAndServe() }()
	go func() { _ = f.tcpLn.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = f.udpLn.Shutdown()
		_ = f.tcpLn.Shutdown()
	})
	return f
}

func (f *fakeDNS) saw(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[name] > 0
}

func (f *fakeDNS) port() int {
	_, p, _ := net.SplitHostPort(f.addr)
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}

// startSingboxServerDNS is startSingboxServer with a box-level
// DNS section: names the tunnel carries as FQDN are resolved at
// the egress through the given DNS server - the Step 11 rig's
// relay shape.
func startSingboxServerDNS(t *testing.T, method, password, dnsAddr string) string {
	t.Helper()
	host, port := hostPort(dnsAddr)
	port_ := freePort(t)
	startBox(t, map[string]any{
		"log": map[string]any{"level": "error"},
		"dns": map[string]any{
			"servers": []any{map[string]any{
				"type": "tcp", "tag": "remote", "server": host, "server_port": port,
			}},
			"final": "remote",
		},
		"inbounds": []any{map[string]any{
			"type": "shadowsocks", "tag": "ss-in",
			"listen": "127.0.0.1", "listen_port": port_,
			"method": method, "password": password,
			"network": []string{"tcp", "udp"},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port_)
	waitPort(t, addr)
	return addr
}

func fetchViaSocks(t *testing.T, socksAddr, rawURL string) (string, error) {
	t.Helper()
	// Parse target out of http://host:port/path.
	rest := strings.TrimPrefix(rawURL, "http://")
	authority, path, _ := strings.Cut(rest, "/")
	h, p := hostPort(authority)
	target := shadowsocks.Addr{Host: h, Port: p}
	conn := socks5Connect(t, socksAddr, target)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, authority); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(body), err
}

func TestRigDataPlaneDNSSeparation(t *testing.T) {
	localDNS := startFakeDNS(t)
	remoteDNS := startFakeDNS(t)

	// HTTP echo target on 127.0.0.1 (both fakes answer A=127.0.0.1).
	echoSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "echo:%s", r.URL.Path)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = echoSrv.Serve(ln) }()
	t.Cleanup(func() { _ = echoSrv.Close() })
	echoPort := ln.Addr().(*net.TCPAddr).Port

	serverAddr := startSingboxServerDNS(t, "aes-256-gcm", "relavia-test-2017", remoteDNS.addr)
	dnsPolicy := routecfg.DNSPolicy{
		Remote: routecfg.DNSServerSpec{Type: "tcp", Server: "127.0.0.1", Port: remoteDNS.port()},
		Local:  routecfg.DNSServerSpec{Type: "tcp", Server: "127.0.0.1", Port: localDNS.port()},
	}
	policy := &routecfg.Policy{
		Mode:          routecfg.ModeRule,
		BypassPrivate: false,
		Rules: []routecfg.Rule{
			{Match: routecfg.Match{DomainSuffixes: []string{"direct.test"}}, Action: routecfg.ActionDirect},
		},
		DNS: dnsPolicy,
	}
	_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", policy)

	// Direct-listed name: resolved LOCALLY by the plane, never
	// shown to the remote resolver.
	body, err := fetchViaSocks(t, planeAddr, fmt.Sprintf("http://www.direct.test:%d/a", echoPort))
	if err != nil || !strings.HasPrefix(body, "echo:/a") {
		t.Fatalf("direct fetch: body=%q err=%v", body, err)
	}
	if !localDNS.saw("www.direct.test") {
		t.Error("local resolver never saw www.direct.test - DNS mirror did not fire on the plane")
	}
	if remoteDNS.saw("www.direct.test") {
		t.Error("remote resolver saw www.direct.test - a direct name leaked to the tunnel side")
	}

	// Proxied name: the plane carries the NAME; resolution
	// happens at the egress (remote log), never locally.
	body, err = fetchViaSocks(t, planeAddr, fmt.Sprintf("http://www.proxied.test:%d/b", echoPort))
	if err != nil || !strings.HasPrefix(body, "echo:/b") {
		t.Fatalf("proxied fetch: body=%q err=%v", body, err)
	}
	if localDNS.saw("www.proxied.test") {
		t.Error("LEAK: local resolver saw www.proxied.test")
	}
	if !remoteDNS.saw("www.proxied.test") {
		t.Error("remote (egress) resolver never saw www.proxied.test")
	}

	// IP-dependent rule (second plane, policy extended with an
	// ip_cidr direct rule): an unlisted name forces the plane
	// to resolve through the TUNNEL (remote) for its decision;
	// the answer (127.0.0.1) hits the ip_cidr direct rule.
	policyB := &routecfg.Policy{
		Mode:          routecfg.ModeRule,
		BypassPrivate: false,
		Rules: []routecfg.Rule{
			{Match: routecfg.Match{DomainSuffixes: []string{"direct.test"}}, Action: routecfg.ActionDirect},
			{Match: routecfg.Match{IPCIDRs: []string{"127.0.0.0/8"}}, Action: routecfg.ActionDirect},
		},
		DNS: dnsPolicy,
	}
	_, planeAddrB := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", policyB)
	body, err = fetchViaSocks(t, planeAddrB, fmt.Sprintf("http://www.viaip.test:%d/c", echoPort))
	if err != nil || !strings.HasPrefix(body, "echo:/c") {
		t.Fatalf("via-ip fetch: body=%q err=%v", body, err)
	}
	if localDNS.saw("www.viaip.test") {
		t.Error("LEAK: local resolver saw www.viaip.test (IP-phase resolution must ride the tunnel)")
	}
	if !remoteDNS.saw("www.viaip.test") {
		t.Error("remote resolver never saw www.viaip.test - plane did not resolve through the tunnel")
	}
}

// --- UDP data plane -------------------------------------------------

type socksUDPClient struct {
	ctrl  net.Conn
	udp   *net.UDPConn
	relay *net.UDPAddr
}

func socksAssociate(t *testing.T, mixedAddr string) *socksUDPClient {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", mixedAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctrl.Close() })
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, buf); err != nil {
		t.Fatal(err)
	}
	// UDP ASSOCIATE with 0.0.0.0:0.
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x00 {
		t.Fatalf("associate reply code %d", head[1])
	}
	var relayIP net.IP
	var relayPort int
	switch head[3] {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(ctrl, b); err != nil {
			t.Fatal(err)
		}
		relayIP = net.IP(b[:4])
		relayPort = int(binary.BigEndian.Uint16(b[4:]))
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(ctrl, lb); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(ctrl, b); err != nil {
			t.Fatal(err)
		}
		ips, err := net.LookupIP(string(b[:len(b)-2]))
		if err != nil || len(ips) == 0 {
			t.Fatalf("associate bnd name: %v", err)
		}
		relayIP = ips[0]
		relayPort = int(binary.BigEndian.Uint16(b[len(b)-2:]))
	default:
		t.Fatalf("associate bnd atyp %d", head[3])
	}
	if relayIP.IsUnspecified() {
		relayIP = net.ParseIP("127.0.0.1")
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return &socksUDPClient{ctrl: ctrl, udp: udp, relay: &net.UDPAddr{IP: relayIP, Port: relayPort}}
}

func (c *socksUDPClient) exchange(t *testing.T, target shadowsocks.Addr, payload []byte, timeout time.Duration) (shadowsocks.Addr, []byte, error) {
	t.Helper()
	pkt := []byte{0, 0, 0}
	pkt = target.AppendSocks(pkt)
	pkt = append(pkt, payload...)
	if _, err := c.udp.WriteToUDP(pkt, c.relay); err != nil {
		return shadowsocks.Addr{}, nil, err
	}
	_ = c.udp.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := c.udp.ReadFromUDP(buf)
	if err != nil {
		return shadowsocks.Addr{}, nil, err
	}
	data := buf[:n]
	if len(data) < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
		return shadowsocks.Addr{}, nil, fmt.Errorf("bad udp reply header %x", data[:min(4, len(data))])
	}
	from, err := readSocksAddrFromBytes(data[3:])
	if err != nil {
		return shadowsocks.Addr{}, nil, err
	}
	hdrLen := 3 + socksAddrLen(data[3:])
	return from, data[hdrLen:], nil
}

func socksAddrLen(b []byte) int {
	switch b[0] {
	case 0x01:
		return 1 + 4 + 2
	case 0x04:
		return 1 + 16 + 2
	case 0x03:
		return 1 + 1 + int(b[1]) + 2
	}
	return 0
}

func readSocksAddrFromBytes(b []byte) (shadowsocks.Addr, error) {
	switch b[0] {
	case 0x01:
		return shadowsocks.Addr{Host: net.IP(b[1:5]).String(), Port: int(binary.BigEndian.Uint16(b[5:7]))}, nil
	case 0x04:
		return shadowsocks.Addr{Host: net.IP(b[1:17]).String(), Port: int(binary.BigEndian.Uint16(b[17:19]))}, nil
	case 0x03:
		l := int(b[1])
		return shadowsocks.Addr{Host: string(b[2 : 2+l]), Port: int(binary.BigEndian.Uint16(b[2+l : 4+l]))}, nil
	}
	return shadowsocks.Addr{}, fmt.Errorf("atyp %d", b[0])
}

func TestRigDataPlaneUDP(t *testing.T) {
	echoAddrStr, ok := udpEchoServer(t)
	if !ok {
		t.Skip("UDP loopback unavailable in this environment")
	}
	echoTarget := parseAddr(t, echoAddrStr)
	methods := []struct{ method, password string }{
		{"aes-256-gcm", "relavia-test-2017"},
		{"2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
		{"2022-blake3-chacha20-poly1305", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
	}
	for _, m := range methods {
		t.Run(m.method, func(t *testing.T) {
			serverAddr := startSingboxServer(t, m.method, m.password)
			_, planeAddr := startPlane(t, serverAddr, m.method, m.password, nil)
			_, ctrlAddr := startControlPlane(t, serverAddr, m.method, m.password, nil)
			for _, base := range []string{planeAddr, ctrlAddr} {
				client := socksAssociate(t, base)
				for _, size := range []int{512, 32 * 1024} {
					payload := pattern(size, 0x5a)
					from, got, err := client.exchange(t, echoTarget, payload, 10*time.Second)
					if err != nil {
						t.Fatalf("udp exchange via %s (%d B): %v", base, size, err)
					}
					if from != echoTarget || !bytes.Equal(got, payload) {
						t.Fatalf("udp echo mismatch via %s: from=%v bytes=%d", base, from, len(got))
					}
				}
			}
		})
	}
}

// --- G4 data-plane error / termination layer --------------------------

func TestRigDataPlaneErrors(t *testing.T) {
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)
	serverAddr := startSingboxServer(t, "aes-256-gcm", "relavia-test-2017")

	t.Run("refused target: same failure phase on both planes", func(t *testing.T) {
		// Shadowsocks has no connect-response for TCP: a
		// target the egress cannot reach is accepted at
		// tunnel establishment and fails on first exchange.
		// Both planes must show exactly that shape (SOCKS
		// success, then a data-phase failure delivering
		// nothing) - recorded here because it pins the
		// observable error layer of the protocol itself.
		_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", nil)
		_, ctrlAddr := startControlPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", nil)
		dead := shadowsocks.Addr{Host: "127.0.0.1", Port: freePort(t)}
		for _, base := range []string{planeAddr, ctrlAddr} {
			rep, conn := socksConnectErr(t, base, dead)
			if rep != 0 {
				t.Fatalf("via %s: connect reply = %d, want 0 (tunnel establishment succeeds; refusal is data-phase)", base, rep)
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = conn.Write(pattern(256, 0x33))
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			_ = conn.Close()
			if err == nil && n > 0 {
				t.Fatalf("via %s: refused target delivered %d bytes", base, n)
			}
		}
	})

	t.Run("wrong password delivers nothing on both planes", func(t *testing.T) {
		_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "wrong-password", nil)
		_, ctrlAddr := startControlPlane(t, serverAddr, "aes-256-gcm", "wrong-password", nil)
		for _, base := range []string{planeAddr, ctrlAddr} {
			conn := socks5Connect(t, base, echoTarget)
			_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
			_, _ = conn.Write(pattern(1024, 0x11))
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err == nil && n > 0 {
				t.Fatalf("wrong password delivered %d bytes via %s", n, base)
			}
			_ = conn.Close()
		}
	})
}

// --- G4: mid-stream server death ---------------------------------------

// startRustServerProc is startRustServer with the process
// handle exposed, for tests that kill the server mid-stream.
// (An in-process sing-box server cannot play this role: its
// Close is a soft stop that leaves established sockets open
// for seconds - a rig artefact measured and recorded in the
// phase-2 record, not a client behaviour.)
func startRustServerProc(t *testing.T, method, password string) (string, *exec.Cmd) {
	t.Helper()
	bin := os.Getenv("RELAVIA_SSSERVER")
	if bin == "" {
		bin, _ = exec.LookPath("ssserver")
	}
	if bin == "" {
		t.Skip("diffrig: ssserver (shadowsocks-rust) not found via RELAVIA_SSSERVER or PATH - mid-stream death leg skipped")
	}
	port := freePort(t)
	cfg := map[string]any{
		"server": "127.0.0.1", "server_port": port,
		"password": password, "method": method, "timeout": 30,
		"mode": "tcp_and_udp",
	}
	data, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "ssserver.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", path)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitPort(t, addr)
	return addr, cmd
}

func TestRigDataPlaneMidStreamDeath(t *testing.T) {
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)

	// Real process death: the rust server is KILLED mid-stream,
	// so its sockets die with it. Both planes must surface the
	// death on the SAME connection promptly (an error, never a
	// hang until the read deadline, never phantom data).
	serverAddr, cmd := startRustServerProc(t, "aes-256-gcm", "relavia-test-2017")

	_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", nil)
	_, ctrlAddr := startControlPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", nil)

	conns := map[string]net.Conn{}
	for name, base := range map[string]string{"plane": planeAddr, "control": ctrlAddr} {
		conn := socks5Connect(t, base, echoTarget)
		payload := pattern(1024, 0x55)
		if got := echoRoundTrip(t, conn, payload); !bytes.Equal(got, payload) {
			t.Fatalf("%s: pre-kill echo corrupted", name)
		}
		conns[name] = conn
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for name, conn := range conns {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		start := time.Now()
		_, _ = conn.Write(pattern(1024, 0x56))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		elapsed := time.Since(start)
		_ = conn.Close()
		if err == nil && n > 0 {
			t.Fatalf("%s: dead server delivered %d phantom bytes", name, n)
		}
		if err == nil {
			t.Fatalf("%s: read after server death returned cleanly (n=0, no error) - termination not signalled", name)
		}
		if elapsed > 10*time.Second {
			t.Fatalf("%s: death surfaced only at the read deadline (%v) - the plane hung on a dead connection", name, elapsed)
		}
		t.Logf("%s: mid-stream death surfaced as %v after %v", name, err, elapsed)
	}
}

// --- NEG-04: SIP022 timestamp window, behaviour level -----------------

func TestRigTimestampWindow(t *testing.T) {
	const method = "2022-blake3-aes-256-gcm"
	const password = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)
	ctx := context.Background()

	skewed := func() *shadowsocks.Client {
		c, err := shadowsocks.NewClient(method, password,
			shadowsocks.WithClock(func() time.Time { return time.Now().Add(2 * time.Hour) }))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	normal := func() *shadowsocks.Client {
		c, err := shadowsocks.NewClient(method, password)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	servers := []struct {
		name  string
		start func(t *testing.T, method, password string) string
	}{
		{"rust", startRustServer},
		{"singbox-inbound", startSingboxServer},
	}
	for _, srv := range servers {
		t.Run(srv.name+"/tcp", func(t *testing.T) {
			serverAddr := srv.start(t, method, password)
			// Skewed clock: the server must reject the request
			// (its 30 s window is a spec MUST); the read side
			// surfaces a failure, never data.
			conn, err := skewed().DialTCP(ctx, serverAddr, echoTarget)
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = conn.Write(pattern(64, 0x01))
				buf := make([]byte, 64)
				n, rerr := conn.Read(buf)
				_ = conn.Close()
				if rerr == nil && n > 0 {
					t.Fatal("skewed-clock request was answered - timestamp window not enforced")
				}
			}
			// Accurate clock works (control-equivalent).
			conn2, err := normal().DialTCP(ctx, serverAddr, echoTarget)
			if err != nil {
				t.Fatalf("normal dial: %v", err)
			}
			payload := pattern(256, 0x02)
			if got := echoRoundTrip(t, conn2, payload); !bytes.Equal(got, payload) {
				t.Fatal("normal-clock echo corrupted")
			}
			_ = conn2.Close()
		})
		t.Run(srv.name+"/udp", func(t *testing.T) {
			echoAddrStr, ok := udpEchoServer(t)
			if !ok {
				t.Skip("UDP loopback unavailable in this environment")
			}
			udpTarget := parseAddr(t, echoAddrStr)
			serverAddr := srv.start(t, method, password)
			pc, err := skewed().DialUDP(ctx, serverAddr)
			if err != nil {
				t.Fatal(err)
			}
			_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := pc.WriteTo(pattern(64, 0x03), udpTarget); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4096)
			if _, _, err := pc.ReadFrom(buf); err == nil {
				t.Fatal("skewed-clock UDP packet was answered - timestamp window not enforced")
			}
			_ = pc.Close()
			pc2, err := normal().DialUDP(ctx, serverAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer pc2.Close()
			_ = pc2.SetDeadline(time.Now().Add(10 * time.Second))
			payload := pattern(128, 0x04)
			if _, err := pc2.WriteTo(payload, udpTarget); err != nil {
				t.Fatal(err)
			}
			n, _, err := pc2.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("normal-clock UDP echo failed: n=%d err=%v", n, err)
			}
		})
	}
	// Control note: the sing-box client exposes no clock hook,
	// so a skewed CONTROL run is impossible by construction;
	// the window value itself (30 s, both directions) was
	// verified byte-level in phase 1 (spec section 6 item 2,
	// vector W22-06). What is compared here is the observable
	// server behaviour toward the self-developed client.
}

// --- NEG-07: SIP022 UDP replay -----------------------------------------

type udpCaptureRelay struct {
	ln       *net.UDPConn
	server   *net.UDPAddr
	mu       sync.Mutex
	client   *net.UDPAddr
	captured [][]byte
}

func startUDPCaptureRelay(t *testing.T, serverAddr string) (*udpCaptureRelay, string) {
	t.Helper()
	sa, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	r := &udpCaptureRelay{ln: ln, server: sa}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			if src.String() == r.server.String() {
				// Server -> client.
				r.mu.Lock()
				client := r.client
				r.mu.Unlock()
				if client != nil {
					_, _ = ln.WriteToUDP(pkt, client)
				}
				continue
			}
			// Client -> server: the first sender is the client
			// by construction of the rig (only it writes first).
			r.mu.Lock()
			if r.client == nil {
				r.client = src
			}
			r.captured = append(r.captured, pkt)
			r.mu.Unlock()
			_, _ = ln.WriteToUDP(pkt, r.server)
		}
	}()
	return r, ln.LocalAddr().String()
}

func (r *udpCaptureRelay) firstPacket(t *testing.T) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.captured) > 0 {
			pkt := r.captured[0]
			r.mu.Unlock()
			return pkt
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("relay captured no client packet")
	return nil
}

func TestRigUDPReplay2022(t *testing.T) {
	echoAddrStr, ok := udpEchoServer(t)
	if !ok {
		t.Skip("UDP loopback unavailable in this environment")
	}
	echoTarget := parseAddr(t, echoAddrStr)
	const method = "2022-blake3-aes-256-gcm"
	const password = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	ctx := context.Background()

	run := func(t *testing.T, serverAddr string, via func(relayAddr string) func() bool) {
		relay, relayAddr := startUDPCaptureRelay(t, serverAddr)
		answered := via(relayAddr)
		if !answered() {
			t.Fatal("initial exchange through the relay failed")
		}
		pkt := relay.firstPacket(t)
		// Replay the captured client packet verbatim from a
		// fresh socket: the server's replay window must drop
		// it (no second answer).
		raw, err := net.ListenUDP("udp", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		if _, err := raw.WriteToUDP(pkt, relay.server); err != nil {
			t.Fatal(err)
		}
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		if _, _, err := raw.ReadFromUDP(buf); err == nil {
			t.Fatal("replayed packet was answered - server replay window did not drop it")
		}
	}

	t.Run("selfdev packet", func(t *testing.T) {
		serverAddr := startSingboxServer(t, method, password)
		run(t, serverAddr, func(relayAddr string) func() bool {
			return func() bool {
				client, err := shadowsocks.NewClient(method, password)
				if err != nil {
					t.Fatal(err)
				}
				pc, err := client.DialUDP(ctx, relayAddr)
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
				payload := pattern(128, 0x07)
				if _, err := pc.WriteTo(payload, echoTarget); err != nil {
					return false
				}
				buf := make([]byte, 4096)
				n, _, err := pc.ReadFrom(buf)
				return err == nil && bytes.Equal(buf[:n], payload)
			}
		})
	})

	t.Run("control packet", func(t *testing.T) {
		serverAddr := startSingboxServer(t, method, password)
		run(t, serverAddr, func(relayAddr string) func() bool {
			return func() bool {
				socksAddr := startSingboxClient(t, relayAddr, method, password)
				client := socksAssociate(t, socksAddr)
				_, _, err := client.exchange(t, echoTarget, pattern(128, 0x08), 10*time.Second)
				return err == nil
			}
		})
	})
}

// --- start discipline: gears, gates, state ------------------------------

func TestRigDataPlaneStartDiscipline(t *testing.T) {
	serverAddr := startSingboxServer(t, "aes-256-gcm", "relavia-test-2017")
	ctx := context.Background()

	t.Run("selfdev start serves and reports", func(t *testing.T) {
		var logs []string
		sb := singbox.New(singbox.Options{})
		comp := selfdev.New(sb, selfdev.Options{
			Policy: selfdev.PolicySelfdev,
			Logf:   func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
		})
		node := ssSpecNode("disc", serverAddr, "aes-256-gcm", "relavia-test-2017")
		if err := comp.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
			t.Fatalf("start: %v", err)
		}
		if st := comp.Status(); st.State != kernel.StateRunning || st.ActiveNodeID != node.ID {
			t.Fatalf("status = %+v", st)
		}
		// Second start is a state error, not a reroute.
		if err := comp.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeManual}); !kernel.IsKind(err, kernel.KindWrongState) {
			t.Fatalf("second start = %v, want wrong_state", err)
		}
		// Traffic flows and is counted.
		echoAddr := startEchoTCP(t)
		conn := socks5Connect(t, comp.MixedAddr(), parseAddr(t, echoAddr))
		payload := pattern(8192, 0x21)
		if got := echoRoundTrip(t, conn, payload); !bytes.Equal(got, payload) {
			t.Fatal("echo corrupted")
		}
		_ = conn.Close()
		stats, err := comp.QueryTraffic(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stats.UploadBytes < uint64(len(payload)) || stats.DownloadBytes < uint64(len(payload)) {
			t.Fatalf("traffic undercounted: %+v", stats)
		}
		if err := comp.Stop(ctx); err != nil {
			t.Fatalf("stop: %v", err)
		}
		if st := comp.Status(); st.State != kernel.StateStopped {
			t.Fatalf("after stop: %v", st.State)
		}
		// Restart works.
		if err := comp.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
			t.Fatalf("restart: %v", err)
		}
		_ = comp.Stop(ctx)
		if !strings.Contains(strings.Join(logs, "\n"), "backend=selfdev") {
			t.Fatalf("backend not recorded in logs:\n%s", strings.Join(logs, "\n"))
		}
	})

	t.Run("tun mode stays with sing-box and is refused there in this build", func(t *testing.T) {
		sb := singbox.New(singbox.Options{})
		comp := selfdev.New(sb, selfdev.Options{Policy: selfdev.PolicySelfdev})
		node := ssSpecNode("disc", serverAddr, "aes-256-gcm", "relavia-test-2017")
		err := comp.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeTUN})
		if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
			t.Fatalf("tun start = %v, want platform_unavailable from the sing-box backend", err)
		}
	})

	t.Run("kill switch gate is shared with sing-box", func(t *testing.T) {
		report := func() killswitch.Report {
			return killswitch.Report{Readiness: killswitch.ReadinessPolicyReady}
		}
		sb := singbox.New(singbox.Options{KillSwitchReport: report})
		comp := selfdev.New(sb, selfdev.Options{Policy: selfdev.PolicySelfdev})
		node := ssSpecNode("disc", serverAddr, "aes-256-gcm", "relavia-test-2017")
		err := comp.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeManual, KillSwitch: true})
		if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
			t.Fatalf("kill-switch start = %v, want platform_unavailable (policy-ready is not enforceable)", err)
		}
	})

	t.Run("plugin node under selfdev gear stays on sing-box", func(t *testing.T) {
		var logs []string
		sb := singbox.New(singbox.Options{})
		comp := selfdev.New(sb, selfdev.Options{
			Policy: selfdev.PolicySelfdev,
			Logf:   func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
		})
		node := ssSpecNode("disc", serverAddr, "aes-256-gcm", "relavia-test-2017")
		node.Shadowsocks.Plugin = "obfs-local"
		// The sing-box backend will try to run the (absent)
		// plugin and fail; what this leg pins is the ROUTING:
		// the log must show the sing-box backend with the
		// plugin reason, never the selfdev plane.
		_ = comp.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeManual})
		_ = comp.Stop(ctx)
		joined := strings.Join(logs, "\n")
		if !strings.Contains(joined, "backend=sing-box") || !strings.Contains(joined, "plugin") {
			t.Fatalf("plugin routing not recorded as sing-box:\n%s", joined)
		}
		if strings.Contains(joined, "backend=selfdev") && strings.Contains(joined, "start") {
			t.Fatalf("plugin node started on the selfdev plane:\n%s", joined)
		}
	})
}

// --- G6 retest on the data plane -----------------------------------------

// socksConnectErrSoft is socksConnectErr for legs where the
// control implementation may refuse by closing the connection
// without a SOCKS reply: it reports rep=-1 then, so callers can
// assert "refused" without pinning the wire shape.
func socksConnectErrSoft(socksAddr string, target shadowsocks.Addr) int {
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return -1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return -1
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return -1
	}
	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(target.Host)
	switch {
	case ip != nil && ip.To4() != nil:
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	case ip != nil:
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	default:
		req = append(req, 0x03, byte(len(target.Host)))
		req = append(req, target.Host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(target.Port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		return -1
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return -1
	}
	return int(head[1])
}

func TestRigPerfSentinelPlane(t *testing.T) {
	serverAddr := startRustServer(t, "aes-256-gcm", "relavia-test-2017")
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)
	payload := pattern(4<<20, 0x77)

	measure := func(mixedAddr string) float64 {
		conn := socks5Connect(t, mixedAddr, echoTarget)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
		start := time.Now()
		go func() { _, _ = conn.Write(payload) }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		return float64(len(payload)) / time.Since(start).Seconds() / (1 << 20)
	}
	_, planeAddr := startPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", nil)
	_, ctrlAddr := startControlPlane(t, serverAddr, "aes-256-gcm", "relavia-test-2017", nil)
	median3 := func(addr string) float64 {
		vals := []float64{measure(addr), measure(addr), measure(addr)}
		for i := 0; i < 3; i++ {
			for j := i + 1; j < 3; j++ {
				if vals[j] < vals[i] {
					vals[i], vals[j] = vals[j], vals[i]
				}
			}
		}
		return vals[1]
	}
	selfMBs := median3(planeAddr)
	ctrlMBs := median3(ctrlAddr)
	t.Logf("G6 plane sentinel (median of 3): selfdev-plane=%.1f MiB/s control-plane=%.1f MiB/s ratio=%.2f (gate: >=0.70)",
		selfMBs, ctrlMBs, selfMBs/ctrlMBs)
}
