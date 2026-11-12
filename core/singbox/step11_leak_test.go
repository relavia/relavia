//go:build with_quic && with_utls && with_wireguard

package singbox

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"openproxy/core/routecfg"
	"openproxy/core/specnode"
)

// Step 11 leak-detection cases (book ch.14 Step 11 acceptance:
// 泄露检测用例 WebRTC/DNS/IPv6 通过并留记录).
//
// Method: the client under test is a real sing-box instance
// compiled from a SOCKS5 node (a loopback relay instance plays
// the server side, exactly like the Step 7 harness) PLUS a
// routecfg fragment. Two fake DNS servers log every query they
// receive: one stands in for the LOCAL resolver (the client's
// own mirrored direct names), the other is the TUNNEL-SIDE
// resolver — it serves the client's detoured remote server AND
// the relay's egress resolution, which is where names carried
// inside the tunnel (socks FQDN) are resolved, mirroring
// production, where the node resolves them at its egress.
// The two servers answer with DIFFERENT loopback addresses
// (127.0.0.1 vs 127.0.0.2) behind which two echo servers
// return different tokens. A fetch therefore leaves two
// independent pieces of evidence: which resolver was
// consulted (DNS query logs) and which egress the connection
// actually took (the token).
//
// Both fake DNS servers speak DNS over TCP. This sandbox
// forbids ALL UDP sends at syscall level (see the Step 7
// record), and DNS-over-TCP exercises the identical sing-box
// DNS routing machinery as UDP; the production policies use
// DoT/DoH, whose transports differ but whose rule evaluation
// is the same code path. UDP-specific behaviour is covered by
// scripts/leak-check.sh in the field (see
// docs/step11-路由与DNS.md).

const (
	tokenRemotePath = "relavia-step11-remote-path"
	tokenDirectPath = "relavia-step11-direct-path"
)

// --- fake DNS server (TCP, RFC 7766 framing) --------------------

type dnsQuery struct {
	Name string
	Type uint16
}

type fakeDNS struct {
	mu       sync.Mutex
	queries  []dnsQuery
	answerA  net.IP
	answer6  net.IP
	listener net.Listener
}

func startFakeDNS(t *testing.T, answerA, answerAAAA string) *fakeDNS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake dns listen: %v", err)
	}
	f := &fakeDNS{listener: ln}
	if answerA != "" {
		f.answerA = net.ParseIP(answerA).To4()
	}
	if answerAAAA != "" {
		f.answer6 = net.ParseIP(answerAAAA).To16()
	}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeDNS) port() int {
	return f.listener.Addr().(*net.TCPAddr).Port
}

func (f *fakeDNS) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeDNS) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	lenBuf := make([]byte, 2)
	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		resp := f.answer(msg)
		if resp == nil {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		if _, err := conn.Write(append(out[:], resp...)); err != nil {
			return
		}
	}
}

// answer parses one DNS query, logs it, and builds a response
// carrying the configured A/AAAA answer (or NODATA).
func (f *fakeDNS) answer(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	// Single question, no compression in the question section.
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return nil
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(msg) {
			return nil
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	if off+4 > len(msg) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(msg[off:])
	qend := off + 4

	f.mu.Lock()
	f.queries = append(f.queries, dnsQuery{Name: strings.Join(labels, "."), Type: qtype})
	f.mu.Unlock()

	var rdata []byte
	var rtype uint16
	switch qtype {
	case 1: // A
		if f.answerA != nil {
			rdata, rtype = f.answerA, 1
		}
	case 28: // AAAA
		if f.answer6 != nil {
			rdata, rtype = f.answer6, 28
		}
	}
	ancount := uint16(0)
	if rdata != nil {
		ancount = 1
	}
	resp := make([]byte, 0, qend+16+len(rdata))
	resp = append(resp, msg[0], msg[1]) // ID
	resp = append(resp, 0x81, 0x80)     // QR RD RA, no error
	resp = append(resp, 0, 1)           // QDCOUNT
	resp = append(resp, byte(ancount>>8), byte(ancount))
	resp = append(resp, 0, 0, 0, 0) // NSCOUNT, ARCOUNT
	resp = append(resp, msg[12:qend]...)
	if rdata != nil {
		resp = append(resp, 0xC0, 0x0C) // name pointer to question
		resp = append(resp, byte(rtype>>8), byte(rtype))
		resp = append(resp, 0, 1) // CLASS IN
		resp = append(resp, 0, 0, 0, 60)
		resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)))
		resp = append(resp, rdata...)
	}
	return resp
}

func (f *fakeDNS) saw(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, q := range f.queries {
		if q.Name == name {
			return true
		}
	}
	return false
}

func (f *fakeDNS) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queries)
}

// --- harness ------------------------------------------------------

// startEchoPair binds two HTTP echo servers returning distinct
// tokens on 127.0.0.1 and 127.0.0.2 at the same port.
func startEchoPair(t *testing.T) int {
	t.Helper()
	handler := func(token string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s %s", token, r.URL.Path)
		})
	}
	var port int
	for attempt := 0; attempt < 20; attempt++ {
		ln1, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = ln1.Addr().(*net.TCPAddr).Port
		ln2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", fmt.Sprint(port)))
		if err != nil {
			_ = ln1.Close()
			continue
		}
		s1 := &http.Server{Handler: handler(tokenRemotePath)}
		s2 := &http.Server{Handler: handler(tokenDirectPath)}
		go func() { _ = s1.Serve(ln1) }()
		go func() { _ = s2.Serve(ln2) }()
		t.Cleanup(func() { _ = s1.Close(); _ = s2.Close() })
		return port
	}
	t.Fatal("could not bind echo pair on a shared port")
	return 0
}

// leakHarness wires the full Step 11 rig: relay instance
// (server side), fake local/remote DNS, echo pair, and a
// client instance compiled from policy.
type leakHarness struct {
	localDNS  *fakeDNS
	remoteDNS *fakeDNS
	echoPort  int
	mixedAddr string
	logs      *logSink
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *logSink) add(level, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, level+": "+message)
}

func (s *logSink) contains(substr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

func startLeakHarness(t *testing.T, policy routecfg.Policy) *leakHarness {
	t.Helper()
	h := &leakHarness{logs: &logSink{}}

	// Echo pair: remote answers point at .1, local at .2.
	h.echoPort = startEchoPair(t)

	// Fake DNS pair. DNS-over-TCP transports (sandbox forbids
	// UDP sends entirely); the policies under test name these
	// servers explicitly instead of the production DoT/local
	// pair.
	h.remoteDNS = startFakeDNS(t, "127.0.0.1", "::1")
	h.localDNS = startFakeDNS(t, "127.0.0.2", "")
	policy.DNS.Remote = routecfg.DNSServerSpec{Type: "tcp", Server: "127.0.0.1", Port: h.remoteDNS.port()}
	policy.DNS.Local = routecfg.DNSServerSpec{Type: "tcp", Server: "127.0.0.1", Port: h.localDNS.port()}

	// Relay (server side): a mixed inbound with direct egress.
	// Its own resolver is the tunnel-side fake DNS: names the
	// tunnel carries as FQDN are resolved HERE, at the egress,
	// exactly as a production node resolves them — and that
	// resolution is the query the assertions look for in the
	// remote log.
	relayPort := freeTCPPort(t)
	relayCfg := serverBase(map[string]any{
		"type":        "mixed",
		"tag":         "in",
		"listen":      "127.0.0.1",
		"listen_port": relayPort,
	})
	relayCfg["dns"] = map[string]any{
		"servers": []any{map[string]any{
			"type": "tcp", "tag": "remote",
			"server": "127.0.0.1", "server_port": h.remoteDNS.port(),
		}},
		"final": "remote",
	}
	startRawInstance(t, relayCfg)

	// Client: a SOCKS5 node at the relay, policy-compiled.
	frag, err := routecfg.Compile(policy)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	node := &specnode.Node{
		ID:       "step11-leak-node",
		Protocol: specnode.ProtocolSOCKS5,
		Server:   "127.0.0.1",
		Port:     relayPort,
	}
	mixedPort := freeTCPPort(t)
	raw, err := compileConfig(node, compileOptions{
		listenHost: "127.0.0.1",
		listenPort: mixedPort,
		logLevel:   "debug",
		cachePath:  filepath.Join(t.TempDir(), "cache.db"),
		fragment:   frag,
	})
	if err != nil {
		t.Fatalf("compile client config: %v", err)
	}
	instance, _, err := startInstance(raw, platformLogWriter{fn: h.logs.add})
	if err != nil {
		t.Fatalf("start client instance: %v\nconfig: %s", err, raw)
	}
	t.Cleanup(func() { _ = instance.Close() })
	h.mixedAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(mixedPort))
	return h
}

// fetchE is fetchBodyViaMixed without the fatal-on-error
// behaviour, for negative cases.
func fetchE(mixedAddr, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	dialer, err := proxy.SOCKS5("tcp", mixedAddr, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	conn, err := dialer.Dial("tcp", u.Host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host); err != nil {
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

// --- cases --------------------------------------------------------

func step11RulePolicy() routecfg.Policy {
	return routecfg.Policy{
		Mode:          routecfg.ModeRule,
		BypassPrivate: false, // off deliberately: the echo pair lives on private loopback space; the class-E bypass would mask the very paths under test
		Rules: []routecfg.Rule{
			{Match: routecfg.Match{DomainSuffixes: []string{"direct.test"}}, Action: routecfg.ActionDirect},
		},
	}
}

// Acceptance: rule mode — a direct-listed name is resolved by
// the LOCAL resolver and reached directly; any other name is
// resolved ONLY on the tunnel side and reached via the node.
func TestStep11RuleModeDNSSeparation(t *testing.T) {
	h := startLeakHarness(t, step11RulePolicy())

	body, err := fetchE(h.mixedAddr, fmt.Sprintf("http://www.direct.test:%d/a", h.echoPort))
	if err != nil {
		t.Fatalf("fetch direct-listed: %v", err)
	}
	if !strings.HasPrefix(body, tokenDirectPath) {
		t.Fatalf("direct-listed name took the wrong egress: body %q (client logs: %v)", body, h.logs.contains("direct.test"))
	}
	if !h.localDNS.saw("www.direct.test") {
		t.Error("local resolver never saw www.direct.test — the DNS mirror of the direct rule did not fire")
	}
	if h.remoteDNS.saw("www.direct.test") {
		t.Error("remote resolver saw www.direct.test — a direct-listed name leaked to the tunnel-side resolver set (should be local-only)")
	}

	body, err = fetchE(h.mixedAddr, fmt.Sprintf("http://www.proxied.test:%d/b", h.echoPort))
	if err != nil {
		t.Fatalf("fetch proxied: %v", err)
	}
	if !strings.HasPrefix(body, tokenRemotePath) {
		t.Fatalf("proxied name took the wrong egress: body %q", body)
	}
	if !h.remoteDNS.saw("www.proxied.test") {
		t.Error("remote resolver never saw www.proxied.test")
	}
	if h.localDNS.saw("www.proxied.test") {
		t.Error("LEAK: local resolver saw www.proxied.test — a non-listed name escaped to the local resolver")
	}
}

// Acceptance: global mode — nothing goes direct and nothing
// resolves locally, not even a name the rule policy lists as
// direct.
func TestStep11GlobalModeNoDirectNoLocalDNS(t *testing.T) {
	p := step11RulePolicy()
	p.Mode = routecfg.ModeGlobal
	p.Rules = nil // global mode accepts only blocks; the point is the direct list no longer exists
	h := startLeakHarness(t, p)

	body, err := fetchE(h.mixedAddr, fmt.Sprintf("http://www.direct.test:%d/a", h.echoPort))
	if err != nil {
		t.Fatalf("fetch in global mode: %v", err)
	}
	if !strings.HasPrefix(body, tokenRemotePath) {
		t.Fatalf("global mode: connection did not take the tunnel path: body %q", body)
	}
	if h.localDNS.total() != 0 {
		t.Fatalf("global mode: local resolver received %d queries — DNS leak", h.localDNS.total())
	}
	if !h.remoteDNS.saw("www.direct.test") {
		t.Error("global mode: remote resolver never saw the query")
	}
}

// Acceptance: IPv6 off — a literal IPv6 destination is refused
// even though it is perfectly reachable; the control run with
// IPv6 on reaches it, proving the refusal is the policy and
// not the environment.
func TestStep11IPv6OffBlocksLiteralV6(t *testing.T) {
	// Echo on ::1.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback in this environment: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", tokenRemotePath)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	v6port := ln.Addr().(*net.TCPAddr).Port

	off := step11RulePolicy()
	off.IPv6 = routecfg.IPv6Off
	off.Rules = nil
	hOff := startLeakHarness(t, off)
	if body, err := fetchE(hOff.mixedAddr, fmt.Sprintf("http://[::1]:%d/", v6port)); err == nil {
		t.Fatalf("ipv6 off: literal v6 fetch SUCCEEDED (body %q) — IPv6 traffic escaped the policy", body)
	}

	on := step11RulePolicy()
	on.IPv6 = routecfg.IPv6On
	on.Rules = nil
	hOn := startLeakHarness(t, on)
	body, err := fetchE(hOn.mixedAddr, fmt.Sprintf("http://[::1]:%d/", v6port))
	if err != nil {
		t.Fatalf("ipv6 on (control): literal v6 fetch failed: %v", err)
	}
	if !strings.HasPrefix(body, tokenRemotePath) {
		t.Fatalf("ipv6 on (control): unexpected body %q", body)
	}
}

// Fragment acceptance beyond the behavioural rig: policies
// exercising rule sets (inline + domain kind), a process_name
// rule (Windows-reserved matcher), a block rule and fake-ip
// must all be accepted by sing-box's own parser and start.
func TestStep11FragmentsAcceptedByKernel(t *testing.T) {
	variants := map[string]routecfg.Policy{}
	variants["rule-sets+process+block"] = routecfg.Policy{
		Mode: routecfg.ModeRule,
		RuleSets: []routecfg.RuleSetRef{
			{Tag: "ads-inline", Kind: routecfg.RuleSetKindDomain, Type: "inline",
				Inline: []routecfg.Match{{DomainSuffixes: []string{"ads.example"}}}},
		},
		Rules: []routecfg.Rule{
			{Match: routecfg.Match{RuleSets: []string{"ads-inline"}}, Action: routecfg.ActionBlock},
			{Match: routecfg.Match{ProcessNames: []string{"game.exe"}, Ports: []int{27015}}, Action: routecfg.ActionProxy},
			{Match: routecfg.Match{DomainKeywords: []string{"static"}}, Action: routecfg.ActionDirect},
		},
	}
	fake := step11RulePolicy()
	fake.DNS.FakeIP = true
	variants["fakeip"] = fake

	for name, policy := range variants {
		t.Run(name, func(t *testing.T) {
			// startLeakHarness overrides the DNS server
			// addresses with the rig's fake pair; for the
			// fakeip variant the fake server tag remains in
			// the compiled dns section, which is exactly the
			// part that needs kernel acceptance.
			h := startLeakHarness(t, policy)
			if h.mixedAddr == "" {
				t.Fatal("client instance did not start")
			}
		})
	}
}
