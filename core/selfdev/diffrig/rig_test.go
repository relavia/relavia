//go:build with_quic && with_utls && with_wireguard

package diffrig

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"openproxy/core/kernel"
	"openproxy/core/selfdev"
	"openproxy/core/selfdev/shadowsocks"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// --- rig plumbing -------------------------------------------------

var rigMethods = []struct {
	method   string
	password string
}{
	{"aes-128-gcm", "relavia-test-2017"},
	{"aes-256-gcm", "relavia-test-2017"},
	{"chacha20-ietf-poly1305", "relavia-test-2017"},
	{"xchacha20-ietf-poly1305", "relavia-test-2017"},
	{"2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="},
	{"2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
	{"2022-blake3-chacha20-poly1305", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s never came up", addr)
}

// startRustServer launches shadowsocks-rust's ssserver (server
// A). Skips loudly when the binary is unavailable.
func startRustServer(t *testing.T, method, password string) string {
	t.Helper()
	bin := os.Getenv("RELAVIA_SSSERVER")
	if bin == "" {
		bin, _ = exec.LookPath("ssserver")
	}
	if bin == "" {
		t.Skip("diffrig: ssserver (shadowsocks-rust) not found via RELAVIA_SSSERVER or PATH - server A leg skipped")
	}
	port := freePort(t)
	cfg := map[string]any{
		"server": "127.0.0.1", "server_port": port,
		"password": password, "method": method, "timeout": 30,
		// ssserver serves TCP only unless told otherwise.
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
		if t.Failed() {
			t.Logf("ssserver output:\n%s", out.String())
		}
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitPort(t, addr)
	return addr
}

func startBox(t *testing.T, cfg map[string]any) *box.Box {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(service.ContextWith(context.Background(),
		deprecated.NewStderrManager(log.StdLogger())))
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		t.Fatalf("parse box config: %v", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("create box: %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("start box: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

// startSingboxServer launches a sing-box Shadowsocks inbound
// (server B) with a direct outbound.
func startSingboxServer(t *testing.T, method, password string) string {
	t.Helper()
	port := freePort(t)
	startBox(t, map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{map[string]any{
			"type": "shadowsocks", "tag": "ss-in",
			"listen": "127.0.0.1", "listen_port": port,
			"method": method, "password": password,
			"network": []string{"tcp", "udp"},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitPort(t, addr)
	return addr
}

// startSingboxClient launches a sing-box box whose mixed
// inbound routes through a Shadowsocks outbound to the server
// under test (the control client's data plane).
func startSingboxClient(t *testing.T, serverAddr, method, password string) string {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(serverAddr)
	var serverPort int
	fmt.Sscanf(portStr, "%d", &serverPort)
	port := freePort(t)
	startBox(t, map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "in",
			"listen": "127.0.0.1", "listen_port": port,
		}},
		"outbounds": []any{
			map[string]any{
				"type": "shadowsocks", "tag": "ss-out",
				"server": host, "server_port": serverPort,
				"method": method, "password": password,
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "ss-out"},
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitPort(t, addr)
	return addr
}

// startEchoTCP starts a TCP echo server and returns its
// address.
func startEchoTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i) ^ byte(i>>8) ^ seed
	}
	return out
}

func parseAddr(t *testing.T, addr string) shadowsocks.Addr {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return shadowsocks.Addr{Host: host, Port: port}
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(p, "%d", &port)
	return h, port
}

// socks5Connect performs a minimal SOCKS5 CONNECT through a
// mixed inbound.
func socks5Connect(t *testing.T, socksAddr string, target shadowsocks.Addr) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 0x05 {
		t.Fatalf("socks greeting: %v %x", err, buf)
	}
	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(target.Host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else {
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
	if head[1] != 0x00 {
		t.Fatalf("socks connect reply code %d", head[1])
	}
	switch head[3] {
	case 0x01:
		_, _ = io.ReadFull(c, make([]byte, 4+2))
	case 0x03:
		lb := make([]byte, 1)
		_, _ = io.ReadFull(c, lb)
		_, _ = io.ReadFull(c, make([]byte, int(lb[0])+2))
	case 0x04:
		_, _ = io.ReadFull(c, make([]byte, 16+2))
	}
	return c
}

func echoRoundTrip(t *testing.T, conn net.Conn, payload []byte) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	return got
}

var nodeSeq int

func ssSpecNode(id, serverAddr, method, password string) *specnode.Node {
	host, port := hostPort(serverAddr)
	nodeSeq++
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            fmt.Sprintf("00000000-0000-4000-8000-%012d", nodeSeq),
		Name:          id,
		Protocol:      "shadowsocks",
		Server:        host, Port: port,
		Source:      specnode.SourceRef{Kind: "manual", Ref: "diffrig", Authorization: "user-provided"},
		Shadowsocks: &specnode.CredShadowsocks{Method: method, Password: password},
	}
}

// rustUnsupported records methods shadowsocks-rust v1.25.0 does
// not implement at all: the rust leg of the rig cannot run for
// them (a property of the reference, verified from its own
// "unsupported method" error), and the sing-box-inbound leg
// carries the interop evidence instead.
var rustUnsupported = map[string]string{
	"xchacha20-ietf-poly1305": "shadowsocks-rust v1.25.0 does not implement AEAD-2017 xchacha20-ietf-poly1305",
}

// --- G1/G2: interop + plaintext layers ----------------------------

func TestRigInteropTCP(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probe.Close()

	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)
	payloads := [][]byte{pattern(100, 0x21), pattern(64*1024, 0x37)}

	servers := []struct {
		name  string
		start func(t *testing.T, method, password string) string
	}{
		{"rust", startRustServer},
		{"singbox-inbound", startSingboxServer},
	}
	for _, srv := range servers {
		for _, m := range rigMethods {
			t.Run(srv.name+"/"+m.method, func(t *testing.T) {
				if srv.name == "rust" {
					if why, ok := rustUnsupported[m.method]; ok {
						t.Skip("diffrig: " + why)
					}
				}
				serverAddr := srv.start(t, m.method, m.password)
				node := ssSpecNode("rig", serverAddr, m.method, m.password)
				ctx := context.Background()

				// Result layer: self-developed probe and the
				// sing-box control probe must both succeed
				// against the same server and node parameters.
				sb := singbox.New(singbox.Options{ProbeURL: probe.URL})
				comp := selfdev.New(sb, selfdev.Options{Policy: selfdev.PolicySelfdev, ProbeURL: probe.URL})
				res, err := comp.TestHandshakeNode(ctx, node)
				if err != nil {
					t.Fatalf("selfdev probe error: %v", err)
				}
				if !res.OK {
					t.Fatalf("selfdev probe failed: %v", res.Error)
				}
				ctrl, err := sb.TestHandshakeNode(ctx, node)
				if err != nil {
					t.Fatalf("control probe error: %v", err)
				}
				if !ctrl.OK {
					t.Fatalf("control probe failed: %v", ctrl.Error)
				}
				t.Logf("latency selfdev=%v control=%v", res.Latency, ctrl.Latency)

				// Plaintext layer: identical payloads through
				// both clients must come back byte-identical
				// from the echo target.
				client, err := shadowsocks.NewClient(m.method, m.password)
				if err != nil {
					t.Fatal(err)
				}
				socksAddr := startSingboxClient(t, serverAddr, m.method, m.password)
				for i, payload := range payloads {
					conn, err := client.DialTCP(ctx, serverAddr, echoTarget)
					if err != nil {
						t.Fatalf("selfdev dial payload %d: %v", i, err)
					}
					got := echoRoundTrip(t, conn, payload)
					_ = conn.Close()
					if !bytes.Equal(got, payload) {
						t.Fatalf("selfdev echo payload %d corrupted", i)
					}
					sc := socks5Connect(t, socksAddr, echoTarget)
					gotCtrl := echoRoundTrip(t, sc, payload)
					_ = sc.Close()
					if !bytes.Equal(gotCtrl, payload) {
						t.Fatalf("control echo payload %d corrupted", i)
					}
				}
			})
		}
	}
}

// --- G2 (UDP): packet echo through both reference servers --------

func udpEchoServer(t *testing.T) (string, bool) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Logf("diffrig: UDP loopback unavailable (%v) - UDP legs skip here and run in CI", err)
		return "", false
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	// Listening is not enough: some sandboxes accept the
	// listener but block the datagrams themselves (EPERM on
	// send). Probe a real plain-UDP round trip; only a working
	// probe lets the UDP legs run, so a skip here is an
	// environment statement, never a silent pass.
	addr := pc.LocalAddr().String()
	probe, err := net.Dial("udp", addr)
	if err != nil {
		t.Logf("diffrig: UDP probe dial failed (%v) - UDP legs skip here and run in CI", err)
		return "", false
	}
	defer probe.Close()
	_ = probe.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := probe.Write([]byte("diffrig-udp-probe")); err != nil {
		t.Logf("diffrig: UDP probe write failed (%v) - environment blocks UDP loopback; legs skip here and run in CI", err)
		return "", false
	}
	buf := make([]byte, 64)
	if _, err := probe.Read(buf); err != nil {
		t.Logf("diffrig: UDP probe read failed (%v) - environment blocks UDP loopback; legs skip here and run in CI", err)
		return "", false
	}
	return addr, true
}

func TestRigInteropUDP(t *testing.T) {
	echoAddrStr, ok := udpEchoServer(t)
	if !ok {
		t.Skip("UDP loopback unavailable in this environment")
	}
	echoTarget := parseAddr(t, echoAddrStr)
	payload := pattern(512, 0x51)

	servers := []struct {
		name  string
		start func(t *testing.T, method, password string) string
	}{
		{"rust", startRustServer},
		{"singbox-inbound", startSingboxServer},
	}
	for _, srv := range servers {
		for _, m := range rigMethods {
			t.Run(srv.name+"/"+m.method, func(t *testing.T) {
				if srv.name == "rust" {
					if why, ok := rustUnsupported[m.method]; ok {
						t.Skip("diffrig: " + why)
					}
				}
				serverAddr := srv.start(t, m.method, m.password)
				client, err := shadowsocks.NewClient(m.method, m.password)
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				pc, err := client.DialUDP(ctx, serverAddr)
				if err != nil {
					t.Fatalf("dial udp: %v", err)
				}
				defer pc.Close()
				_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := pc.WriteTo(payload, echoTarget); err != nil {
					t.Fatalf("write: %v", err)
				}
				buf := make([]byte, 4096)
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				if addr != echoTarget || !bytes.Equal(buf[:n], payload) {
					t.Fatalf("echo mismatch: addr=%v bytes=%d", addr, n)
				}
			})
		}
	}
}

// --- G3: structural layer (fixed-salt wire bytes) -----------------

// captureRelay proxies TCP to the real server while recording
// the client->server byte stream.
//
// Recording is authoritative and independent of forwarding:
// every byte read from the client is appended to the capture
// BEFORE it is forwarded, and forwarding is best-effort - if
// the server tears the connection down mid-stream (its target
// side closed, its session ended), the relay keeps draining
// the client to EOF instead of aborting the copy. The earlier
// shape (io.Copy through a MultiWriter with the upstream
// first) coupled the two: a failed upstream write discarded
// the batch it carried and ended the capture, truncating it
// at a chunk boundary - 88 bytes (prologue only) or 16505 of
// 16639 in TestRigStructural2022, depending on when the
// server closed (CI run 45136593588; record section 4.7).
// The client had produced every byte; the recorder dropped
// them.
type captureRelay struct {
	upstream string
	buf      bytes.Buffer
	done     chan struct{}
}

func startCaptureRelay(t *testing.T, upstream string) (string, *captureRelay) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &captureRelay{upstream: upstream, done: make(chan struct{})}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		defer close(r.done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		defer up.Close()
		go func() { _, _ = io.Copy(c, up) }()
		chunk := make([]byte, 32*1024)
		upDead := false
		for {
			n, rerr := c.Read(chunk)
			if n > 0 {
				r.buf.Write(chunk[:n])
				if !upDead {
					if _, werr := up.Write(chunk[:n]); werr != nil {
						upDead = true
					}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	return l.Addr().String(), r
}

func loadVector(t *testing.T, id string) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../shadowsocks/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Vectors []struct {
			ID       string         `json:"id"`
			Inputs   map[string]any `json:"inputs"`
			Expected map[string]any `json:"expected"`
		} `json:"vectors"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&vf); err != nil {
		t.Fatal(err)
	}
	for _, v := range vf.Vectors {
		if v.ID == id {
			out := map[string]any{}
			for k, val := range v.Inputs {
				out["in."+k] = val
			}
			for k, val := range v.Expected {
				out["exp."+k] = val
			}
			return out
		}
	}
	t.Fatalf("vector %s not found", id)
	return nil
}

func hexField(t *testing.T, v map[string]any, key string) []byte {
	t.Helper()
	s, _ := v[key].(string)
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("field %s: %v", key, err)
	}
	return b
}

func TestRigStructural2017(t *testing.T) {
	v := loadVector(t, "W17-01")
	serverAddr := startRustServer(t, "aes-256-gcm", "relavia-test-2017")
	relayAddr, relay := startCaptureRelay(t, serverAddr)

	client, err := shadowsocks.NewClient("aes-256-gcm", "relavia-test-2017",
		shadowsocks.WithRand(bytes.NewReader(hexField(t, v, "in.salt"))))
	if err != nil {
		t.Fatal(err)
	}
	target := shadowsocks.Addr{Host: "93.184.216.34", Port: 80}
	conn, err := client.DialTCP(context.Background(), relayAddr, target)
	if err != nil {
		t.Fatal(err)
	}
	payload := hexField(t, v, "in.payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-relay.done
	want := hexField(t, v, "exp.requestStream")
	if !bytes.Equal(relay.buf.Bytes(), want) {
		t.Fatalf("structural mismatch: captured %d bytes, vector %d bytes", relay.buf.Len(), len(want))
	}
}

func TestRigStructural2022(t *testing.T) {
	v := loadVector(t, "W22-05a")
	serverAddr := startRustServer(t, "2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	relayAddr, relay := startCaptureRelay(t, serverAddr)

	// Deterministic rand stream for the engine: salt (32) ||
	// padding-length draw (0x0003 -> 3%900+1 = 4) || padding.
	salt := hexField(t, v, "in.salt")
	padding := hexField(t, v, "in.padding")
	randStream := append(append(append([]byte{}, salt...), 0x00, 0x03), padding...)
	ts := int64(1700000000)
	client, err := shadowsocks.NewClient("2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		shadowsocks.WithRand(bytes.NewReader(randStream)),
		shadowsocks.WithClock(func() time.Time { return time.Unix(ts, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	target := shadowsocks.Addr{Host: "93.184.216.34", Port: 80}
	conn, err := client.DialTCP(context.Background(), relayAddr, target)
	if err != nil {
		t.Fatal(err)
	}
	payload := hexField(t, v, "in.payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-relay.done
	want := hexField(t, v, "exp.requestStream")
	if !bytes.Equal(relay.buf.Bytes(), want) {
		t.Fatalf("structural mismatch: captured %d bytes, vector %d bytes", relay.buf.Len(), len(want))
	}
}

// --- G4: error classification layer --------------------------------

func errClass(err *kernel.Error) string {
	if err == nil {
		return "ok"
	}
	switch err.Kind {
	case kernel.KindInvalidConfig, kernel.KindUnsupported:
		return "config"
	case kernel.KindNetwork:
		return "network"
	default:
		return "handshake"
	}
}

func TestRigErrorLayer(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probe.Close()
	ctx := context.Background()

	for _, m := range []struct{ method, password string }{
		{"aes-256-gcm", "relavia-test-2017"},
		{"2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
	} {
		t.Run("wrong-password/"+m.method, func(t *testing.T) {
			serverAddr := startRustServer(t, m.method, m.password)
			node := ssSpecNode("rig", serverAddr, m.method, "wrong-"+m.password)
			if m.method[:4] == "2022" {
				node = ssSpecNode("rig", serverAddr, m.method, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			}
			sb := singbox.New(singbox.Options{ProbeURL: probe.URL})
			comp := selfdev.New(sb, selfdev.Options{Policy: selfdev.PolicySelfdev, ProbeURL: probe.URL})
			res, err := comp.TestHandshakeNode(ctx, node)
			if err != nil {
				t.Fatalf("selfdev probe go-error: %v", err)
			}
			ctrl, err := sb.TestHandshakeNode(ctx, node)
			if err != nil {
				// Adjudicated control quirk: when the server
				// silently drops wrong-password traffic, the
				// sing-box probe surfaces its own internal
				// probe timeout as a Go error instead of a
				// failed result. The outcome (handshake
				// failure) is identical to the self-developed
				// result, so normalize it to one for the
				// classification comparison and record the
				// quirk in the run log.
				if err != context.DeadlineExceeded {
					t.Fatalf("control probe go-error: %v", err)
				}
				t.Logf("control probe reported its timeout as a Go error (sing-box quirk, adjudicated as handshake failure)")
				ctrl = &kernel.HandshakeResult{NodeID: node.ID, OK: false,
					Error: kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake", "probe timeout (control quirk)", err)}
			}
			if res.OK || ctrl.OK {
				t.Fatalf("wrong password accepted: selfdev=%v control=%v", res.OK, ctrl.OK)
			}
			if errClass(res.Error) != errClass(ctrl.Error) {
				t.Fatalf("error class mismatch: selfdev=%s (%v) control=%s (%v)",
					errClass(res.Error), res.Error, errClass(ctrl.Error), ctrl.Error)
			}
		})
		t.Run("server-down/"+m.method, func(t *testing.T) {
			node := ssSpecNode("rig", fmt.Sprintf("127.0.0.1:%d", freePort(t)), m.method, m.password)
			sb := singbox.New(singbox.Options{ProbeURL: probe.URL})
			comp := selfdev.New(sb, selfdev.Options{Policy: selfdev.PolicySelfdev, ProbeURL: probe.URL})
			res, err := comp.TestHandshakeNode(ctx, node)
			if err != nil {
				t.Fatalf("selfdev probe go-error: %v", err)
			}
			ctrl, err := sb.TestHandshakeNode(ctx, node)
			if err != nil {
				t.Fatalf("control probe go-error: %v", err)
			}
			if res.OK || ctrl.OK {
				t.Fatalf("dead server accepted: selfdev=%v control=%v", res.OK, ctrl.OK)
			}
			if errClass(res.Error) != errClass(ctrl.Error) {
				t.Fatalf("error class mismatch: selfdev=%s control=%s", errClass(res.Error), errClass(ctrl.Error))
			}
		})
	}
}

// --- G7: fallback drill ---------------------------------------------

func TestRigFallbackDrill(t *testing.T) {
	var logs []string
	sb := singbox.New(singbox.Options{})
	comp := selfdev.New(sb, selfdev.Options{
		Policy: selfdev.PolicyAuto,
		Logf:   func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	})
	// Node pointing at a dead server: the selfdev attempt fails,
	// the node is pinned, and the next decision point routes to
	// sing-box (recorded in the log) without a mid-connection
	// switch.
	node := ssSpecNode("drill", fmt.Sprintf("127.0.0.1:%d", freePort(t)), "aes-256-gcm", "pw")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := comp.TestHandshakeNode(ctx, node)
	if err != nil {
		t.Fatalf("first probe: %v", err)
	}
	if res.OK {
		t.Fatal("dead server probe must fail")
	}
	_, err = comp.TestHandshakeNode(ctx, node)
	if err != nil {
		t.Fatalf("second probe: %v", err)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "backend=selfdev") {
		t.Fatalf("first attempt not recorded as selfdev:\n%s", joined)
	}
	if !strings.Contains(joined, "pinned") {
		t.Fatalf("pin not recorded:\n%s", joined)
	}
	if !strings.Contains(joined, "backend=sing-box") {
		t.Fatalf("fallback at the next decision point not recorded:\n%s", joined)
	}
	// Ineligible nodes never touch the selfdev backend.
	pluginNode := ssSpecNode("drill2", node.Server+":"+fmt.Sprint(node.Port), "aes-256-gcm", "pw")
	pluginNode.Shadowsocks.Plugin = "obfs-local"
	logs = nil
	_, _ = comp.TestHandshakeNode(ctx, pluginNode)
	joined = strings.Join(logs, "\n")
	if strings.Contains(joined, "backend=selfdev") {
		t.Fatalf("plugin node routed to selfdev:\n%s", joined)
	}
	if !strings.Contains(joined, "plugin") {
		t.Fatalf("plugin routing reason not recorded:\n%s", joined)
	}
}

// --- G6: performance sentinel (logged, not auto-failed) ------------

func TestRigPerfSentinel(t *testing.T) {
	serverAddr := startRustServer(t, "aes-256-gcm", "relavia-test-2017")
	echoAddr := startEchoTCP(t)
	echoTarget := parseAddr(t, echoAddr)
	ctx := context.Background()
	payload := pattern(4<<20, 0x77)

	// Self-developed throughput.
	client, err := shadowsocks.NewClient("aes-256-gcm", "relavia-test-2017")
	if err != nil {
		t.Fatal(err)
	}
	measure := func(dial func() (net.Conn, error)) float64 {
		conn, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		start := time.Now()
		go func() { _, _ = conn.Write(payload) }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		return float64(len(payload)) / time.Since(start).Seconds() / (1 << 20)
	}
	median3 := func(f func() float64) float64 {
		vals := []float64{f(), f(), f()}
		for i := 0; i < 3; i++ {
			for j := i + 1; j < 3; j++ {
				if vals[j] < vals[i] {
					vals[i], vals[j] = vals[j], vals[i]
				}
			}
		}
		return vals[1]
	}
	selfMBs := median3(func() float64 {
		return measure(func() (net.Conn, error) { return client.DialTCP(ctx, serverAddr, echoTarget) })
	})
	socksAddr := startSingboxClient(t, serverAddr, "aes-256-gcm", "relavia-test-2017")
	ctrlMBs := median3(func() float64 {
		return measure(func() (net.Conn, error) { return socks5Connect(t, socksAddr, echoTarget), nil })
	})
	t.Logf("G6 sentinel (median of 3): selfdev=%.1f MiB/s control=%.1f MiB/s ratio=%.2f (gate: >=0.70, miss = analysis not auto-fail)",
		selfMBs, ctrlMBs, selfMBs/ctrlMBs)
}
