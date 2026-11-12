//go:build with_quic && with_utls && with_wireguard

package singbox

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/proxy"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// Loopback acceptance tests for Step 7 (book ch.14: "first-tier
// protocols each at least one real node handshake succeeded, with
// test records"). No public node exists in the sandbox, so each
// protocol's server side is a real sing-box inbound started on
// loopback by this harness, and the client side is the adapter
// under test. A case passes only when (a) TestHandshakeNode
// reports OK with a measured latency, AND (b) after StartNode, an
// HTTP fetch through the adapter's mixed inbound returns the echo
// server's token body — i.e. a real handshake plus real forwarded
// data, both directions of the tunnel exercised.

const echoToken = "relavia-loopback-echo"

func startEchoServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", echoToken, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv.URL // http://127.0.0.1:PORT
}

func startRawInstance(t *testing.T, cfg map[string]any) {
	t.Helper()
	// Every instance gets its own cache file: sing-box 1.14
	// force-enables the cache file when a platform log writer is
	// present, and the shared default path deadlocks concurrent
	// instances on the bbolt file lock.
	cfg["experimental"] = map[string]any{
		"cache_file": map[string]any{
			"enabled": true,
			"path":    filepath.Join(t.TempDir(), "cache.db"),
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal server config: %v", err)
	}
	instance, _, err := startInstance(raw, platformLogWriter{})
	if err != nil {
		t.Fatalf("start server instance: %v\nconfig: %s", err, raw)
	}
	t.Cleanup(func() { _ = instance.Close() })
}

func serverBase(inbound map[string]any) map[string]any {
	return map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc tcp port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("alloc udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// writeTestCert creates a self-signed CA-style certificate valid
// for localhost / 127.0.0.1 and returns (certPath, keyPath).
func writeTestCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func x25519Pair(t *testing.T) (privB64URL, pubB64URL string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv), enc.EncodeToString(pub)
}

func wgKeyPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding
	return enc.EncodeToString(priv), enc.EncodeToString(pub)
}

// Environment probes for the UDP cases. The project sandbox
// blocks ALL UDP sends at syscall level (sendto/sendmsg and
// sendmmsg both return EPERM for every destination, loopback
// included — verified with raw syscall probes, see
// docs/step7-sing-box集成.md §握手记录). No UDP protocol
// handshake can physically leave the machine there, so the UDP
// cases probe first and, on such a host, skip WITH the evidence
// instead of burning minutes on timeouts misreported as protocol
// failures. On unrestricted hosts (the CI step added in Step 7
// runs on GitHub-hosted runners) the probes pass silently and
// every case executes in full.

// fetchBodyViaMixed fetches rawURL through the adapter's mixed
// inbound (SOCKS5) and returns the response body.
func fetchBodyViaMixed(t *testing.T, mixedAddr, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse echo url: %v", err)
	}
	dialer, err := proxy.SOCKS5("tcp", mixedAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	conn, err := dialer.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial through mixed inbound: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	return string(body[:n])
}

type loopbackCase struct {
	name  string
	setup func(t *testing.T) *specnode.Node
	// precheck, when set, runs before setup (e.g. environment
	// capability probes that may skip the case with evidence).
	precheck func(t *testing.T)
	// target, when set, rewrites the shared echo server's base
	// URL into the address this case must address THROUGH the
	// tunnel (probe and data fetch alike). Most protocols can
	// address the echo server by its loopback address directly;
	// WireGuard cannot (see the wireguard case comment).
	target func(echoURL string) string
}

// probeUDPSend skips the calling case when this environment
// forbids sending UDP datagrams at all (EPERM on a plain
// loopback sendto).
func probeUDPSend(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("probe"), conn.LocalAddr()); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "not implemented") {
			t.Skipf("environment blocks UDP sends (%v): no UDP handshake can leave this host — case environment-blocked, re-run on an unrestricted host (CI step runs it)", err)
		}
		t.Logf("UDP probe error (non-blocking signature, continuing): %v", err)
	}
}

// probeWireGuard additionally requires the sendmmsg batch
// syscall that the WireGuard UDP bind (x/net batch API, same
// code path as wireguard-go) sends through.
func probeWireGuard(t *testing.T) {
	t.Helper()
	probeUDPSend(t)
	probeSendmmsg(t)
}

// probeSendmmsg reports whether this environment permits the
// sendmmsg syscall. On a host that rejects it (EPERM/ENOSYS) the
// WireGuard case cannot run and is skipped WITH the evidence,
// while on unrestricted hosts (CI) it executes fully.
func probeSendmmsg(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	defer conn.Close()
	pc := ipv4.NewPacketConn(conn)
	msgs := []ipv4.Message{{
		Buffers: [][]byte{[]byte("probe")},
		Addr:    conn.LocalAddr(),
	}}
	_, err = pc.WriteBatch(msgs, 0)
	if err == nil {
		return // sendmmsg works here
	}
	msg := err.Error()
	if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "not implemented") {
		t.Skipf("environment blocks sendmmsg (%v): the WireGuard bind cannot send UDP in this sandbox — case environment-blocked, re-run on an unrestricted host (CI step runs it)", err)
	}
	t.Logf("sendmmsg probe error (non-blocking signature, continuing): %v", err)
}

func TestLoopbackHandshakes(t *testing.T) {
	echoURL := startEchoServer(t)
	certPath, keyPath := writeTestCert(t)
	const testUUID = "20000000-0000-4000-8000-0000000000aa"

	cases := []loopbackCase{
		{
			name: "shadowsocks-2022",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
				startRawInstance(t, serverBase(map[string]any{
					"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
					"method": "2022-blake3-aes-256-gcm", "password": key,
				}))
				n := baseNode(specnode.ProtocolShadowsocks)
				n.Port = port
				n.Shadowsocks = &specnode.CredShadowsocks{Method: "2022-blake3-aes-256-gcm", Password: key}
				return n
			},
		},
		{
			name: "shadowsocks-aes128-gcm",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
					"method": "aes-128-gcm", "password": "loopback-pw",
				}))
				n := baseNode(specnode.ProtocolShadowsocks)
				n.Port = port
				n.Shadowsocks = &specnode.CredShadowsocks{Method: "aes-128-gcm", Password: "loopback-pw"}
				return n
			},
		},
		{
			name: "trojan-tls",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "trojan", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"password": "trojan-pw"}},
					"tls":   map[string]any{"enabled": true, "server_name": "localhost", "certificate_path": certPath, "key_path": keyPath},
				}))
				n := baseNode(specnode.ProtocolTrojan)
				n.Port = port
				n.Trojan = &specnode.CredTrojan{Password: "trojan-pw"}
				n.Security = &specnode.Security{Type: "tls", ServerName: "localhost", AllowInsecure: true}
				return n
			},
		},
		{
			name: "trojan-ws-tls",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "trojan", "listen": "127.0.0.1", "listen_port": port,
					"users":     []any{map[string]any{"password": "trojan-pw"}},
					"tls":       map[string]any{"enabled": true, "server_name": "localhost", "certificate_path": certPath, "key_path": keyPath},
					"transport": map[string]any{"type": "ws", "path": "/ws"},
				}))
				n := baseNode(specnode.ProtocolTrojan)
				n.Port = port
				n.Trojan = &specnode.CredTrojan{Password: "trojan-pw"}
				n.Transport = &specnode.Transport{Type: "ws", Path: "/ws"}
				n.Security = &specnode.Security{Type: "tls", ServerName: "localhost", AllowInsecure: true}
				return n
			},
		},
		{
			name: "vmess-tcp",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "vmess", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"uuid": testUUID}},
				}))
				n := baseNode(specnode.ProtocolVMess)
				n.Port = port
				n.VMess = &specnode.CredVMess{UUID: testUUID, Cipher: "auto"}
				return n
			},
		},
		{
			name: "vmess-grpc-tls",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "vmess", "listen": "127.0.0.1", "listen_port": port,
					"users":     []any{map[string]any{"uuid": testUUID}},
					"tls":       map[string]any{"enabled": true, "server_name": "localhost", "certificate_path": certPath, "key_path": keyPath},
					"transport": map[string]any{"type": "grpc", "service_name": "loopback-svc"},
				}))
				n := baseNode(specnode.ProtocolVMess)
				n.Port = port
				n.VMess = &specnode.CredVMess{UUID: testUUID, Cipher: "auto"}
				n.Transport = &specnode.Transport{Type: "grpc", ServiceName: "loopback-svc"}
				n.Security = &specnode.Security{Type: "tls", ServerName: "localhost", AllowInsecure: true}
				return n
			},
		},
		{
			name: "vless-tcp-plain",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "vless", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"uuid": testUUID}},
				}))
				n := baseNode(specnode.ProtocolVLESS)
				n.Port = port
				n.VLESS = &specnode.CredVLESS{UUID: testUUID}
				return n
			},
		},
		{
			name: "vless-reality-vision",
			setup: func(t *testing.T) *specnode.Node {
				// Reality camouflage destination: a local TLS
				// server (httptest) whose certificate Reality
				// borrows during handshakes.
				dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				t.Cleanup(dest.Close)
				destPort := dest.Listener.Addr().(*net.TCPAddr).Port

				priv, pub := x25519Pair(t)
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "vless", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"uuid": testUUID, "flow": "xtls-rprx-vision"}},
					"tls": map[string]any{
						"enabled":     true,
						"server_name": "example.com",
						"reality": map[string]any{
							"enabled":     true,
							"handshake":   map[string]any{"server": "127.0.0.1", "server_port": destPort},
							"private_key": priv,
							"short_id":    []string{"0123abcd"},
						},
					},
				}))
				n := baseNode(specnode.ProtocolVLESS)
				n.Port = port
				n.VLESS = &specnode.CredVLESS{UUID: testUUID, Flow: "xtls-rprx-vision"}
				n.Security = &specnode.Security{
					Type: "reality", ServerName: "example.com",
					PublicKey: pub, ShortID: "0123abcd", Fingerprint: "chrome",
				}
				return n
			},
		},
		{
			name:     "hysteria2-salamander",
			precheck: probeUDPSend,
			setup: func(t *testing.T) *specnode.Node {
				port := freeUDPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"password": "hy2-auth"}},
					"obfs":  map[string]any{"type": "salamander", "password": "hy2-obfs"},
					"tls":   map[string]any{"enabled": true, "server_name": "localhost", "certificate_path": certPath, "key_path": keyPath},
				}))
				n := baseNode(specnode.ProtocolHysteria2)
				n.Port = port
				n.Hysteria2 = &specnode.CredHysteria2{Auth: "hy2-auth", ObfsType: "salamander", ObfsPassword: "hy2-obfs"}
				n.Security = &specnode.Security{Type: "tls", ServerName: "localhost", AllowInsecure: true, ALPN: []string{"h3"}}
				return n
			},
		},
		{
			name:     "tuic-v5",
			precheck: probeUDPSend,
			setup: func(t *testing.T) *specnode.Node {
				port := freeUDPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "tuic", "listen": "127.0.0.1", "listen_port": port,
					"users":              []any{map[string]any{"uuid": testUUID, "password": "tuic-pw"}},
					"congestion_control": "bbr",
					"tls":                map[string]any{"enabled": true, "server_name": "localhost", "certificate_path": certPath, "key_path": keyPath, "alpn": []string{"h3"}},
				}))
				n := baseNode(specnode.ProtocolTUIC)
				n.Port = port
				n.TUIC = &specnode.CredTUIC{UUID: testUUID, Password: "tuic-pw"}
				n.Transport = &specnode.Transport{Type: "quic", CongestionControl: "bbr", UDPRelayMode: "native"}
				n.Security = &specnode.Security{Type: "tls", ServerName: "localhost", AllowInsecure: true, ALPN: []string{"h3"}}
				return n
			},
		},
		{
			name:     "wireguard",
			precheck: probeWireGuard,
			// Through the tunnel this case must address the echo
			// server as 10.66.66.1 (the server endpoint's own
			// tunnel address), NOT as 127.0.0.1. Root cause,
			// from the sing-box 1.14 sources: a non-system
			// WireGuard endpoint feeds decapsulated packets
			// into an embedded gVisor stack
			// (transport/wireguard/device_stack.go), and
			// gVisor's IPv4 receive path drops any packet with
			// a loopback source or destination arriving on a
			// non-loopback NIC as a "martian" packet
			// (gvisor pkg/tcpip/network/ipv4 HandlePacket,
			// AllowExternalLoopbackTraffic unset). With a
			// loopback tunnel target the server's TCP
			// forwarder therefore never sees the connection
			// and the probe starves until the context deadline
			// — exactly the first CI run's failure (60s
			// timeout, martian drop in the log). Addressing
			// the endpoint's tunnel address instead is the
			// stack's designed path: the protocol endpoint
			// rewrites destinations inside its local addresses
			// to 127.0.0.1 before routing
			// (protocol/wireguard/endpoint.go NewConnectionEx),
			// so the server still dials the same loopback echo
			// server via its direct outbound, while the packet
			// inside the tunnel carries a plain unicast
			// destination. The assertions are unchanged: a
			// real WireGuard handshake must still complete
			// before any data flows, the HTTP body must still
			// round-trip through the tunnel, and the traffic
			// counters must still move.
			target: func(echoURL string) string {
				u, err := url.Parse(echoURL)
				if err != nil {
					return echoURL
				}
				return "http://10.66.66.1:" + u.Port()
			},
			setup: func(t *testing.T) *specnode.Node {
				serverPriv, serverPub := wgKeyPair(t)
				clientPriv, clientPub := wgKeyPair(t)
				port := freeUDPPort(t)
				cfg := map[string]any{
					"log": map[string]any{"level": "error"},
					"endpoints": []any{map[string]any{
						"type": "wireguard", "tag": "wg-in",
						"address":     []string{"10.66.66.1/32"},
						"private_key": serverPriv,
						"listen_port": port,
						"peers": []any{map[string]any{
							"public_key":  clientPub,
							"allowed_ips": []string{"10.66.66.2/32"},
						}},
					}},
					"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
					"route":     map[string]any{"final": "direct"},
				}
				startRawInstance(t, cfg)

				n := baseNode(specnode.ProtocolWireGuard)
				n.Port = port
				n.WireGuard = &specnode.CredWireGuard{
					PrivateKey:    clientPriv,
					PeerPublicKey: serverPub,
					Addresses:     []string{"10.66.66.2/32"},
					AllowedIPs:    []string{"0.0.0.0/0"},
				}
				return n
			},
		},
		{
			name: "socks5-userpass",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "socks", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"username": "alice", "password": "socks-pw"}},
				}))
				n := baseNode(specnode.ProtocolSOCKS5)
				n.Port = port
				n.UserPass = &specnode.CredUserPass{Username: "alice", Password: "socks-pw"}
				return n
			},
		},
		{
			name: "http-proxy-userpass",
			setup: func(t *testing.T) *specnode.Node {
				port := freeTCPPort(t)
				startRawInstance(t, serverBase(map[string]any{
					"type": "http", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"username": "bob", "password": "http-pw"}},
				}))
				n := baseNode(specnode.ProtocolHTTP)
				n.Port = port
				n.UserPass = &specnode.CredUserPass{Username: "bob", Password: "http-pw"}
				return n
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.precheck != nil {
				tc.precheck(t)
			}
			node := tc.setup(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			targetBase := echoURL
			if tc.target != nil {
				targetBase = tc.target(echoURL)
			}
			adapter := New(Options{ProbeURL: targetBase + "/probe"})

			res, err := adapter.TestHandshakeNode(ctx, node)
			if err != nil {
				t.Fatalf("TestHandshakeNode returned Go error: %v", err)
			}
			if !res.OK {
				t.Fatalf("handshake failed: %v", res.Error)
			}
			if res.Latency <= 0 {
				t.Fatalf("handshake latency not measured: %v", res.Latency)
			}
			t.Logf("handshake ok, latency %v", res.Latency)

			if err := adapter.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
				t.Fatalf("StartNode: %v", err)
			}
			defer adapter.Stop(ctx)
			body := fetchBodyViaMixed(t, adapter.MixedAddr(), targetBase+"/data")
			if !strings.Contains(body, echoToken) {
				t.Fatalf("data path body = %q, want echo token", body)
			}
			// Traffic counters must reflect the fetched data.
			deadline := time.Now().Add(3 * time.Second)
			for {
				ts, err := adapter.QueryTraffic(ctx)
				if err != nil {
					t.Fatalf("QueryTraffic: %v", err)
				}
				if ts.DownloadBytes > 0 && ts.UploadBytes > 0 {
					t.Logf("traffic up=%d down=%d", ts.UploadBytes, ts.DownloadBytes)
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("traffic counters stayed zero: %+v", ts)
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}

// Negative control: a wrong Shadowsocks password must produce a
// FAILED handshake result (not a vacuous pass, not a Go error),
// proving TestHandshake performs the real protocol handshake.
func TestLoopbackWrongPasswordFails(t *testing.T) {
	echoURL := startEchoServer(t)
	port := freeTCPPort(t)
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	startRawInstance(t, serverBase(map[string]any{
		"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
		"method": "2022-blake3-aes-256-gcm", "password": key,
	}))

	n := baseNode(specnode.ProtocolShadowsocks)
	n.Port = port
	wrongKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	n.Shadowsocks = &specnode.CredShadowsocks{Method: "2022-blake3-aes-256-gcm", Password: wrongKey}

	adapter := New(Options{ProbeURL: echoURL})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := adapter.TestHandshakeNode(ctx, n)
	if err != nil {
		t.Fatalf("Go error = %v, want handshake-failed result", err)
	}
	if res.OK {
		t.Fatal("handshake with wrong password reported OK — handshake is not real")
	}
	if res.Error == nil || res.Error.Kind != kernel.KindHandshakeFailed {
		t.Fatalf("result error = %v, want kind handshake_failed", res.Error)
	}
}
