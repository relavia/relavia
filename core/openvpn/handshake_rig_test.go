package openvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// Handshake rig: a REAL OpenVPN server (test CA, TCP loopback)
// and the adapter as its client. Gated on RELAVIA_OPENVPN_RIG=1
// because it needs an openvpn binary (RELAVIA_OPENVPN_BIN or
// PATH). CI runs it in the dedicated openvpn-rig job.
//
// Device note: this sandbox (and typical CI) forbids creating a
// TUN device (TUNSETIFF returns EPERM) and blocks UDP outright,
// so the rig runs TCP with the null device + ifconfig-noexec on
// both ends — OpenVPN's own test-device form. The full TLS
// handshake, certificate authentication, tls-auth HMAC and
// data-channel key establishment all execute for real, and the
// management interface reports CONNECTED; what the null device
// cannot prove is payload traffic through a kernel TUN device
// (recorded as an environment-blocked item in
// docs/openvpn进程适配.md, with the EPERM evidence).

func rigEnabled(t *testing.T) string {
	t.Helper()
	if os.Getenv("RELAVIA_OPENVPN_RIG") != "1" {
		t.Skip("rig disabled: set RELAVIA_OPENVPN_RIG=1 (CI openvpn-rig job does)")
	}
	bin := os.Getenv("RELAVIA_OPENVPN_BIN")
	if bin == "" {
		p, err := exec.LookPath("openvpn")
		if err != nil {
			t.Fatalf("RELAVIA_OPENVPN_RIG=1 but no openvpn binary (set RELAVIA_OPENVPN_BIN): %v", err)
		}
		bin = p
	}
	return bin
}

type rigPKI struct {
	caPEM, serverCertPEM, serverKeyPEM string
	clientCertPEM, clientKeyPEM        string
	taKey                              string
	otherCAPEM                         string // untrusted CA for the negative case
}

func makeCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, eku []x509.ExtKeyUsage, ku x509.KeyUsage, serial int64) (certPEM, keyPEM string, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     ku,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, parsed, key
}

func makeCA(t *testing.T, cn string) (certPEM string, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, parsed, key
}

func staticKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 256)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(b)
	var sb strings.Builder
	sb.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 64 {
		sb.WriteString(h[i:i+64] + "\n")
	}
	sb.WriteString("-----END OpenVPN Static key V1-----\n")
	return sb.String()
}

func rigPKIGen(t *testing.T) *rigPKI {
	t.Helper()
	caPEM, ca, caKey := makeCA(t, "RigTestCA")
	otherCAPEM, _, _ := makeCA(t, "OtherCA")
	sCert, sKey, _, _ := makeCert(t, ca, caKey, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, 2)
	cCert, cKey, _, _ := makeCert(t, ca, caKey, "client1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, x509.KeyUsageDigitalSignature, 3)
	return &rigPKI{
		caPEM: caPEM, serverCertPEM: sCert, serverKeyPEM: sKey,
		clientCertPEM: cCert, clientKeyPEM: cKey,
		taKey: staticKey(t), otherCAPEM: otherCAPEM,
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func rigClientNode(pki *rigPKI, port int, caPEM string) *specnode.Node {
	dir := 1
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "33333333-3333-3333-3333-333333333333",
		Name:          "rig-client",
		Protocol:      specnode.ProtocolOpenVPN,
		Server:        "127.0.0.1",
		Port:          port,
		OpenVPN: &specnode.CredOpenVPN{
			Proto:        "tcp",
			DataCiphers:  "AES-256-GCM",
			CACert:       caPEM,
			ClientCert:   pki.clientCertPEM,
			ClientKey:    pki.clientKeyPEM,
			TLSAuthKey:   pki.taKey,
			KeyDirection: &dir,
		},
		Source: specnode.SourceRef{Kind: "manual", Ref: "rig", Authorization: "self"},
	}
}

func TestRigHandshakeAndLifecycle(t *testing.T) {
	bin := rigEnabled(t)
	pki := rigPKIGen(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	port := freePort(t)
	dev := os.Getenv("RELAVIA_OPENVPN_RIG_DEV")
	if dev == "" {
		dev = "null"
	}
	serverConf := fmt.Sprintf(`port %d
proto tcp-server
dev %s
tls-server
ca %s
cert %s
key %s
dh none
tls-auth %s 0
ifconfig 10.8.0.1 10.8.0.2
data-ciphers AES-256-GCM
keepalive 10 60
verb 4
`, port, dev,
		write("ca.crt", pki.caPEM), write("server.crt", pki.serverCertPEM),
		write("server.key", pki.serverKeyPEM), write("ta.key", pki.taKey))
	if dev == "null" {
		serverConf += "ifconfig-noexec\nroute-noexec\n"
	}
	confPath := write("server.conf", serverConf)

	var serverLog lockedBuffer
	srv := exec.Command(bin, "--config", confPath)
	srv.Stdout = &serverLog
	srv.Stderr = &serverLog
	if err := srv.Start(); err != nil {
		t.Fatalf("start rig server: %v", err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_ = srv.Wait()
	}()
	// Wait until the server accepts TCP connections.
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rig server never listened; log:\n%s", serverLog.String())
		}
		time.Sleep(150 * time.Millisecond)
	}

	a := New(Options{
		BinaryPath:      bin,
		ConnectTimeout:  30 * time.Second,
		DevOverride:     dev,
		ExtraDirectives: []string{"ifconfig 10.8.0.2 10.8.0.1"},
	})
	if dev == "null" {
		a.opts.ExtraDirectives = append(a.opts.ExtraDirectives, "ifconfig-noexec", "route-noexec")
	}
	ctx := context.Background()
	node := rigClientNode(pki, port, pki.caPEM)

	// 1. Real handshake through the adapter.
	res, err := a.TestHandshakeNode(ctx, node)
	if err != nil {
		t.Fatalf("TestHandshakeNode Go error: %v", err)
	}
	if !res.OK {
		t.Fatalf("handshake failed: %+v\nserver log:\n%s", res.Error, serverLog.String())
	}
	t.Logf("handshake OK, latency %s", res.Latency)
	if res.Latency <= 0 {
		t.Error("latency must be positive")
	}

	// 2. Full lifecycle: start, observe, traffic snapshot, stop.
	if err := a.StartNode(ctx, node, kernel.PlatformOptions{Mode: kernel.ModeTUN}); err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	if st := a.Status(); st.State != kernel.StateRunning {
		t.Fatalf("state = %v, want running", st.State)
	}
	traf, err := a.QueryTraffic(ctx)
	if err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	if traf.SessionStartedAt.IsZero() {
		t.Error("traffic snapshot must carry the session start time")
	}
	t.Logf("traffic while connected (null device, no payload possible): up=%d down=%d", traf.UploadBytes, traf.DownloadBytes)
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if st := a.Status(); st.State != kernel.StateStopped {
		t.Fatalf("state after stop = %v, want stopped", st.State)
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("second Stop must be a no-op: %v", err)
	}

	// 3. Negative: a client trusting a different CA must fail the
	// handshake, classified as a handshake failure (not a Go
	// error, not a success).
	bad := rigClientNode(pki, port, pki.otherCAPEM)
	res, err = a.TestHandshakeNode(ctx, bad)
	if err != nil {
		t.Fatalf("negative case must be a result, got Go error: %v", err)
	}
	if res.OK {
		t.Fatal("handshake with an untrusted CA must not succeed")
	}
	if res.Error == nil || !kernel.IsKind(res.Error, kernel.KindHandshakeFailed) {
		t.Fatalf("negative case error = %v, want handshake_failed", res.Error)
	}
	t.Logf("negative case classified: %v", res.Error)

	// 4. Server-side evidence: the server saw a full session.
	log := serverLog.String()
	for _, want := range []string{"Peer Connection Initiated", "Initialization Sequence Completed"} {
		if !strings.Contains(log, want) {
			t.Errorf("server log missing %q", want)
		}
	}
}
