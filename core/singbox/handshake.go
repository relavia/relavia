package singbox

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// TestHandshake: a REAL protocol handshake, per book 5.3 (no ICMP
// ping substitution). The adapter starts a throwaway sing-box
// instance whose only outbound is the node under test, then
// fetches Options.ProbeURL through the instance's mixed inbound
// over a hand-rolled SOCKS5 negotiation. Success therefore proves
// the full chain: local SOCKS5 negotiation -> sing-box outbound ->
// the node's protocol handshake with its server -> return data
// path carrying an HTTP response.
//
// A failed handshake is reported in the HandshakeResult (Go error
// nil), exactly as the interface contract requires; Go errors are
// reserved for tests that cannot run (invalid node, unsupported
// combination, context cancellation).

const defaultProbeTimeout = 20 * time.Second

// TestHandshake implements kernel.Adapter (placeholder node path).
func (a *Adapter) TestHandshake(ctx context.Context, node *kernel.Node) (*kernel.HandshakeResult, error) {
	if err := kernel.ValidateNode(node); err != nil {
		return nil, err
	}
	if !a.caps.SupportsNode(node) {
		return nil, kernel.NewError(kernel.KindUnsupported, "TestHandshake",
			"combination not supported by this kernel", nil)
	}
	spec := specnode.FromKernel(node)
	if err := checkSupported(spec); err != nil {
		return nil, err
	}
	if err := checkCompileInputs(spec); err != nil {
		return nil, err
	}
	return a.testHandshake(ctx, spec, node.ID)
}

// TestHandshakeNode is the full-fidelity entry point for
// unified-model nodes.
func (a *Adapter) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	if err := a.ValidateSpec(ctx, n); err != nil {
		return nil, err
	}
	return a.testHandshake(ctx, n, n.ID)
}

func (a *Adapter) testHandshake(ctx context.Context, n *specnode.Node, nodeID string) (*kernel.HandshakeResult, error) {
	res := &kernel.HandshakeResult{NodeID: nodeID, TestedAt: time.Now()}

	port, err := allocateLoopbackPort(a.opts.ListenHost)
	if err != nil {
		return nil, kernel.NewError(kernel.KindNetwork, "TestHandshake", "allocate mixed inbound port", err)
	}
	dir, err := os.MkdirTemp("", "relavia-singbox-probe-*")
	if err != nil {
		return nil, kernel.NewError(kernel.KindInternal, "TestHandshake", "create probe temp dir", err)
	}
	configJSON, err := compileConfig(n, compileOptions{
		listenHost: a.opts.ListenHost,
		listenPort: port,
		logLevel:   "error", // probes stay quiet unless OnLog debugging matters elsewhere
		cachePath:  filepath.Join(dir, "cache.db"),
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, kernel.NewError(kernel.KindInternal, "TestHandshake", "compile configuration", err)
	}
	instance, _, err := startInstance(configJSON, a.platformLogWriter())
	if err != nil {
		_ = os.RemoveAll(dir)
		// The kernel itself rejected the run (bad keys, bind
		// conflicts, feature not compiled in). The handshake
		// could not take place: report as a failed handshake
		// with the cause attached for diagnosis.
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake",
			"kernel instance failed to start for handshake test", err)
		return res, nil
	}
	defer func() {
		_ = instance.Close()
		_ = os.RemoveAll(dir)
	}()

	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultProbeTimeout)
		defer cancel()
	}

	start := time.Now()
	status, err := fetchViaSOCKS5(ctx, net.JoinHostPort(a.opts.ListenHost, fmt.Sprint(port)), a.opts.ProbeURL)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake",
			"probe through node failed", err)
		return res, nil
	}
	res.OK = true
	res.Latency = time.Since(start)
	_ = status // any well-formed HTTP response proves the data path; the code itself is the probe target's business
	return res, nil
}

// fetchViaSOCKS5 performs a minimal SOCKS5 CONNECT negotiation
// against a mixed inbound and then a plain HTTP/1.1 GET, returning
// the response status code. Hand-rolled (instead of x/net/proxy)
// so the probe has zero behavioural dependencies beyond the
// kernel under test.
func fetchViaSOCKS5(ctx context.Context, mixedAddr, rawURL string) (int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, fmt.Errorf("parse probe url: %w", err)
	}
	if u.Scheme != "http" {
		return 0, fmt.Errorf("probe url scheme %q not supported (http only)", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", mixedAddr)
	if err != nil {
		return 0, fmt.Errorf("dial mixed inbound: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Greeting: version 5, one method (no-auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return 0, fmt.Errorf("socks greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return 0, fmt.Errorf("socks greeting reply: %w", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		return 0, fmt.Errorf("socks greeting rejected: %v", greeting)
	}

	// CONNECT request.
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return 0, fmt.Errorf("probe host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	pnum, _ := strconv.Atoi(port)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(pnum))
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("socks connect: %w", err)
	}
	// Reply: ver, status, reserved, atyp, addr, port.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("socks connect reply: %w", err)
	}
	if header[1] != 0x00 {
		return 0, fmt.Errorf("socks connect failed with status 0x%02x", header[1])
	}
	var skip int
	switch header[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return 0, fmt.Errorf("socks connect reply addr: %w", err)
		}
		skip = int(lb[0])
	default:
		return 0, fmt.Errorf("socks connect reply: unknown atyp 0x%02x", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		return 0, fmt.Errorf("socks connect reply drain: %w", err)
	}

	// Plain HTTP GET over the established tunnel.
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: relavia-handshake-probe\r\nConnection: close\r\n\r\n", path, u.Host)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return 0, fmt.Errorf("write probe request: %w", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read probe response: %w", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/") {
		return 0, fmt.Errorf("probe response is not HTTP: %q", strings.TrimSpace(statusLine))
	}
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed probe status line: %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("malformed probe status code: %q", statusLine)
	}
	return code, nil
}
