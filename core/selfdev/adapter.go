// Package selfdev is the composite kernel adapter of the
// self-development route (docs/自研协议路线-01-shadowsocks.md
// section 3.1): it presents the frozen kernel.Adapter interface
// while routing work between the borrowed sing-box kernel and
// the project's own protocol implementations as they land,
// protocol by protocol, each behind its differential gates.
//
// Phase 1 scope: the data plane (Start/Stop/Status/
// QueryTraffic/ValidateConfig) is sing-box, unchanged. The
// Shadowsocks handshake face (TestHandshake) can be served by
// the self-developed engine in core/selfdev/shadowsocks under
// the backend policy below. Interface signatures are the frozen
// kernel.Adapter ones - zero changes.
package selfdev

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/selfdev/shadowsocks"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// Policy is the backend selection gear for protocols that have
// a self-developed implementation (spec section 3.3). It is a
// local setting, never part of the node model.
type Policy int

const (
	// PolicySingbox routes everything to sing-box. This is the
	// initial default: the self-developed backend earns traffic
	// through the differential gates, not by default.
	PolicySingbox Policy = iota
	// PolicyAuto tries the self-developed backend for eligible
	// nodes; a node whose self-developed handshake fails is
	// pinned to sing-box until its data changes or the pin is
	// reset manually.
	PolicyAuto
	// PolicySelfdev routes every eligible node to the
	// self-developed backend (testing/diagnostics; never the
	// default).
	PolicySelfdev
)

func (p Policy) String() string {
	switch p {
	case PolicySingbox:
		return "singbox"
	case PolicyAuto:
		return "auto"
	case PolicySelfdev:
		return "selfdev"
	}
	return "unknown"
}

// Backend identifiers recorded in logs and results.
const (
	BackendSingbox = "sing-box"
	BackendSelfdev = "selfdev"
)

// Options configures the composite adapter.
type Options struct {
	// ProbeURL is fetched through the node by self-developed
	// handshake tests, mirroring the sing-box probe shape.
	// Empty means singbox.DefaultProbeURL.
	ProbeURL string
	// ProbeTimeout bounds a self-developed handshake test when
	// the caller's context has no deadline. Zero means 20s.
	ProbeTimeout time.Duration
	// Policy is the initial backend gear. The zero value is
	// PolicySingbox.
	Policy Policy
	// Logf receives backend routing records (actual backend per
	// node, pins, fallbacks). Nil discards them.
	Logf func(format string, args ...any)
}

// Adapter is the composite kernel adapter. It wraps a sing-box
// adapter; construct the sing-box adapter as usual and hand it
// over.
type Adapter struct {
	sb   *singbox.Adapter
	opts Options

	mu     sync.Mutex
	policy Policy
	// pins maps node ID -> node fingerprint for nodes pinned to
	// sing-box under PolicyAuto. A pin stops applying when the
	// node's fingerprint changes.
	pins map[string]string
}

// New builds the composite adapter over sb.
func New(sb *singbox.Adapter, opts Options) *Adapter {
	if opts.ProbeURL == "" {
		opts.ProbeURL = singbox.DefaultProbeURL
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 20 * time.Second
	}
	return &Adapter{sb: sb, opts: opts, policy: opts.Policy, pins: map[string]string{}}
}

var _ kernel.Adapter = (*Adapter)(nil)

// SetPolicy changes the backend gear at runtime (settings UI).
func (a *Adapter) SetPolicy(p Policy) {
	a.mu.Lock()
	a.policy = p
	a.mu.Unlock()
	a.logf("selfdev: backend policy set to %s", p)
}

// Policy reports the current gear.
func (a *Adapter) Policy() Policy {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.policy
}

// ResetPins clears all auto-mode pins (manual reset in the
// spec's pinning discipline).
func (a *Adapter) ResetPins() {
	a.mu.Lock()
	a.pins = map[string]string{}
	a.mu.Unlock()
	a.logf("selfdev: backend pins reset")
}

func (a *Adapter) logf(format string, args ...any) {
	if a.opts.Logf != nil {
		a.opts.Logf(format, args...)
	}
}

// --- kernel.Adapter: data plane delegates to sing-box ----------

// Capabilities reports the union the composite can serve: the
// sing-box matrix (platform facts included), under the
// composite's own kernel ID. Nothing is over-reported - the
// self-developed backend only ever serves combinations sing-box
// also serves.
func (a *Adapter) Capabilities() kernel.Capabilities {
	caps := a.sb.Capabilities()
	caps.KernelID = "selfdev"
	return caps
}

// ValidateConfig delegates to sing-box in phase 1.
func (a *Adapter) ValidateConfig(ctx context.Context, cfg *kernel.Config) error {
	return a.sb.ValidateConfig(ctx, cfg)
}

// ValidateSpec delegates to sing-box in phase 1.
func (a *Adapter) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	return a.sb.ValidateSpec(ctx, n)
}

// Start delegates to sing-box in phase 1 (the self-developed
// data plane is phase 2). A KindInternal from the data plane
// fails the start as-is: the composite never silently reroutes
// a failed start.
func (a *Adapter) Start(ctx context.Context, cfg *kernel.Config, opts kernel.PlatformOptions) error {
	return a.sb.Start(ctx, cfg, opts)
}

// StartNode delegates to sing-box in phase 1.
func (a *Adapter) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	return a.sb.StartNode(ctx, n, opts)
}

// Stop delegates to sing-box.
func (a *Adapter) Stop(ctx context.Context) error { return a.sb.Stop(ctx) }

// Status delegates to sing-box.
func (a *Adapter) Status() kernel.Status { return a.sb.Status() }

// QueryTraffic delegates to sing-box.
func (a *Adapter) QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error) {
	return a.sb.QueryTraffic(ctx)
}

// --- handshake face: routed ------------------------------------

// TestHandshake implements kernel.Adapter by converting to the
// unified model and routing like TestHandshakeNode.
func (a *Adapter) TestHandshake(ctx context.Context, node *kernel.Node) (*kernel.HandshakeResult, error) {
	if err := kernel.ValidateNode(node); err != nil {
		return nil, err
	}
	return a.TestHandshakeNode(ctx, specnode.FromKernel(node))
}

// TestHandshakeNode routes the handshake test for one node to
// the backend the policy selects, and records the actual
// backend in the log.
func (a *Adapter) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	if err := a.ValidateSpec(ctx, n); err != nil {
		return nil, err
	}
	backend, reason := a.route(n)
	if backend == BackendSelfdev {
		res, err := a.selfdevHandshake(ctx, n)
		if err != nil {
			return nil, err
		}
		a.logf("selfdev: handshake node=%s backend=selfdev ok=%v (%s)", n.ID, res.OK, reason)
		if !res.OK && a.Policy() == PolicyAuto {
			a.pin(n)
		}
		return res, nil
	}
	a.logf("selfdev: handshake node=%s backend=sing-box (%s)", n.ID, reason)
	return a.sb.TestHandshakeNode(ctx, n)
}

// route decides the backend for a node. Fallback decisions are
// made here - at the connection-establishment decision point,
// never mid-connection (spec section 3.3).
func (a *Adapter) route(n *specnode.Node) (backend, reason string) {
	eligible, why := selfdevEligible(n)
	switch a.Policy() {
	case PolicySelfdev:
		if eligible {
			return BackendSelfdev, "policy=selfdev"
		}
		return BackendSingbox, "policy=selfdev but node ineligible: " + why
	case PolicyAuto:
		if !eligible {
			return BackendSingbox, "policy=auto, node ineligible: " + why
		}
		if a.pinned(n) {
			return BackendSingbox, "policy=auto, node pinned after selfdev failure"
		}
		return BackendSelfdev, "policy=auto"
	default: // PolicySingbox
		return BackendSingbox, "policy=singbox"
	}
}

// selfdevEligible reports whether the self-developed engine may
// serve this node at all. Out-of-scope shapes (plugin
// transports, multi-segment PSK, methods outside the 7) are
// fixed to sing-box with the reason recorded (spec section 2).
func selfdevEligible(n *specnode.Node) (bool, string) {
	if n == nil || n.Protocol != "shadowsocks" {
		return false, "not a shadowsocks node"
	}
	cred := n.Shadowsocks
	if cred == nil {
		return false, "missing shadowsocks credentials"
	}
	if _, ok := shadowsocks.LookupMethod(cred.Method); !ok {
		return false, "method outside the self-developed scope: " + cred.Method
	}
	if cred.Plugin != "" || cred.PluginOpts != "" {
		return false, "plugin transport is out of scope (plugin=" + cred.Plugin + ")"
	}
	if shadowsocks.IsMultiPSK(cred.Method, cred.Password) {
		return false, "multi-segment PSK is out of scope"
	}
	return true, ""
}

func nodeFingerprint(n *specnode.Node) string {
	// The credential fields carry json:"-" tags, so fingerprint
	// the routing-relevant fields explicitly.
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|", n.Protocol, n.Server, n.Port)
	if c := n.Shadowsocks; c != nil {
		fmt.Fprintf(h, "%s|%s|%s|%s", c.Method, c.Password, c.Plugin, c.PluginOpts)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Adapter) pinned(n *specnode.Node) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	fp, ok := a.pins[n.ID]
	return ok && fp == nodeFingerprint(n)
}

func (a *Adapter) pin(n *specnode.Node) {
	a.mu.Lock()
	a.pins[n.ID] = nodeFingerprint(n)
	a.mu.Unlock()
	a.logf("selfdev: node=%s pinned to sing-box after selfdev handshake failure (until node data changes or manual reset)", n.ID)
}

// selfdevHandshake performs the probe with the self-developed
// engine, in the same shape as the sing-box probe: a real
// protocol connection to the probe target through the node,
// fetching ProbeURL; any well-formed HTTP response proves the
// data path.
func (a *Adapter) selfdevHandshake(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	res := &kernel.HandshakeResult{NodeID: n.ID, TestedAt: time.Now()}
	cred := n.Shadowsocks
	client, err := shadowsocks.NewClient(cred.Method, cred.Password)
	if err != nil {
		// Engine-side classification failure (a shape ValidateSpec
		// let through but the engine refuses): report as a failed
		// handshake with the classified error attached.
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "selfdev.TestHandshake",
			"self-developed engine refused the node", err)
		return res, nil
	}
	probe, err := url.Parse(a.opts.ProbeURL)
	if err != nil || probe.Host == "" {
		return nil, kernel.NewError(kernel.KindInternal, "selfdev.TestHandshake",
			"invalid probe URL", err)
	}
	probeHost := probe.Hostname()
	probePort := 80
	if p := probe.Port(); p != "" {
		fmt.Sscanf(p, "%d", &probePort)
	}
	parentCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.opts.ProbeTimeout)
		defer cancel()
	}
	serverAddr := net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
	target := shadowsocks.Addr{Host: probeHost, Port: probePort}

	start := time.Now()
	conn, err := client.DialTCP(ctx, serverAddr, target)
	if err != nil {
		if parentCtx.Err() != nil {
			return nil, parentCtx.Err()
		}
		res.Error = asHandshakeError(err)
		return res, nil
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	path := probe.RequestURI()
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, probe.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		res.Error = asHandshakeError(err)
		return res, nil
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		if parentCtx.Err() != nil {
			return nil, parentCtx.Err()
		}
		res.Error = asHandshakeError(err)
		return res, nil
	}
	if !strings.HasPrefix(line, "HTTP/") {
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "selfdev.TestHandshake",
			"probe response is not HTTP", nil)
		return res, nil
	}
	res.OK = true
	res.Latency = time.Since(start)
	return res, nil
}

// asHandshakeError maps an engine failure onto the probe
// contract: a failed handshake test is a HandshakeResult with
// Kind KindHandshakeFailed (the same classification the
// sing-box probe reports), with the engine's precisely
// classified error preserved as the cause. The engine's own
// classification (network, AEAD failure, protocol violation)
// stays intact for data-plane callers; only the probe layer
// flattens it, so the differential error layer compares like
// with like.
func asHandshakeError(err error) *kernel.Error {
	return kernel.NewError(kernel.KindHandshakeFailed, "selfdev.TestHandshake",
		"self-developed handshake failed", err)
}
