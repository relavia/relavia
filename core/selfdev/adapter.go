// Package selfdev is the composite kernel adapter of the
// self-development route (docs/自研协议路线-01-shadowsocks.md
// section 3.1): it presents the frozen kernel.Adapter interface
// while routing work between the borrowed sing-box kernel and
// the project's own protocol implementations as they land,
// protocol by protocol, each behind its differential gates.
//
// Phase 1 landed the handshake face: TestHandshake for
// Shadowsocks nodes can be served by the self-developed engine
// in core/selfdev/shadowsocks under the backend policy below.
//
// Phase 2 lands the data plane for manual mode: when the
// policy routes a Shadowsocks node to the self-developed
// backend, Start brings up the project's own forwarding plane
// (forward.go) - a loopback mixed inbound served by the
// self-developed engine under the Step 11 routing/DNS policy
// (policy.go, dns.go) and the Step 12 kill-switch gate. TUN and
// system-proxy starts always stay with the sing-box backend
// (the TUN composition is not the self-developed plane's, per
// spec section 3.2), as does every non-Shadowsocks node.
// Interface signatures are the frozen kernel.Adapter ones -
// zero changes.
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
	"openproxy/core/killswitch"
	"openproxy/core/routecfg"
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
	// ListenHost / ListenPort bind the self-developed
	// forwarding plane's mixed inbound. Defaults mirror the
	// sing-box adapter's: loopback only, port 0 allocates a
	// free port per Start (see MixedAddr). Wire them to the
	// same values as the sing-box adapter's options so the
	// local endpoint does not move when the backend changes.
	ListenHost string
	ListenPort int
	// Routing is the Step 11 routing/DNS policy the
	// self-developed plane enforces (package routecfg). It is
	// the same policy document the sing-box adapter receives
	// via its own Options.Routing - pass the same value to
	// both so a node's behaviour does not depend on which
	// backend serves it. Nil keeps the Step 7 behaviour
	// (everything to the node, no local resolution).
	Routing *routecfg.Policy
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

	// Self-developed data-plane session state (phase 2). The
	// sing-box backend keeps its own state inside sb; the
	// composite reports whichever backend ran the current/last
	// session, and traffic is the sum over both (spec 3.1).
	plane         *plane
	runBackend    string
	pState        kernel.State
	pSince        time.Time
	pNodeID       string
	pMode         kernel.RunMode
	pErr          *kernel.Error
	pStart        time.Time
	planeEverRan  bool
	planeUpTotal  uint64 // folded totals of finished plane sessions
	planeDownTotal uint64
}

// New builds the composite adapter over sb.
func New(sb *singbox.Adapter, opts Options) *Adapter {
	if opts.ProbeURL == "" {
		opts.ProbeURL = singbox.DefaultProbeURL
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 20 * time.Second
	}
	return &Adapter{sb: sb, opts: opts, policy: opts.Policy, pins: map[string]string{},
		pState: kernel.StateIdle, pSince: time.Now()}
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

// --- kernel.Adapter: data plane, routed -------------------------

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

// ValidateConfig validates against the sing-box gates (the
// support union) plus the composite's own routing policy
// syntax, mirroring how the sing-box adapter validates its
// routing fragment at validation time.
func (a *Adapter) ValidateConfig(ctx context.Context, cfg *kernel.Config) error {
	if err := a.sb.ValidateConfig(ctx, cfg); err != nil {
		return err
	}
	return a.validateRouting()
}

// ValidateSpec is ValidateConfig for unified-model nodes.
func (a *Adapter) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	if err := a.sb.ValidateSpec(ctx, n); err != nil {
		return err
	}
	return a.validateRouting()
}

func (a *Adapter) validateRouting() error {
	if a.opts.Routing == nil {
		return nil
	}
	if _, err := routecfg.Compile(*a.opts.Routing); err != nil {
		return kernel.NewError(kernel.KindInvalidConfig, "ValidateConfig",
			"routing policy does not compile", err)
	}
	return nil
}

// Start implements kernel.Adapter using the placeholder node
// (converted via specnode.FromKernel), routed like StartNode.
func (a *Adapter) Start(ctx context.Context, cfg *kernel.Config, opts kernel.PlatformOptions) error {
	spec := specnode.FromKernel(cfg.Node)
	if err := a.ValidateSpec(ctx, spec); err != nil {
		return err
	}
	return a.startRouted(ctx, spec, cfg.Node.ID, opts)
}

// StartNode is the full-fidelity entry point: start with a
// unified-model node, on the backend the policy selects.
func (a *Adapter) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	if err := a.ValidateSpec(ctx, n); err != nil {
		return err
	}
	return a.startRouted(ctx, n, n.ID, opts)
}

// startRouted performs a Start on the selected backend. The
// backend decision is made here, at the connection-
// establishment decision point (spec 3.3); a failed start is
// reported as-is and never silently rerouted - in particular a
// KindInternal from the self-developed plane fails the start
// (spec 3.3, last bullet).
func (a *Adapter) startRouted(ctx context.Context, n *specnode.Node, nodeID string, opts kernel.PlatformOptions) error {
	a.mu.Lock()
	planeRunning := a.pState == kernel.StateRunning || a.pState == kernel.StateStarting
	a.mu.Unlock()
	if planeRunning {
		return kernel.NewError(kernel.KindWrongState, "Start", "kernel already running or transitioning", nil)
	}
	mode := opts.Mode
	if mode == "" {
		mode = kernel.ModeManual
	}
	backend, reason := a.route(n)
	if backend == BackendSelfdev && mode == kernel.ModeManual {
		return a.startPlane(ctx, n, nodeID, opts, reason)
	}
	if backend == BackendSelfdev {
		// TUN and system-proxy compositions stay with the
		// sing-box backend (spec 3.2): the self-developed plane
		// is a manual-mode loopback plane.
		reason += fmt.Sprintf("; mode %s stays with the sing-box backend", mode)
	}
	a.logf("selfdev: start node=%s backend=sing-box (%s)", nodeID, reason)
	if err := a.sb.StartNode(ctx, n, opts); err != nil {
		return err
	}
	a.mu.Lock()
	a.runBackend = BackendSingbox
	a.mu.Unlock()
	return nil
}

// startPlane brings up the self-developed forwarding plane for
// one Shadowsocks node, under the same platform gates the
// sing-box adapter applies.
func (a *Adapter) startPlane(ctx context.Context, n *specnode.Node, nodeID string, opts kernel.PlatformOptions, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Step 12 gate, consulted from the same graded source the
	// sing-box adapter uses, so both planes share one truth:
	// a kill-switch request the platform cannot enforce is
	// refused, never silently dropped.
	if opts.KillSwitch && a.sb.KillSwitchReadiness() != killswitch.ReadinessEnforceable {
		return a.failPlaneStart(kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"kill switch requested but not enforceable: no attached kill-switch source reports enforceable (Step 12 policy layer is ready; production platform enforcement is pending)", nil))
	}
	if st := a.sb.Status().State; st == kernel.StateRunning || st == kernel.StateStarting || st == kernel.StateStopping {
		return kernel.NewError(kernel.KindWrongState, "Start", "kernel already running or transitioning", nil)
	}
	cred := n.Shadowsocks
	client, err := shadowsocks.NewClient(cred.Method, cred.Password)
	if err != nil {
		return a.failPlaneStart(asKernelError(err))
	}
	eval, err := compilePolicyEval(a.opts.Routing)
	if err != nil {
		return a.failPlaneStart(asKernelError(err))
	}
	pl := newPlane(client, n, eval, a.logf, a.opts.ListenHost, a.opts.ListenPort)
	a.mu.Lock()
	a.pState = kernel.StateStarting
	a.pSince = time.Now()
	a.mu.Unlock()
	if err := pl.start(ctx); err != nil {
		return a.failPlaneStart(asKernelError(err))
	}
	a.mu.Lock()
	a.plane = pl
	a.runBackend = BackendSelfdev
	a.pState = kernel.StateRunning
	a.pSince = time.Now()
	a.pNodeID = nodeID
	a.pMode = kernel.ModeManual
	a.pErr = nil
	a.pStart = pl.startedAt
	a.planeEverRan = true
	a.mu.Unlock()
	a.logf("selfdev: start node=%s backend=selfdev (%s)", nodeID, reason)
	return nil
}

func (a *Adapter) failPlaneStart(err *kernel.Error) error {
	a.mu.Lock()
	a.runBackend = BackendSelfdev
	a.pState = kernel.StateFailed
	a.pSince = time.Now()
	a.pErr = err
	a.mu.Unlock()
	return err
}

func asKernelError(err error) *kernel.Error {
	if ke, ok := err.(*kernel.Error); ok {
		return ke
	}
	return kernel.NewError(kernel.KindInternal, "selfdev.Start", "self-developed plane failed", err)
}

// Stop tears down whichever backend is running. Idempotent.
func (a *Adapter) Stop(ctx context.Context) error {
	a.mu.Lock()
	pl := a.plane
	planeActive := a.runBackend == BackendSelfdev && pl != nil
	a.mu.Unlock()
	if planeActive {
		pl.close()
		up, down := pl.totals()
		a.mu.Lock()
		a.plane = nil
		a.planeUpTotal += up
		a.planeDownTotal += down
		a.pState = kernel.StateStopped
		a.pSince = time.Now()
		a.pNodeID = ""
		a.mu.Unlock()
	}
	return a.sb.Stop(ctx)
}

// Status reports the state of the backend that ran the
// current/last session.
func (a *Adapter) Status() kernel.Status {
	a.mu.Lock()
	if a.runBackend == BackendSelfdev {
		st := kernel.Status{
			State:        a.pState,
			Since:        a.pSince,
			ActiveNodeID: a.pNodeID,
			Mode:         a.pMode,
			LastError:    a.pErr,
		}
		a.mu.Unlock()
		return st
	}
	a.mu.Unlock()
	return a.sb.Status()
}

// QueryTraffic aggregates both backends (spec 3.1): the
// sing-box session counters plus the self-developed plane's,
// with per-backend detail retained in the log record on Stop.
func (a *Adapter) QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error) {
	stats, err := a.sb.QueryTraffic(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	up, down := a.planeUpTotal, a.planeDownTotal
	if a.plane != nil {
		u, d := a.plane.totals()
		up += u
		down += d
	}
	if a.runBackend == BackendSelfdev && a.planeEverRan {
		stats.SessionStartedAt = a.pStart
	}
	a.mu.Unlock()
	stats.UploadBytes += up
	stats.DownloadBytes += down
	return stats, nil
}

// MixedAddr reports the local mixed inbound address while
// running, from whichever backend serves the session; empty
// otherwise. Mirrors the sing-box adapter's accessor so the
// service layer can treat the composite as a drop-in.
func (a *Adapter) MixedAddr() string {
	a.mu.Lock()
	pl := a.plane
	running := a.runBackend == BackendSelfdev && a.pState == kernel.StateRunning
	a.mu.Unlock()
	if running && pl != nil {
		return pl.addr()
	}
	return a.sb.MixedAddr()
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
