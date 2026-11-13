// Package openvpn implements kernel.Adapter by driving the
// official OpenVPN 2.x program as an independent child process
// (proposal book Step 2 license-audit ruling F-1: OpenVPN is
// GPL-2.0-only and must never be linked into the project's GPLv3
// binary; arm's-length interaction via config file, command line
// and the management interface is the compliant form, and this
// package is exactly that boundary — it contains no OpenVPN code).
//
// The adapter compiles configurations from the unified node model
// (package specnode) like the other real adapter: the
// kernel.Adapter methods convert the placeholder node through
// specnode.FromKernel (lossy for OpenVPN — the placeholder cannot
// carry config bodies or certificates, so that path validates and
// then refuses with a precise invalid_config), and the native
// entry points (StartNode / ValidateSpec / TestHandshakeNode)
// accept spec nodes directly and are the full-fidelity path.
//
// Honesty contract (project-wide): when the openvpn executable is
// missing or too old, every operation fails explicitly with
// KindPlatformUnavailable and an actionable message. There is no
// silent fallback to another kernel and no simulated handshake.
package openvpn

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/killswitch"
	"openproxy/core/specnode"
)

// kernelID is the adapter's diagnostics identifier.
const kernelID = "openvpn-process"

// DefaultConnectTimeout bounds how long Start/TestHandshake wait
// for the management CONNECTED state before giving up. Server
// configs frequently retry forever, so the bound lives here, not
// in the child.
const DefaultConnectTimeout = 45 * time.Second

// Options configures an Adapter.
type Options struct {
	// BinaryPath pins the openvpn executable. Empty means: search
	// the application directory (bundled form first), then
	// SearchDirs, then PATH. See locate.go for the exact order.
	BinaryPath string
	// AppDir is the application installation directory whose
	// openvpn/ and bin/ subdirectories are searched first. Empty
	// uses the running executable's directory.
	AppDir string
	// SearchDirs are extra directories searched (in order) before
	// PATH.
	SearchDirs []string
	// WorkDir parents the per-session private directories.
	// Empty uses the OS temp directory.
	WorkDir string
	// OnLog receives redacted child output lines. Default:
	// discarded.
	OnLog func(level, message string)
	// ConnectTimeout overrides DefaultConnectTimeout when > 0.
	ConnectTimeout time.Duration
	// KillSwitchReport, when set, is the REAL status source for
	// the kill switch (Step 12, package killswitch), consulted
	// live exactly like the sing-box adapter does: Capabilities
	// reports KillSwitch=true and Start honours a kill-switch
	// request ONLY when the source reports
	// ReadinessEnforceable. Nil keeps the honest report of false.
	//
	// Division of labour (Step 12 boundary): the kill switch
	// enforcer owns blocking non-tunnel egress; this adapter owns
	// the tunnel process. A crashed tunnel process is surfaced
	// immediately as StateFailed (see watchSession), and the
	// routes the child installed vanish with its TUN device, so
	// the process layer never routes around the enforcer.
	KillSwitchReport func() killswitch.Report
	// DevOverride replaces the generated dev directive. TEST AND
	// DIAGNOSTICS ONLY (the CI handshake rig uses a null device
	// where no TUN device may be created); production passes "".
	DevOverride string
	// ExtraDirectives are appended verbatim to generated configs.
	// Adapter-controlled callers only (test rigs); never feed
	// node-supplied data into this.
	ExtraDirectives []string
}

// Adapter is an OpenVPN-process-backed kernel.Adapter. Safe for
// concurrent use; lifecycle transitions are serialised. At most
// one tunnel session runs per Adapter instance; TestHandshake uses
// independent ephemeral sessions and may run while a tunnel is up.
type Adapter struct {
	opts Options

	mu        sync.Mutex
	state     kernel.State
	since     time.Time
	activeID  string
	mode      kernel.RunMode
	lastError *kernel.Error
	sess      *session

	binMu sync.Mutex
	bin   *BinaryInfo

	lastTraffic kernel.TrafficStats
	sessionSeq  uint64
}

// New builds an Adapter. No process is started and the binary is
// not probed until the first operation that needs it.
func New(opts Options) *Adapter {
	return &Adapter{opts: opts, state: kernel.StateIdle, since: time.Now()}
}

var _ kernel.Adapter = (*Adapter)(nil)

// --- capabilities -----------------------------------------------------------

func (a *Adapter) killSwitchEnforceable() bool {
	if a.opts.KillSwitchReport == nil {
		return false
	}
	return a.opts.KillSwitchReport().Readiness == killswitch.ReadinessEnforceable
}

// KillSwitchReadiness mirrors the sing-box adapter's reporting so
// the service layer can treat both engines uniformly.
func (a *Adapter) KillSwitchReadiness() killswitch.Readiness {
	if a.opts.KillSwitchReport == nil {
		return killswitch.ReadinessUnavailable
	}
	return a.opts.KillSwitchReport().Readiness
}

// Capabilities implements kernel.Adapter. The protocol matrix
// holds exactly one row — OpenVPN — with its real transports.
// The TUN platform flag reflects whether a usable openvpn
// executable is locatable right now: without the process there
// is no tunnel, and reporting otherwise would be a lie the UI
// would act on.
func (a *Adapter) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		KernelID:      kernelID,
		KernelVersion: a.binaryVersionHint(),
		Protocols: map[kernel.Protocol]kernel.ProtocolSupport{
			kernel.ProtocolOpenVPN: {
				Transports: map[kernel.TransportType]kernel.TransportSupport{
					kernel.TransportNative: {
						Security: []kernel.SecurityType{kernel.SecurityTLS, kernel.SecurityNone},
						UDP:      true,
					},
					kernel.TransportTCP: {
						Security: []kernel.SecurityType{kernel.SecurityTLS, kernel.SecurityNone},
						UDP:      false,
					},
					kernel.TransportUDP: {
						Security: []kernel.SecurityType{kernel.SecurityTLS, kernel.SecurityNone},
						UDP:      true,
					},
				},
			},
		},
		Platform: kernel.PlatformCapabilities{
			Platform:              runtime.GOOS,
			TUN:                   a.binaryLocatable(),
			SystemProxy:           false, // a child-process tunnel has no system-proxy form
			KillSwitch:            a.killSwitchEnforceable(),
			IPv6:                  false, // the adapter provisions no IPv6 itself; passthrough configs may carry it — reported conservatively
			RequiresVPNPermission: false,
		},
		Features: kernel.FeatureSet{
			HandshakeTest: true,
			TrafficStats:  true,
			UDP:           true,
		},
	}
}

// binaryVersionHint returns the located binary's version when a
// probe already ran, else "" (Capabilities must stay cheap: no
// child process is spawned here).
func (a *Adapter) binaryVersionHint() string {
	a.binMu.Lock()
	defer a.binMu.Unlock()
	if a.bin != nil {
		return "openvpn " + a.bin.Version
	}
	return ""
}

// binaryLocatable is a spawn-free presence check (PATH/bundled
// candidates only). The authoritative version-verified probe runs
// in locate() at operation time.
func (a *Adapter) binaryLocatable() bool {
	if a.opts.BinaryPath != "" {
		return fileExists(a.opts.BinaryPath)
	}
	for _, p := range candidatePaths(a.opts) {
		if fileExists(p) {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// locate returns the cached, version-verified binary, probing on
// first use.
func (a *Adapter) locate(ctx context.Context) (*BinaryInfo, error) {
	a.binMu.Lock()
	defer a.binMu.Unlock()
	if a.bin != nil {
		return a.bin, nil
	}
	bin, err := locateBinary(ctx, a.opts)
	if err != nil {
		return nil, err
	}
	a.bin = bin
	return bin, nil
}

// BinaryInfo exposes the located executable (probing if needed),
// for diagnostics surfaces that must show which OpenVPN the
// adapter will drive.
func (a *Adapter) BinaryInfo(ctx context.Context) (*BinaryInfo, error) {
	return a.locate(ctx)
}

// --- validation ---------------------------------------------------------------

// checkNode gates a spec node for this adapter: unified-model
// validity, OpenVPN protocol, and this adapter's config-generation
// requirements.
func checkNode(n *specnode.Node) error {
	if n == nil {
		return kernel.NewError(kernel.KindInvalidConfig, "Validate", "nil node", nil)
	}
	if err := n.Validate(); err != nil {
		return err
	}
	if n.Protocol != specnode.ProtocolOpenVPN {
		return kernel.NewError(kernel.KindUnsupported, "Validate",
			"openvpn process adapter serves only openvpn nodes, got "+n.Protocol, nil)
	}
	// Generation requirements beyond schema validity (structured
	// mode needs a CA to verify against; both modes are fully
	// exercised by rendering a throwaway config).
	_, err := buildConfig(n, buildOptions{})
	return err
}

// ValidateSpec validates a unified-model node for this adapter.
func (a *Adapter) ValidateSpec(_ context.Context, n *specnode.Node) error {
	return checkNode(n)
}

// ValidateConfig implements kernel.Adapter via the placeholder
// conversion. A placeholder node cannot carry an OpenVPN config
// body or certificates, so full-text nodes are refused here with
// a precise message (use StartNode); nothing is silently
// approximated.
func (a *Adapter) ValidateConfig(_ context.Context, cfg *kernel.Config) error {
	if err := kernel.ValidateAgainst(cfg, a.Capabilities()); err != nil {
		return err
	}
	return checkNode(specnode.FromKernel(cfg.Node))
}

func (a *Adapter) validateKernelNode(cfg *kernel.Config) (*specnode.Node, error) {
	if err := kernel.ValidateAgainst(cfg, a.Capabilities()); err != nil {
		return nil, err
	}
	n := specnode.FromKernel(cfg.Node)
	if err := checkNode(n); err != nil {
		return nil, err
	}
	return n, nil
}

// --- lifecycle ------------------------------------------------------------------

// Start implements kernel.Adapter (placeholder path; see
// ValidateConfig for its limits).
func (a *Adapter) Start(ctx context.Context, cfg *kernel.Config, opts kernel.PlatformOptions) error {
	n, err := a.validateKernelNode(cfg)
	if err != nil {
		return err
	}
	return a.StartNode(ctx, n, opts)
}

// StartNode starts the tunnel for a unified-model node and returns
// once the management interface reports CONNECTED. Any failure
// leaves the adapter in StateFailed with the classified error in
// Status().LastError, and no child process behind.
func (a *Adapter) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	if err := checkNode(n); err != nil {
		return err
	}
	if opts.Mode == kernel.ModeSystemProxy {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"the OpenVPN process adapter has no system-proxy mode; system-proxy is served by the sing-box adapter", nil)
	}
	if opts.KillSwitch && !a.killSwitchEnforceable() {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"kill switch requested but no enforceable kill switch is attached (Step 12 enforcer not wired); refusing to run unprotected", nil)
	}
	a.mu.Lock()
	switch a.state {
	case kernel.StateIdle, kernel.StateStopped, kernel.StateFailed:
	default:
		a.mu.Unlock()
		return kernel.NewError(kernel.KindWrongState, "Start",
			"adapter is "+string(a.state)+"; stop it before starting again", nil)
	}
	a.state = kernel.StateStarting
	a.since = time.Now()
	a.lastError = nil
	a.activeID = n.ID
	a.mode = opts.Mode
	a.mu.Unlock()

	bin, err := a.locate(ctx)
	if err != nil {
		a.setFailed(err)
		return err
	}
	sess, err := spawnSession(ctx, bin, n, a.opts)
	if err != nil {
		a.setFailed(err)
		return err
	}
	if err := sess.waitConnected(ctx, a.connectTimeout()); err != nil {
		_ = sess.shutdown(2 * time.Second)
		a.setFailed(err)
		return err
	}
	a.mu.Lock()
	a.sess = sess
	a.state = kernel.StateRunning
	a.since = time.Now()
	a.sessionSeq++
	seq := a.sessionSeq
	a.mu.Unlock()
	go a.watchSession(sess, seq)
	return nil
}

// watchSession turns an unexpected child exit while running into
// StateFailed with the classified cause — this is the signal the
// Step 12 kill-switch layer and the UI react to; the tunnel never
// silently disappears.
func (a *Adapter) watchSession(sess *session, seq uint64) {
	<-sess.done
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessionSeq != seq || a.sess != sess {
		return // a Stop or a newer session owns the state now
	}
	a.lastTraffic = sess.traffic()
	a.sess = nil
	a.state = kernel.StateFailed
	a.since = time.Now()
	var kerr *kernel.Error
	if f := sess.getFailure(); f != nil {
		kerr = f.kerr
	} else {
		kerr = kernel.NewError(kernel.KindNetwork, "Session",
			"openvpn process exited unexpectedly (exit: "+exitString(sess.waitErr)+")", sess.waitErr)
	}
	a.lastError = kerr
}

// Stop implements kernel.Adapter. Idempotent; graceful first
// (management SIGTERM), escalating to process termination.
func (a *Adapter) Stop(_ context.Context) error {
	a.mu.Lock()
	sess := a.sess
	if sess == nil {
		if a.state == kernel.StateStarting || a.state == kernel.StateRunning {
			a.state = kernel.StateStopped
			a.since = time.Now()
		}
		a.mu.Unlock()
		return nil
	}
	a.sess = nil
	a.state = kernel.StateStopping
	a.since = time.Now()
	a.mu.Unlock()

	_ = sess.shutdown(3 * time.Second)

	a.mu.Lock()
	a.lastTraffic = sess.traffic()
	a.state = kernel.StateStopped
	a.since = time.Now()
	a.activeID = ""
	a.mu.Unlock()
	return nil
}

// Status implements kernel.Adapter.
func (a *Adapter) Status() kernel.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := kernel.Status{
		State:     a.state,
		Since:     a.since,
		Mode:      a.mode,
		LastError: a.lastError,
	}
	if a.state == kernel.StateRunning || a.state == kernel.StateStopping {
		st.ActiveNodeID = a.activeID
	}
	return st
}

func (a *Adapter) setFailed(err error) {
	var kerr *kernel.Error
	if ce, ok := err.(*classifiedError); ok {
		kerr = ce.kerr
	} else if ke, ok := err.(*kernel.Error); ok {
		kerr = ke
	} else {
		kerr = kernel.NewError(kernel.KindInternal, "Start", err.Error(), err)
	}
	a.mu.Lock()
	a.state = kernel.StateFailed
	a.since = time.Now()
	a.lastError = kerr
	a.mu.Unlock()
}

func (a *Adapter) connectTimeout() time.Duration {
	if a.opts.ConnectTimeout > 0 {
		return a.opts.ConnectTimeout
	}
	return DefaultConnectTimeout
}

// --- traffic --------------------------------------------------------------------

// QueryTraffic implements kernel.Adapter: live counters from the
// management byte-count notifications while a session runs; the
// final snapshot of the last session afterwards; zeros if no
// session ever ran.
func (a *Adapter) QueryTraffic(_ context.Context) (*kernel.TrafficStats, error) {
	a.mu.Lock()
	sess := a.sess
	last := a.lastTraffic
	a.mu.Unlock()
	if sess != nil {
		t := sess.traffic()
		return &t, nil
	}
	return &last, nil
}

// --- handshake test ---------------------------------------------------------------

// TestHandshake implements kernel.Adapter (placeholder path).
func (a *Adapter) TestHandshake(ctx context.Context, node *kernel.Node) (*kernel.HandshakeResult, error) {
	if node == nil {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "TestHandshake", "nil node", nil)
	}
	if node.Protocol != kernel.ProtocolOpenVPN {
		return nil, kernel.NewError(kernel.KindUnsupported, "TestHandshake",
			"openvpn process adapter serves only openvpn nodes, got "+string(node.Protocol), nil)
	}
	return a.TestHandshakeNode(ctx, specnode.FromKernel(node))
}

// TestHandshakeNode performs a REAL OpenVPN handshake: it starts
// an ephemeral child process for the node and waits for the
// management CONNECTED state (full TLS handshake, authentication
// and data-channel setup — the initialization sequence openvpn
// itself reports complete). Latency is spawn-to-CONNECTED.
//
// A failed handshake is a result (OK=false, Error classified); the
// Go error is reserved for test-preventing problems (invalid node,
// missing binary, cancellation), per the interface contract.
func (a *Adapter) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	res := &kernel.HandshakeResult{TestedAt: time.Now()}
	if n != nil {
		res.NodeID = n.ID
	}
	if err := checkNode(n); err != nil {
		return nil, err
	}
	bin, err := a.locate(ctx)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	sess, err := spawnSession(ctx, bin, n, a.opts)
	if err != nil {
		// A classified startup failure (auth rejected, TLS
		// failure, config rejected, process died mid-handshake)
		// IS the handshake outcome: report it as a result. Only
		// test-preventing problems stay Go errors.
		if ce, ok := err.(*classifiedError); ok && ce.code != CodeManagementFailed {
			res.Error = resultError(ce)
			return res, nil
		}
		if kernel.IsKind(err, kernel.KindPlatformUnavailable) ||
			kernel.IsKind(err, kernel.KindInvalidConfig) ||
			kernel.IsKind(err, kernel.KindCanceled) {
			return nil, err
		}
		if ke, ok := err.(*kernel.Error); ok {
			res.Error = ke
			return res, nil
		}
		return nil, err
	}
	defer func() { _ = sess.shutdown(time.Second) }()
	if err := sess.waitConnected(ctx, a.connectTimeout()); err != nil {
		if ce, ok := err.(*classifiedError); ok {
			res.Error = resultError(ce)
			return res, nil
		}
		if kernel.IsKind(err, kernel.KindCanceled) {
			return nil, err
		}
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake", err.Error(), err)
		return res, nil
	}
	res.OK = true
	res.Latency = time.Since(start)
	return res, nil
}
