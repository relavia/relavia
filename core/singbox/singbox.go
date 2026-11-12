// Package singbox implements kernel.Adapter on top of the
// sing-box kernel (proposal book Step 7: 挂接内核集成).
//
// Integration form: sing-box is linked IN-PROCESS as a Go library
// (its license is GPL-3.0-or-later plus a name/association clause —
// see docs/step2-许可证审计.md §2.1; this package never uses the
// sing-box or SagerNet name to imply association, the adapter's
// public identity is the neutral kernel id "sing-box" used purely
// descriptively in diagnostics, as the audit permits).
//
// The adapter compiles configurations from the unified node model
// (package specnode, the frozen Step 5 model), NOT from the
// placeholder kernel.Node. The kernel.Adapter methods convert the
// placeholder through specnode.FromKernel; the native entry
// points (StartNode / ValidateSpec / TestHandshakeNode) accept
// spec nodes directly and are the full-fidelity path the
// application service layer is expected to use (book 5.1/5.2:
// adapters consume the unified model).
//
// Official build: the adapter's capabilities depend on sing-box
// build tags. The project build (Step 7) is:
//
//	go build -tags "with_quic with_utls with_wireguard with_gvisor" ./...
//
// Capabilities() mirrors the tags actually compiled in (see
// features_*.go), so an untagged build honestly reports a smaller
// matrix instead of failing at runtime.
package singbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"openproxy/core/kernel"
	"openproxy/core/killswitch"
	"openproxy/core/routecfg"
	"openproxy/core/specnode"
)

// kernelID is the adapter's diagnostics identifier.
const kernelID = "sing-box"

// singBoxVersion is the pinned sing-box release (go.mod). A test
// cross-checks it against the linked module build info so the
// self-report cannot drift from reality.
const singBoxVersion = "1.14.4"

// DefaultProbeURL is the fallback TestHandshake probe target: a
// connectivity-check endpoint that answers 204 with no body.
// Callers (and all loopback tests) override it via Options.
const DefaultProbeURL = "http://connectivitycheck.gstatic.com/generate_204"

// Options configures an Adapter.
type Options struct {
	// ListenHost is the bind host of the local mixed inbound.
	// Default "127.0.0.1" (loopback only — the inbound is never
	// exposed on the LAN by this adapter).
	ListenHost string
	// ListenPort is the mixed inbound port. 0 (default) allocates
	// a free loopback port at each Start; the effective address is
	// reported by MixedAddr while running.
	ListenPort int
	// ProbeURL is the URL TestHandshake fetches through the node
	// to prove a real handshake plus data path. Default
	// DefaultProbeURL.
	ProbeURL string
	// LogLevel is the sing-box log level ("trace".."panic").
	// Default "warn".
	LogLevel string
	// OnLog, when set, receives sing-box log lines. Default:
	// discarded.
	OnLog func(level, message string)
	// Routing, when set, is the Step 11 routing/DNS policy
	// compiled into every configuration this adapter starts
	// (package routecfg). Nil keeps the Step 7 behaviour:
	// route.final = the node, no DNS section.
	Routing *routecfg.Policy
	// KillSwitchReport, when set, is the REAL status source
	// for the kill switch (Step 12, package killswitch —
	// typically a killswitch.Controller's Report method). The
	// adapter consults it live: Capabilities reports
	// Platform.KillSwitch=true, and Start honours a kill-switch
	// request, ONLY when the source reports
	// ReadinessEnforceable. Nil (the default, and the state of
	// every build this step ships: the Step 12 policy layer is
	// ready but no production Windows/Android enforcer is
	// wired in) keeps the honest Step 7 report of false —
	// policy-ready is NOT enforceable and is never rounded up.
	KillSwitchReport func() killswitch.Report
}

// Adapter is a sing-box-backed kernel.Adapter. Safe for
// concurrent use; lifecycle transitions are serialized.
type Adapter struct {
	opts Options
	caps kernel.Capabilities

	mu           sync.Mutex
	state        kernel.State
	since        time.Time
	activeID     string
	mode         kernel.RunMode
	lastError    *kernel.Error
	box          *box.Box
	trafficMgr   *trafficcontrol.Manager
	mixedPort    int
	sessionStart time.Time
	frozenUp     uint64
	frozenDown   uint64
	everRan      bool
	// runDir is the running instance's private temp directory
	// (holds its sing-box cache file — see compileOptions);
	// removed on Stop.
	runDir string
}

// Compile-time check: Adapter satisfies the Step 6 interface.
var _ kernel.Adapter = (*Adapter)(nil)

// New creates an Adapter in StateIdle.
func New(opts Options) *Adapter {
	if opts.ListenHost == "" {
		opts.ListenHost = "127.0.0.1"
	}
	if opts.ProbeURL == "" {
		opts.ProbeURL = DefaultProbeURL
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "warn"
	}
	a := &Adapter{
		opts:  opts,
		state: kernel.StateIdle,
		since: time.Now(),
	}
	a.caps = a.Capabilities()
	return a
}

// killSwitchEnforceable reports whether the attached Step 12
// kill-switch status source (Options.KillSwitchReport) grades
// enforcement as REAL right now. It is consulted live (not via
// the construction-time capability snapshot) so a source whose
// readiness changes is honoured at Start time.
func (a *Adapter) killSwitchEnforceable() bool {
	if a.opts.KillSwitchReport == nil {
		return false
	}
	return a.opts.KillSwitchReport().Readiness == killswitch.ReadinessEnforceable
}

// KillSwitchReadiness exposes the graded Step 12 readiness for
// UI/diagnostics: unavailable (no source attached),
// policy-ready (state machine + compiled rules ready, platform
// enforcement not real), or enforceable. Only enforceable ever
// maps to Platform.KillSwitch=true.
func (a *Adapter) KillSwitchReadiness() killswitch.Readiness {
	if a.opts.KillSwitchReport == nil {
		return killswitch.ReadinessUnavailable
	}
	return a.opts.KillSwitchReport().Readiness
}

// MixedAddr reports the local mixed inbound address while
// running ("127.0.0.1:port"); empty otherwise. The service layer
// points the OS / apps at this address in manual mode.
func (a *Adapter) MixedAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != kernel.StateRunning || a.mixedPort == 0 {
		return ""
	}
	return net.JoinHostPort(a.opts.ListenHost, fmt.Sprint(a.mixedPort))
}

// --- validation ----------------------------------------------------

// ValidateConfig implements kernel.Adapter: structural validation
// of the placeholder node, the Capabilities support check, then
// the spec-level support/compile gates on the converted node.
func (a *Adapter) ValidateConfig(_ context.Context, cfg *kernel.Config) error {
	if err := kernel.ValidateAgainst(cfg, a.caps); err != nil {
		return err
	}
	spec := specnode.FromKernel(cfg.Node)
	if err := checkSupported(spec); err != nil {
		return err
	}
	return checkCompileInputs(spec)
}

// ValidateSpec validates a unified-model node for this adapter:
// full schema-aligned validation plus support gates.
func (a *Adapter) ValidateSpec(_ context.Context, n *specnode.Node) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if err := checkSupported(n); err != nil {
		return err
	}
	if err := checkCompileInputs(n); err != nil {
		return err
	}
	_, err := a.routingFragment()
	return err
}

func (a *Adapter) validateKernelNode(cfg *kernel.Config) (*specnode.Node, error) {
	if err := kernel.ValidateAgainst(cfg, a.caps); err != nil {
		return nil, err
	}
	spec := specnode.FromKernel(cfg.Node)
	if err := checkSupported(spec); err != nil {
		return nil, err
	}
	if err := checkCompileInputs(spec); err != nil {
		return nil, err
	}
	if _, err := a.routingFragment(); err != nil {
		return nil, err
	}
	return spec, nil
}

// routingFragment compiles the adapter's Step 11 policy, if
// any. A policy that fails to compile is a configuration
// error and must surface at validation time, not mid-start.
func (a *Adapter) routingFragment() (*routecfg.Fragment, error) {
	if a.opts.Routing == nil {
		return nil, nil
	}
	frag, err := routecfg.Compile(*a.opts.Routing)
	if err != nil {
		return nil, kernel.NewError(kernel.KindInvalidConfig, "Validate",
			"routing policy does not compile", err)
	}
	return frag, nil
}

// --- lifecycle -----------------------------------------------------

// Start implements kernel.Adapter using the placeholder node
// (converted via specnode.FromKernel).
func (a *Adapter) Start(ctx context.Context, cfg *kernel.Config, opts kernel.PlatformOptions) error {
	spec, err := a.validateKernelNode(cfg)
	if err != nil {
		return err
	}
	return a.startInternal(ctx, spec, cfg.Node.ID, opts)
}

// StartNode is the full-fidelity entry point: start the kernel
// with a unified-model node.
func (a *Adapter) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	if err := a.ValidateSpec(ctx, n); err != nil {
		return err
	}
	return a.startInternal(ctx, n, n.ID, opts)
}

func (a *Adapter) startInternal(ctx context.Context, n *specnode.Node, nodeID string, opts kernel.PlatformOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Platform gates first (interface contract: refuse explicitly,
	// never silently degrade).
	mode := opts.Mode
	if mode == "" {
		mode = kernel.ModeManual
	}
	if mode == kernel.ModeTUN && !a.caps.Platform.TUN {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"TUN mode is not available in this step's in-process integration (platform networking lands in Steps 9-12)", nil)
	}
	if mode == kernel.ModeSystemProxy && !a.caps.Platform.SystemProxy {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"system-proxy mode is not available in this step's integration", nil)
	}
	if mode != kernel.ModeManual {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			fmt.Sprintf("run mode %q is not available in this step's integration", mode), nil)
	}
	if opts.KillSwitch && !a.killSwitchEnforceable() {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"kill switch requested but not enforceable: no attached kill-switch source reports enforceable (Step 12 policy layer is ready; production platform enforcement is pending — see docs/step12-断网保护.md)", nil)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	switch a.state {
	case kernel.StateRunning, kernel.StateStarting, kernel.StateStopping:
		return kernel.NewError(kernel.KindWrongState, "Start", "kernel already running or transitioning", nil)
	}
	a.setStateLocked(kernel.StateStarting)

	port := a.opts.ListenPort
	if port == 0 {
		p, err := allocateLoopbackPort(a.opts.ListenHost)
		if err != nil {
			return a.failStartLocked(kernel.NewError(kernel.KindNetwork, "Start", "allocate mixed inbound port", err))
		}
		port = p
	}
	dir, err := os.MkdirTemp("", "relavia-singbox-*")
	if err != nil {
		return a.failStartLocked(kernel.NewError(kernel.KindInternal, "Start", "create instance temp dir", err))
	}
	fragment, err := a.routingFragment()
	if err != nil {
		_ = os.RemoveAll(dir)
		return a.failStartLocked(kernel.NewError(kernel.KindInvalidConfig, "Start",
			"routing policy does not compile", err))
	}
	configJSON, err := compileConfig(n, compileOptions{
		listenHost: a.opts.ListenHost,
		listenPort: port,
		logLevel:   a.opts.LogLevel,
		cachePath:  filepath.Join(dir, "cache.db"),
		fragment:   fragment,
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return a.failStartLocked(kernel.NewError(kernel.KindInternal, "Start", "compile configuration", err))
	}
	instance, ictx, err := startInstance(configJSON, a.platformLogWriter())
	if err != nil {
		_ = os.RemoveAll(dir)
		kind := kernel.KindInternal
		if strings.Contains(err.Error(), "bind") || strings.Contains(err.Error(), "address already in use") {
			kind = kernel.KindNetwork
		}
		return a.failStartLocked(kernel.NewError(kind, "Start", "sing-box instance failed to start", err))
	}
	a.runDir = dir

	a.box = instance
	a.trafficMgr = service.PtrFromContext[trafficcontrol.Manager](ictx)
	a.mixedPort = port
	a.activeID = nodeID
	a.mode = mode
	a.lastError = nil
	a.sessionStart = time.Now()
	a.everRan = true
	a.frozenUp, a.frozenDown = 0, 0
	a.setStateLocked(kernel.StateRunning)
	return nil
}

func (a *Adapter) failStartLocked(err *kernel.Error) error {
	a.setStateLocked(kernel.StateFailed)
	a.lastError = err
	return err
}

// Stop implements kernel.Adapter. Idempotent.
func (a *Adapter) Stop(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch a.state {
	case kernel.StateRunning, kernel.StateFailed:
		if a.trafficMgr != nil {
			up, down := a.trafficMgr.Total()
			a.frozenUp, a.frozenDown = uint64(max64(up, 0)), uint64(max64(down, 0))
		}
		if a.box != nil {
			_ = a.box.Close()
			a.box = nil
		}
		if a.runDir != "" {
			_ = os.RemoveAll(a.runDir)
			a.runDir = ""
		}
		a.mixedPort = 0
		a.activeID = ""
		a.setStateLocked(kernel.StateStopped)
	}
	return nil
}

// Status implements kernel.Adapter.
func (a *Adapter) Status() kernel.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return kernel.Status{
		State:        a.state,
		Since:        a.since,
		ActiveNodeID: a.activeID,
		Mode:         a.mode,
		LastError:    a.lastError,
	}
}

// QueryTraffic implements kernel.Adapter. While running it reads
// the kernel's live traffic-control counters (cumulative bytes of
// all tracked connections, opened via sing-box's trafficcontrol
// manager); after Stop it returns the totals frozen at shutdown;
// before the first session it returns zeros without an error.
func (a *Adapter) QueryTraffic(_ context.Context) (*kernel.TrafficStats, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	stats := &kernel.TrafficStats{SampledAt: time.Now()}
	if !a.everRan {
		return stats, nil
	}
	stats.SessionStartedAt = a.sessionStart
	if a.state == kernel.StateRunning && a.trafficMgr != nil {
		up, down := a.trafficMgr.Total()
		stats.UploadBytes = uint64(max64(up, 0))
		stats.DownloadBytes = uint64(max64(down, 0))
	} else {
		stats.UploadBytes = a.frozenUp
		stats.DownloadBytes = a.frozenDown
	}
	return stats, nil
}

func (a *Adapter) setStateLocked(s kernel.State) {
	a.state = s
	a.since = time.Now()
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// --- instance plumbing ----------------------------------------------

type platformLogWriter struct {
	fn func(level, message string)
}

func (w platformLogWriter) WriteMessage(level log.Level, message string) {
	if w.fn != nil {
		w.fn(levelName(level), message)
	}
}

// levelName renders a sing-box log level (a bare uint8 alias in
// sing-box 1.14) as text for the OnLog sink.
func levelName(level log.Level) string {
	switch level {
	case log.LevelTrace:
		return "trace"
	case log.LevelDebug:
		return "debug"
	case log.LevelInfo:
		return "info"
	case log.LevelWarn:
		return "warn"
	case log.LevelError:
		return "error"
	case log.LevelFatal:
		return "fatal"
	case log.LevelPanic:
		return "panic"
	}
	return "unknown"
}

func (a *Adapter) platformLogWriter() log.PlatformWriter {
	// A non-nil PlatformLogWriter also makes sing-box create its
	// traffic-control manager (box.go), which QueryTraffic reads;
	// no Clash API listener is configured, so nothing is exposed.
	return platformLogWriter{fn: a.opts.OnLog}
}

// startInstance parses a sing-box JSON configuration and starts
// an instance. The instance context is adapter-owned (derived
// from Background): the caller's request context must not tear
// the kernel down when it ends.
func startInstance(configJSON []byte, writer log.PlatformWriter) (*box.Box, context.Context, error) {
	ctx := include.Context(service.ContextWith(context.Background(),
		deprecated.NewStderrManager(log.StdLogger())))
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, configJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("parse configuration: %w", err)
	}
	instance, err := box.New(box.Options{
		Context:           ctx,
		Options:           opts,
		PlatformLogWriter: writer,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create instance: %w", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, nil, fmt.Errorf("start instance: %w", err)
	}
	return instance, ctx, nil
}

func allocateLoopbackPort(host string) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// linkedSingBoxVersion returns the sing-box module version found
// in the binary's build info ("(devel)" when running from a
// module workspace in tests may report the module version via the
// dependency list).
func linkedSingBoxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
			return strings.TrimPrefix(dep.Version, "v")
		}
	}
	return ""
}
