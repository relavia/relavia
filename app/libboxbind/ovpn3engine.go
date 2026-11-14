package libboxbind

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"openproxy/app/android"
	"openproxy/app/platform"
	"openproxy/app/service"
	"openproxy/core/kernel"
	"openproxy/core/openvpn"
	"openproxy/core/specnode"
)

// ovpn3Engine is the Android OpenVPN slot of the protocol
// dispatch, served by the OpenVPN 3 core on the native side
// (docs/openvpn3安卓接线.md). It replaces the honest
// UnavailableEngine where the shell registered an Ovpn3Bridge;
// where none is registered it reproduces that engine's
// behaviour exactly (every start fails
// KindPlatformUnavailable), so a build without the native
// library never pretends the pool is connectable.
//
// Failure semantics deliberately mirror the desktop process
// adapter: waits are bounded by openvpn.DefaultConnectTimeout,
// and native core events are classified onto the same stable
// codes (openvpn.CodeAuthFailed, ...) wrapped so
// openvpn.CodeOf recovers them, with kernel kinds alongside.
//
// Consent: the engine asks for OS VPN consent through the
// same platform bridge the libbox choreography uses, before
// the native session starts — the core's TunBuilder establish
// inside the VPN service then finds consent already granted.
type ovpn3Engine struct {
	onLog func(level, message string)

	// connectTimeout bounds the CONNECTED wait; zero means
	// openvpn.DefaultConnectTimeout (the desktop adapter's
	// bound). A field, not a constant, so tests can shrink it.
	connectTimeout time.Duration

	mu        sync.Mutex
	state     kernel.State
	since     time.Time
	activeID  string
	lastError error // classified (openvpn.CodeOf-compatible) or *kernel.Error
	waiter    chan ovpn3Outcome
	startedAt time.Time
	up, down  uint64

	// nativeLive tracks the most recently LAUNCHED native
	// session: non-nil (open) from a successful
	// StartOvpn3Session until the core's DISCONNECTED for
	// that session closes it. A subsequent start waits on it
	// (bounded by unwindWait) before launching, so a new
	// core session never overlaps the previous session's
	// unwind inside the single-slot native session
	// controller (2026-11-14 timing audit, docs/真机连接
	// 失败诊断-2026-11-14.md §8): the native stop is
	// fire-and-forget, and without this gate a fast retry —
	// exactly the one-tap chain's shape — could install a
	// new session while the old core was still tearing
	// down, letting the old session's cleanup (client-slot
	// clear, service stop) land on the new session.
	nativeLive chan struct{}
	// unwindWait bounds the gate above; a field so tests
	// can stretch/shrink it. Zero means defaultUnwindWait.
	unwindWait time.Duration
}

// defaultUnwindWait bounds how long a start waits for the
// previous native session's DISCONNECTED before proceeding
// anyway: a core that never reports its own teardown must
// not wedge every later connect behind it.
const defaultUnwindWait = 3 * time.Second

type ovpn3Outcome struct {
	err error // nil on CONNECTED
}

// activeOvpn3Engine is the process-wide event sink target:
// NotifyOvpn3Event & friends are package-level facade entry
// points (the gomobile shape), so they route to the engine
// the session assembly built. Set once by newOvpn3Engine.
var activeOvpn3Engine atomic.Pointer[ovpn3Engine]

var _ service.Engine = (*ovpn3Engine)(nil)

func newOvpn3Engine(onLog func(level, message string)) *ovpn3Engine {
	e := &ovpn3Engine{onLog: onLog, state: kernel.StateIdle, since: time.Now()}
	activeOvpn3Engine.Store(e)
	return e
}

// ConnectAvailable reports whether a native bridge is
// registered: DispatchEngine.CanConnect (and with it the
// UI's per-node connect affordance) keys off this, so pool
// nodes become connectable exactly when the native side is
// really there — not before.
func (e *ovpn3Engine) ConnectAvailable() bool { return currentOvpn3Bridge() != nil }

func (e *ovpn3Engine) unavailable(op string) *kernel.Error {
	return kernel.NewError(kernel.KindPlatformUnavailable, op,
		"the OpenVPN 3 native bridge is not registered in this build; OpenVPN nodes are import/probe-only here", nil)
}

func (e *ovpn3Engine) Capabilities() kernel.Capabilities {
	support := kernel.ProtocolSupport{
		Transports: map[kernel.TransportType]kernel.TransportSupport{
			kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityTLS, kernel.SecurityNone}, UDP: true},
			kernel.TransportTCP:    {Security: []kernel.SecurityType{kernel.SecurityTLS, kernel.SecurityNone}, UDP: false},
			kernel.TransportUDP:    {Security: []kernel.SecurityType{kernel.SecurityTLS, kernel.SecurityNone}, UDP: true},
		},
	}
	return kernel.Capabilities{
		KernelID:      "openvpn3",
		KernelVersion: "3.12",
		Protocols:     map[kernel.Protocol]kernel.ProtocolSupport{kernel.ProtocolOpenVPN: support},
		Platform: kernel.PlatformCapabilities{
			Platform:              "android",
			TUN:                   e.ConnectAvailable(),
			SystemProxy:           false, // an in-process tunnel has no system-proxy form
			RequiresVPNPermission: true,
		},
		Features: kernel.FeatureSet{TrafficStats: true},
	}
}

func (e *ovpn3Engine) ValidateSpec(_ context.Context, n *specnode.Node) error {
	if n == nil || n.Protocol != specnode.ProtocolOpenVPN || n.OpenVPN == nil {
		return kernel.NewError(kernel.KindUnsupported, "ValidateSpec",
			"the OpenVPN 3 engine serves OpenVPN nodes only", nil)
	}
	_, err := openvpn.RenderProfile(n)
	return err
}

// StartNode runs one session to CONNECTED: consent, profile
// render, native launch, bounded wait on the event channel.
func (e *ovpn3Engine) StartNode(ctx context.Context, n *specnode.Node, _ kernel.PlatformOptions) error {
	return e.start(ctx, n)
}

func (e *ovpn3Engine) start(ctx context.Context, n *specnode.Node) error {
	bridge := currentOvpn3Bridge()
	if bridge == nil {
		return e.unavailable("Start")
	}
	if err := e.ValidateSpec(ctx, n); err != nil {
		return err
	}

	// Native-unwind gate (2026-11-14 timing audit §8): if
	// the previous native session was launched but its
	// DISCONNECTED has not been observed yet, wait for it
	// (bounded) BEFORE claiming Starting or touching
	// consent — a late DISCONNECTED consumed here can only
	// belong to the dead session, never to the one about
	// to launch, and the new core never starts while the
	// old one is still unwinding in the shared native
	// controller. The wait honors the caller's context.
	e.mu.Lock()
	prevLive := e.nativeLive
	e.mu.Unlock()
	if prevLive != nil {
		wait := e.unwindWait
		if wait <= 0 {
			wait = defaultUnwindWait
		}
		timer := time.NewTimer(wait)
		select {
		case <-prevLive:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			kerr := kernel.NewError(kernel.KindCanceled, "Start",
				"the start was canceled while waiting for the previous session to unwind", ctx.Err())
			e.setFailed(kerr)
			return kerr
		}
		timer.Stop()
	}

	e.mu.Lock()
	if e.state == kernel.StateRunning || e.state == kernel.StateStarting {
		e.mu.Unlock()
		return kernel.NewError(kernel.KindWrongState, "Start",
			"an OpenVPN session is already active", nil)
	}
	e.state = kernel.StateStarting
	e.since = time.Now()
	e.lastError = nil
	e.up, e.down = 0, 0
	e.mu.Unlock()

	// Consent first (the shell's latch shows the OS dialog
	// when needed). The caller's deadline does not account
	// for a human reading the dialog; detach like the TUN
	// engine does and bound by the session start budget.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tunStartTimeout)
	granted, err := platform.BridgeVPNService{}.Prepare(cctx)
	cancel()
	if err != nil {
		e.setFailed(err)
		return err
	}
	if !granted {
		e.setFailed(android.ErrPermissionDenied)
		return android.ErrPermissionDenied
	}
	// The consent wait above is detached on purpose (a human
	// reading the dialog is not the caller's deadline), but a
	// caller that gave up meanwhile — the one-tap chain
	// canceled by Disconnect — must not get a session launched
	// behind its back (2026-11-14 fix batch: a real cancel
	// for in-flight connects).
	if err := ctx.Err(); err != nil {
		kerr := kernel.NewError(kernel.KindCanceled, "Start",
			"the start was canceled before the session launched", err)
		e.setFailed(kerr)
		return kerr
	}

	profile, err := openvpn.RenderProfile(n)
	if err != nil {
		e.setFailed(err)
		return err
	}

	waiter := make(chan ovpn3Outcome, 1)
	e.mu.Lock()
	e.waiter = waiter
	e.mu.Unlock()

	if err := bridge.StartOvpn3Session(profile.Text, profile.Username, profile.Password); err != nil {
		e.clearWaiter(waiter)
		kerr := kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"the native OpenVPN session could not be launched", err)
		e.setFailed(kerr)
		return kerr
	}
	// The native session is launched: track it for the
	// unwind gate until its DISCONNECTED closes the channel
	// (onNativeEvent). Installed before the CONNECTED wait
	// so every exit path of this session is covered.
	e.mu.Lock()
	e.nativeLive = make(chan struct{})
	e.mu.Unlock()

	bound := e.connectTimeout
	if bound <= 0 {
		bound = openvpn.DefaultConnectTimeout
	}
	// The wait honors the caller's context (2026-11-14 fix
	// batch): previously it was detached (WithoutCancel), so
	// canceling a connect — Disconnect during the one-tap
	// chain — could not interrupt a start until the full
	// timeout burned down, one of the ingredients of "it
	// keeps reconnecting by itself". The consent phase above
	// stays detached; from here on the caller owns the clock
	// together with the connect bound.
	wctx, wcancel := context.WithTimeout(ctx, bound)
	defer wcancel()
	select {
	case out := <-waiter:
		e.clearWaiter(waiter)
		if out.err != nil {
			e.setFailed(out.err)
			return out.err
		}
		e.mu.Lock()
		e.state = kernel.StateRunning
		e.since = time.Now()
		e.startedAt = e.since
		e.activeID = n.ID
		e.mu.Unlock()
		return nil
	case <-wctx.Done():
		_ = bridge.StopOvpn3Session()
		e.clearWaiter(waiter)
		if cerr := ctx.Err(); cerr != nil {
			// Caller cancellation, not a server timeout:
			// classify it as what it is so chains can tell
			// "user said stop" from "server stayed silent".
			kerr := kernel.NewError(kernel.KindCanceled, "Start",
				"the start was canceled while waiting for the core", cerr)
			e.setFailed(kerr)
			return kerr
		}
		kerr := openvpn.WrapClassified(openvpn.CodeConnectTimeout,
			kernel.NewError(kernel.KindTimeout, "Start",
				"the OpenVPN core did not reach CONNECTED within the connect timeout", nil))
		e.setFailed(kerr)
		return kerr
	}
}

func (e *ovpn3Engine) Stop(ctx context.Context) error {
	bridge := currentOvpn3Bridge()
	e.mu.Lock()
	wasActive := e.state == kernel.StateRunning || e.state == kernel.StateStarting
	e.mu.Unlock()
	if bridge != nil {
		// Bounded like the facade's historical stop budget;
		// the native stop itself is a fire-and-forget ask.
		_ = bridge.StopOvpn3Session()
	}
	e.mu.Lock()
	if wasActive {
		e.state = kernel.StateIdle
		e.since = time.Now()
		e.activeID = ""
		// Wake any in-flight start wait so it unwinds now.
		if e.waiter != nil {
			select {
			case e.waiter <- ovpn3Outcome{err: kernel.NewError(kernel.KindCanceled, "Stop",
				"the session was stopped before it connected", nil)}:
			default:
			}
		}
	}
	e.mu.Unlock()
	return nil
}

func (e *ovpn3Engine) Status() kernel.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := kernel.Status{State: e.state, Since: e.since}
	if e.state == kernel.StateRunning {
		st.ActiveNodeID = e.activeID
		st.Mode = kernel.ModeTUN
	}
	if e.lastError != nil {
		var kerr *kernel.Error
		if errors.As(e.lastError, &kerr) {
			st.LastError = kerr
		}
	}
	return st
}

// TestHandshakeNode performs a real connect to CONNECTED and
// tears it down: for an in-process core the handshake test IS
// a session (the desktop rig's management-CONNECTED proof has
// the same shape). The pool's handshake-verified admission
// therefore means exactly what it says on Android too. While
// a user session is live the probe refuses (wrong state) —
// it must never tear down the user's tunnel to test another.
func (e *ovpn3Engine) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	res := &kernel.HandshakeResult{NodeID: n.ID, TestedAt: time.Now()}
	if currentOvpn3Bridge() == nil {
		res.Error = e.unavailable("TestHandshake")
		return res, nil
	}
	e.mu.Lock()
	busy := e.state == kernel.StateRunning || e.state == kernel.StateStarting
	e.mu.Unlock()
	if busy {
		res.Error = kernel.NewError(kernel.KindWrongState, "TestHandshake",
			"an OpenVPN session is active; the probe does not disturb it", nil)
		return res, nil
	}
	start := time.Now()
	if err := e.start(ctx, n); err != nil {
		var kerr *kernel.Error
		if errors.As(err, &kerr) {
			res.Error = kerr
		} else {
			res.Error = kernel.NewError(kernel.KindOf(err), "TestHandshake", err.Error(), nil)
		}
		return res, nil
	}
	res.OK = true
	res.Latency = time.Since(start)
	_ = e.Stop(ctx)
	return res, nil
}

func (e *ovpn3Engine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &kernel.TrafficStats{
		UploadBytes:      e.up,
		DownloadBytes:    e.down,
		SampledAt:        time.Now(),
		SessionStartedAt: e.startedAt,
	}, nil
}

// MixedAddr is empty: an in-process TUN tunnel exposes no
// local mixed listener (honest absence, as on desktop).
func (e *ovpn3Engine) MixedAddr() string { return "" }

// --- native event intake ------------------------------------

func (e *ovpn3Engine) setFailed(err error) {
	e.mu.Lock()
	e.state = kernel.StateFailed
	e.since = time.Now()
	e.lastError = err
	e.activeID = ""
	e.mu.Unlock()
}

func (e *ovpn3Engine) clearWaiter(w chan ovpn3Outcome) {
	e.mu.Lock()
	if e.waiter == w {
		e.waiter = nil
	}
	e.mu.Unlock()
}

// onNativeEvent classifies one verbatim core event. CONNECTED
// completes a pending start; a fatal event fails it; an
// unsolicited DISCONNECTED while running drops the engine to
// idle (the tunnel is gone — say so, never keep showing
// "connected").
func (e *ovpn3Engine) onNativeEvent(name, info string, fatal bool) {
	switch name {
	case "CONNECTED":
		e.mu.Lock()
		w := e.waiter
		e.mu.Unlock()
		if w != nil {
			select {
			case w <- ovpn3Outcome{}:
			default:
			}
		}
	case "DISCONNECTED":
		e.mu.Lock()
		w := e.waiter
		wasRunning := e.state == kernel.StateRunning
		if e.state == kernel.StateRunning || e.state == kernel.StateStarting {
			e.state = kernel.StateIdle
			e.since = time.Now()
			e.activeID = ""
		}
		// The native session this DISCONNECTED belongs to
		// has fully unwound: release the next start's gate.
		if e.nativeLive != nil {
			close(e.nativeLive)
			e.nativeLive = nil
		}
		e.mu.Unlock()
		if w != nil {
			select {
			case w <- ovpn3Outcome{err: openvpn.WrapClassified(openvpn.CodeConnectionFailed,
				kernel.NewError(kernel.KindNetwork, "Start",
					"the OpenVPN core disconnected before the session was established", nil))}:
			default:
			}
		}
		_ = wasRunning
	default:
		if !fatal {
			return
		}
		err := classifyNativeEvent(name, info)
		e.mu.Lock()
		w := e.waiter
		e.mu.Unlock()
		if w != nil {
			select {
			case w <- ovpn3Outcome{err: err}:
			default:
			}
		} else {
			e.setFailed(err)
		}
	}
}

// classifyNativeEvent maps a fatal OpenVPN 3 core event onto
// the desktop adapter's stable taxonomy (core/openvpn
// process.go codes), so a pool node fails with the same code
// on Android as on desktop.
func classifyNativeEvent(name, info string) error {
	upper := strings.ToUpper(name + " " + info)
	mk := func(code string, kind kernel.Kind, msg string) error {
		return openvpn.WrapClassified(code,
			kernel.NewError(kind, "Start", msg+": "+info, nil))
	}
	switch {
	case strings.Contains(upper, "PROFILE_ERROR") || strings.Contains(upper, "CONFIG"):
		return mk(openvpn.CodeConfigRejected, kernel.KindInvalidConfig,
			"the profile was rejected by the OpenVPN core")
	case strings.Contains(upper, "AUTH_FAILED") || strings.Contains(upper, "AUTH FAIL"):
		return mk(openvpn.CodeAuthFailed, kernel.KindHandshakeFailed,
			"the server rejected the credentials")
	case strings.Contains(upper, "TIMEOUT"):
		return mk(openvpn.CodeConnectTimeout, kernel.KindTimeout,
			"the connection timed out")
	case strings.Contains(upper, "VERIFY") || strings.Contains(upper, "CERT"):
		return mk(openvpn.CodeTLSVerifyFailed, kernel.KindHandshakeFailed,
			"the server certificate could not be verified")
	case strings.Contains(upper, "TLS") || strings.Contains(upper, "SSL"):
		return mk(openvpn.CodeTLSFailed, kernel.KindHandshakeFailed,
			"the TLS handshake failed")
	case strings.Contains(upper, "TUN") || strings.Contains(upper, "ROUTE"):
		return mk(openvpn.CodeTunUnavailable, kernel.KindPlatformUnavailable,
			"the tunnel interface could not be established")
	default:
		return mk(openvpn.CodeConnectionFailed, kernel.KindNetwork,
			"the OpenVPN core reported a fatal event "+name)
	}
}

func (e *ovpn3Engine) onTraffic(up, down uint64) {
	e.mu.Lock()
	e.up, e.down = up, down
	e.mu.Unlock()
}

func (e *ovpn3Engine) logLine(message string) {
	if e.onLog != nil {
		e.onLog("info", message)
	}
}
