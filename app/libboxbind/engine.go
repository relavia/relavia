package libboxbind

// The Android TUN engine (docs/android产品界面接入.md §3):
// the service-layer Engine whose connections run the Step 10
// choreography — OS consent through the ShellBridge, the shell
// establishes the TUN interface, libbox starts with the parked
// fd — instead of the desktop in-process adapter path, whose
// local listener routes nothing on Android (no system-proxy
// mode exists there, book 8.2).
//
// Why this exists: the product UI (app/ui) drives connections
// exclusively through service.Service.Connect, which speaks to
// an Engine. Until this engine landed, the merged APK's
// service carried the desktop dispatch (in-process sing-box),
// so a UI connect on Android could never reach the libbox
// choreography — the session facade (StartSession) was the
// only caller, and the only UI was the Kotlin shell page.
// Wiring the choreography in AS the engine makes the UI path
// and the shell-facade path the same path: session.startSession
// is now svc.Connect on the same assembly.
//
// Division of labour inside the engine:
//
//   - StartNode -> android.Shell.ConnectNode (the production
//     binder/starter installed by RegisterShellBridge and the
//     session assembly). The platform mode option is ignored:
//     the choreography is TUN by construction.
//   - Stop -> android.Shell.StopTUN, which unwinds only the
//     TUN side and never defers back into the service layer —
//     routing engine Stop through Shell.Disconnect would
//     recurse (Service.Disconnect -> engine Stop -> ...).
//   - Status follows the shell's live handle, which is also
//     what SessionStatus reports to the Kotlin shell.
//   - TestHandshakeNode / ValidateSpec delegate to an
//     in-process sing-box engine ("probe"): a handshake test
//     needs no TUN (it runs a throwaway local box, exactly as
//     on desktop), and it must keep working while a TUN
//     session is up.
//   - QueryTraffic fails explicitly: this binding exposes no
//     counters for the libbox TUN session (the command
//     server's stats surface is not wired), and the capability
//     report says so (Features.TrafficStats = false) instead
//     of the UI ever showing fabricated zeros.
//   - Capabilities takes the probe's protocol matrix and
//     reports the platform facts of THIS path: TUN available
//     (VpnService, consent-gated), no system proxy, no kill
//     switch (Step 12 lockdown wiring is still open, KI-08),
//     IPv4 only (the choreography establishes the v4 request,
//     platform.DefaultTUNRequest(false)).

import (
	"context"
	"sync/atomic"
	"time"

	"openproxy/app/android"
	"openproxy/app/platform"
	"openproxy/app/service"
	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// Bounds mirror the facade session's historical limits: the
// outer bound covers the shell's consent wait (itself bounded
// at 120s in the shell) plus interface establishment plus box
// start; stop gets the same 30s the facade always used.
const (
	tunStartTimeout = 3 * time.Minute
	tunStopTimeout  = 30 * time.Second
)

type tunEngine struct {
	probe service.Engine
	shell atomic.Pointer[android.Shell]
}

var _ service.Engine = (*tunEngine)(nil)

func newTUNEngine(probe service.Engine) *tunEngine {
	return &tunEngine{probe: probe}
}

// bind installs the assembled shell. The shell is constructed
// after the service (it consumes it), while the service is
// constructed with this engine — the pointer is the late
// binding between the two, set exactly once by the session
// assembly before either is reachable.
func (e *tunEngine) bind(shell *android.Shell) { e.shell.Store(shell) }

func (e *tunEngine) StartNode(ctx context.Context, n *specnode.Node, _ kernel.PlatformOptions) error {
	shell := e.shell.Load()
	if shell == nil {
		return platform.ErrUnavailable
	}
	// The caller's deadline is the UI's generic operation
	// budget, which does not account for a human reading the
	// OS consent dialog; detach from it and apply the session
	// bound instead (same posture as the facade path).
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tunStartTimeout)
	defer cancel()
	return shell.ConnectNode(cctx, n)
}

func (e *tunEngine) Stop(ctx context.Context) error {
	shell := e.shell.Load()
	if shell == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tunStopTimeout)
	defer cancel()
	return shell.StopTUN(cctx)
}

func (e *tunEngine) Status() kernel.Status {
	if shell := e.shell.Load(); shell != nil && shell.Connected() {
		return kernel.Status{State: kernel.StateRunning}
	}
	return kernel.Status{State: kernel.StateIdle}
}

func (e *tunEngine) Capabilities() kernel.Capabilities {
	caps := e.probe.Capabilities()
	caps.Platform.Platform = "android"
	caps.Platform.TUN = true
	caps.Platform.SystemProxy = false
	caps.Platform.KillSwitch = false
	caps.Platform.IPv6 = false
	caps.Platform.RequiresVPNPermission = true
	caps.Features.TrafficStats = false
	return caps
}

func (e *tunEngine) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	return e.probe.ValidateSpec(ctx, n)
}

func (e *tunEngine) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return e.probe.TestHandshakeNode(ctx, n)
}

func (e *tunEngine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	return nil, kernel.NewError(kernel.KindPlatformUnavailable, "QueryTraffic",
		"traffic counters are not exposed by the Android TUN path", nil)
}

func (e *tunEngine) MixedAddr() string { return "" }
