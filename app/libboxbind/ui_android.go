//go:build android && cgo

package libboxbind

// Product UI bootstrap for the merged Android APK
// (docs/android产品界面接入.md §2/§4).
//
// Build constraint: the Gio Android driver is cgo/JNI code, so
// this file compiles only into the gomobile build (CGO on,
// GOOS android). Host builds and the CGO-off cross-compile
// gate (scripts/build-android.sh check) see ui_stub.go's no-op
// instead — the same reason app/cmd/relavia-android is not
// part of that gate.
//
// How the UI starts without a Go main of our own: the library
// is gomobile's c-shared build, whose generated main is a
// stub; Gio's Java side (vendored org.gioui classes in the
// Gradle project) runs the library's main through
// Gio.runGoMain and gets that stub, harmlessly. The product
// window loop therefore starts from the one entry the shell
// always calls first — the Setup facade, via
// maybeStartProductUI — on its own goroutine, and blocks on
// window events until the Gio view attaches. Creating the Gio
// window before any view exists is the driver's normal state
// (the desktop entry points do the same); views attach and
// detach over the process lifetime while the loop persists.
//
// The UI is assembled over the SESSION's service and
// translator (ensureBuiltLocked), never a second assembly:
// node selection, imports and VPN Gate state are one store,
// and Connect reaches the TUN choreography through the
// session's engine wiring (engine.go). There is exactly one
// service instance in this process.

import (
	"sync"
	"sync/atomic"
	"time"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"openproxy/app/platform"
	"openproxy/app/ui"
)

var productUIOnce sync.Once

// maybeStartProductUI launches the product window loop once
// per process. Called from the Setup facade: every process
// entry point of the shell (Application, VpnService) funnels
// through ShellRuntime.ensureStarted -> Libboxbind.setup, so
// the loop is up before any surface can need it. If the
// process was started for the service alone (always-on VPN,
// boot), the loop simply blocks on window events at no
// meaningful cost until the user opens the activity.
func maybeStartProductUI() {
	productUIOnce.Do(func() { go runProductUI() })
}

func runProductUI() {
	// NO-AUTO-RECONNECT INVARIANT (2026-11-14 fix batch,
	// diagnosis §4③): application startup must never start a
	// session, restore a previous connection, or schedule one.
	// A connection begins only from an explicit user action in
	// the shell (connect button, one-tap hero). The 2026-11-14
	// device report "it turned itself back on" was traced to
	// the one-tap chain surviving Disconnect, not to startup —
	// the chain cancellation is fixed in the service layer —
	// and this path stays connect-free so it cannot regress:
	// nothing below this comment may call Connect /
	// OneTapConnect / engine.StartNode.
	session.mu.Lock()
	err := session.ensureBuiltLocked()
	svc, tr := session.svc, session.tr
	session.mu.Unlock()
	if err != nil {
		logLine("error", "libboxbind: product UI assembly failed: "+err.Error())
		return
	}

	th := material.NewTheme()
	th.Shaper = ui.NewShaper()

	shell := ui.New(svc, tr, th)
	shell.Tray = platform.NewTray(platform.TrayEvents{})

	// Periodic refresh while running (traffic + status),
	// mirroring both desktop and logic-build entry points.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if w := currentWindow.Load(); w != nil {
				w.Invalidate()
			}
		}
	}()

	// Window lifetime: a DestroyEvent ends ONE window, not
	// the product UI. On Android the process routinely
	// outlives its activity (the VPN foreground service keeps
	// it alive), and the user can relaunch the activity in
	// the same process — a fresh window must serve that
	// launch. Recreate the window and keep the same UI state.
	for {
		w := new(app.Window)
		w.Option(
			app.Title(tr.T("app.title", nil)),
			app.Size(unit.Dp(420), unit.Dp(760)),
		)
		ui.SetInvalidateFunc(w.Invalidate)
		currentWindow.Store(w)
		if !runWindow(w, shell) {
			return
		}
		currentWindow.CompareAndSwap(w, nil)
		// Avoid a spin loop if a window is destroyed
		// immediately (e.g. view churn during process
		// teardown); the next launch still gets a window
		// within a frame or two of human perception.
		time.Sleep(300 * time.Millisecond)
	}
}

// currentWindow is the live window incarnation, swapped per
// incarnation for the refresh ticker above.
var currentWindow atomic.Pointer[app.Window]

// runWindow pumps one window until its DestroyEvent. It
// returns false only when the destroy carries an error worth
// abandoning the UI for (none are known on Android today;
// errors are logged either way).
func runWindow(w *app.Window, shell *ui.App) bool {
	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			if e.Err != nil {
				logLine("error", "libboxbind: product window destroyed with error: "+e.Err.Error())
			}
			return true
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			shell.Layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}
