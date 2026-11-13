package libboxbind

// The app session: the libboxbind-side assembly of the Step 9
// service layer + Step 10 choreography for Android. The shell
// drives exactly three product entries — StartSession,
// StopSession, SessionStatus — plus Localize for its own
// (minimal, bootstrap) UI text; the in-process Gio product UI
// (ui_android.go) drives the SAME assembly through the service
// layer, so both surfaces share one store, one service and one
// choreography (docs/android产品界面接入.md). Store layout
// (<base>/Relavia/store.json) and the default language
// fallback mirror app/cmd/relavia-android (the gogio logic
// entry); the engine wiring does NOT — here the dispatch's
// sing-box slot is the TUN engine (engine.go), and the Step 11
// default TUN routing policy applies, neither of which the
// Gio logic build runs.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"openproxy/app/android"
	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/service"
	"openproxy/core/routecfg"
)

// --- kernel log sink -------------------------------------------------

var (
	sinkMu sync.RWMutex
	sinkFn func(level, message string)
)

func logLine(level, message string) {
	sinkMu.RLock()
	fn := sinkFn
	sinkMu.RUnlock()
	if fn != nil {
		fn(level, message)
	}
}

// --- session state -----------------------------------------------------

type appSession struct {
	mu      sync.Mutex
	shell   *android.Shell
	svc     *service.Service
	tr      *i18n.Translator
	lastErr string
}

// trAtomic mirrors appSession.tr for Localize: it is read
// WITHOUT session.mu on purpose. Localize is called by the
// shell from arbitrary threads — including from inside bridge
// callbacks that run while a session connect (which holds
// session.mu for the whole choreography) is in flight; taking
// the session lock there would deadlock the connect.
var trAtomic atomic.Pointer[i18n.Translator]

var session = &appSession{}

// ensureBuiltLocked assembles the session on first use.
// Caller holds session.mu.
func (s *appSession) ensureBuiltLocked() error {
	if s.shell != nil {
		return nil
	}
	basePath, _, _, ok := manager.paths()
	if !ok {
		return errors.New("libboxbind: Setup has not been called")
	}
	storePath := filepath.Join(basePath, "Relavia", "store.json")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		return err
	}
	store, err := service.OpenStore(storePath)
	if err != nil {
		return err
	}
	// Engine log wiring mirrors app/cmd/relavia-android: the
	// closure reads svc at call time because the engine is
	// constructed before the service that consumes its logs.
	var svc *service.Service
	logSink := func(level, message string) {
		if svc != nil {
			svc.OnKernelLog(level, message)
		}
	}
	// Protocol dispatch for Android (docs/android产品界面
	// 接入.md §3): the sing-box slot is the TUN engine, whose
	// connects run this package's choreography (consent ->
	// shell TUN -> libbox) — NOT the desktop in-process
	// adapter, whose listener would route nothing here. The
	// in-process adapter survives as the engine's probe for
	// handshake tests and spec validation. The OpenVPN slot
	// stays honestly unavailable, and the VPN Gate pool
	// source attaches as on every platform.
	probe := service.NewSingBoxEngine(logSink)
	tunEng := newTUNEngine(probe)
	engine := service.NewDispatchEngine(
		tunEng,
		service.NewAndroidOpenVPNEngine(),
	)
	svc = service.New(store, engine)
	service.AttachVPNGateDefault(svc, storePath)

	lang := store.Settings().Language
	if lang == "" {
		lang = locales.Source
	}
	tr, err := i18n.New(locales.FS, locales.Supported, lang, locales.Fallback)
	if err != nil {
		return err
	}

	// Step 11 default TUN policy for the session; if the
	// default policy ever fails to compile, run without a
	// fragment (bare final=out route) rather than failing the
	// session — and say so in the kernel log.
	var fragment *routecfg.Fragment
	if compiled, err := routecfg.Compile(routecfg.DefaultTUNPolicy()); err == nil {
		fragment = compiled
	} else {
		svc.OnKernelLog("warn", "libboxbind: default TUN policy failed to compile, continuing without it: "+err.Error())
	}

	s.shell = android.NewShell(svc, tr, android.Options{
		Starter: &tunStarter{fragment: fragment},
	})
	// Late-bind the shell into the TUN engine now that both
	// exist: from here on svc.Connect IS the choreography.
	tunEng.bind(s.shell)
	s.svc = svc
	s.tr = tr
	trAtomic.Store(tr)
	sinkMu.Lock()
	sinkFn = svc.OnKernelLog
	sinkMu.Unlock()
	return nil
}

func startSession() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.ensureBuiltLocked(); err != nil {
		return err
	}
	if session.shell.Connected() {
		return nil
	}
	nodeID := session.svc.SelectedNodeID()
	if nodeID == "" {
		return errors.New("libboxbind: no node selected")
	}
	// svc.Connect reaches the choreography through the TUN
	// engine bound into the session's dispatch (engine.go);
	// the engine applies the session time bound itself, which
	// covers the shell's consent wait plus interface
	// establishment plus box start.
	if err := session.svc.Connect(context.Background(), nodeID); err != nil {
		session.lastErr = err.Error()
		return err
	}
	session.lastErr = ""
	return nil
}

func stopSession() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.shell == nil {
		return nil
	}
	// svc.Disconnect -> dispatch Stop -> TUN engine StopTUN:
	// the choreography's unwind order (box stop -> interface
	// close -> service teardown), with the engine's own bound.
	if err := session.svc.Disconnect(context.Background()); err != nil {
		session.lastErr = err.Error()
		return err
	}
	session.lastErr = ""
	return nil
}

// --- facade entries used by the shell ---------------------------------

// StartSession connects the currently selected node through
// the full choreography (consent → establish → libbox TUN
// start). Blocking; the shell calls it off its UI thread.
func StartSession() error {
	return startSession()
}

// StopSession disconnects in the choreography's order (box
// stop → interface close → service teardown).
func StopSession() error {
	return stopSession()
}

// SessionStatus is a coarse, shell-presentable state:
// "connected", "error: <detail>", or "idle". The detail is a
// diagnostic string, not localized copy — the shell only
// distinguishes the prefix.
func SessionStatus() string {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.shell != nil && session.shell.Connected() {
		return "connected"
	}
	if session.lastErr != "" {
		return "error: " + session.lastErr
	}
	return "idle"
}

// Localize resolves a UI string key in the user's configured
// language. It replaces the Step 10 shell's JNI localize
// entry: gomobile does not generate the old hand-declared JNI
// symbols, the generated facade is the only Go surface the
// shell links against. Returns "" for unknown keys so the
// shell falls back to its bootstrap resources.
func Localize(key string) string {
	tr := trAtomic.Load()
	if tr == nil {
		// Best effort: build the session (which needs the
		// store for the configured language). If that is not
		// possible yet, serve the source pack — the shell's
		// bootstrap resources carry the same source strings.
		session.mu.Lock()
		if session.tr == nil {
			_ = session.ensureBuiltLocked()
		}
		tr = session.tr
		session.mu.Unlock()
	}
	if tr == nil {
		if packs, err := i18n.New(locales.FS, locales.Supported, locales.Source, locales.Fallback); err == nil {
			tr = packs
		}
	}
	if tr == nil {
		return ""
	}
	if v := tr.T(key, nil); v != key {
		return v
	}
	return ""
}
