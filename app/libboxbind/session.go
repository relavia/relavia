package libboxbind

// The app session: the libboxbind-side assembly of the Step 9
// service layer + Step 10 choreography for the Android shell.
// The shell drives exactly three product entries —
// StartSession, StopSession, SessionStatus — plus Localize for
// its own (minimal, bootstrap) UI text. Logic mirrors
// app/cmd/relavia-android (the Gio entry): same store layout
// (<base>/Relavia/store.json), same engine wiring, same
// default language fallback; the Android differences are the
// production starter/binder and the Step 11 default TUN
// routing policy, which the Gio logic build does not run.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

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
	engine := service.NewSingBoxEngine(func(level, message string) {
		if svc != nil {
			svc.OnKernelLog(level, message)
		}
	})
	svc = service.New(store, engine)

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
	// The outer bound covers the shell's consent wait plus
	// interface establishment plus box start.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := session.shell.Connect(ctx, nodeID); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := session.shell.Disconnect(ctx); err != nil {
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
