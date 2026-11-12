package libboxbind

// libbox service lifecycle: one CommandServer per process,
// created lazily, driving sing-box through
// StartOrReloadService / CloseService.
//
// Policy decisions (docs §3):
//
//   - The command server's gRPC listener (Start) is NOT
//     opened. Nothing in the shell speaks the command
//     protocol, and the in-process facade calls the service
//     methods directly; an unused local socket would be pure
//     attack surface. Lifecycle is driven by direct calls.
//   - FixAndroidStack is on: libbox's documented workaround
//     for the Android Go runtime stack issue (goland/go#68760,
//     per SFA practice); it is a no-op concern on the host.
//   - Stop requests arriving through the handler (only
//     reachable if a future client speaks the protocol) are
//     routed to the app session's stop, so all layers unwind
//     in the choreography's order.

import (
	"errors"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// logMaxLines bounds libbox's in-memory log buffer
// (sLogMaxLines feeds the daemon's log ring).
const logMaxLines = 1000

type serviceManager struct {
	mu           sync.Mutex
	basePath     string
	workingPath  string
	tempPath     string
	configured   bool
	libSetupDone bool
	server       *libbox.CommandServer
	platform     *platformImpl
	handler      *handlerImpl
	lastConfig   string
	running      bool
}

var manager = newServiceManager()

func newServiceManager() *serviceManager {
	m := &serviceManager{
		platform: newPlatformImpl(),
		handler:  &handlerImpl{},
	}
	m.handler.mgr = m
	return m
}

func (m *serviceManager) configure(basePath, workingPath, tempPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if basePath == "" || workingPath == "" || tempPath == "" {
		return errors.New("libboxbind: Setup requires base, working and temp paths")
	}
	m.basePath, m.workingPath, m.tempPath = basePath, workingPath, tempPath
	m.configured = true
	// The handler's ServiceStop must unwind the whole app
	// session, not just the box.
	m.handler.stopFn = func() error { return stopSession() }
	return nil
}

func (m *serviceManager) paths() (base, working, temp string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.basePath, m.workingPath, m.tempPath, m.configured
}

// ensureServerLocked creates the libbox runtime and command
// server on first use. Caller holds m.mu.
func (m *serviceManager) ensureServerLocked() error {
	if !m.configured {
		return errors.New("libboxbind: Setup has not been called")
	}
	if !m.libSetupDone {
		err := libbox.Setup(&libbox.SetupOptions{
			BasePath:          m.basePath,
			WorkingPath:       m.workingPath,
			TempPath:          m.tempPath,
			FixAndroidStack:   true,
			LogMaxLines:       logMaxLines,
			CrashReportSource: "relavia-android",
		})
		if err != nil {
			return fmt.Errorf("libboxbind: libbox setup: %w", err)
		}
		m.libSetupDone = true
	}
	if m.server == nil {
		server, err := libbox.NewCommandServer(m.handler, m.platform)
		if err != nil {
			return fmt.Errorf("libboxbind: new command server: %w", err)
		}
		m.server = server
	}
	return nil
}

// startOrReload starts the box with configContent, or reloads
// a running box onto it (libbox semantics: the old instance is
// fully closed first).
func (m *serviceManager) startOrReload(configContent string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureServerLocked(); err != nil {
		return err
	}
	// OverrideOptions must be non-nil: libbox 1.14.4's
	// StartOrReloadService dereferences it unconditionally
	// (nil panics inside the library — host-test proven).
	if err := m.server.StartOrReloadService(configContent, &libbox.OverrideOptions{}); err != nil {
		m.running = false
		// A failed start may have consumed the pending fd or
		// half-established a direct one; make the platform
		// state consistent before surfacing the error.
		m.platform.onServiceStopped()
		return fmt.Errorf("libboxbind: start service: %w", err)
	}
	m.lastConfig = configContent
	m.running = true
	return nil
}

// startWithPendingFD is startOrReload for the TUN
// choreography: pendingFD is the shell-established TUN fd the
// platform interface will hand to the tun inbound.
func (m *serviceManager) startWithPendingFD(configContent string, pendingFD int32) error {
	m.platform.setPendingFD(pendingFD)
	if err := m.startOrReload(configContent); err != nil {
		m.platform.setPendingFD(-1)
		return err
	}
	return nil
}

func (m *serviceManager) closeService() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server == nil {
		m.running = false
		return nil
	}
	err := m.server.CloseService()
	m.running = false
	m.platform.onServiceStopped()
	if err != nil {
		return fmt.Errorf("libboxbind: close service: %w", err)
	}
	return nil
}

func (m *serviceManager) serviceRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// reloadLast re-runs the most recent configuration (handler
// ServiceReload). Caller does NOT hold m.mu.
func (m *serviceManager) reloadLast() error {
	m.mu.Lock()
	last := m.lastConfig
	m.mu.Unlock()
	if last == "" {
		return errors.New("libboxbind: no configuration to reload")
	}
	return m.startOrReload(last)
}

// handlerImpl implements libbox.CommandServerHandler.
type handlerImpl struct {
	mgr    *serviceManager
	stopFn func() error
}

var _ libbox.CommandServerHandler = (*handlerImpl)(nil)

func (h *handlerImpl) ServiceStop() error {
	if h.stopFn != nil {
		return h.stopFn()
	}
	return h.mgr.closeService()
}

func (h *handlerImpl) ServiceReload() error {
	return h.mgr.reloadLast()
}

// GetSystemProxyStatus: Android has no system-proxy mode in
// this client (the Step 10 posture is unchanged), so the
// status is honestly "not available".
func (h *handlerImpl) GetSystemProxyStatus() (*libbox.SystemProxyStatus, error) {
	return &libbox.SystemProxyStatus{Available: false, Enabled: false}, nil
}

func (h *handlerImpl) SetSystemProxyEnabled(enabled bool) error {
	return errors.New("libboxbind: system proxy is not available on Android")
}

// TriggerNativeCrash is deliberately not implemented: a debug
// self-crash hook has no place in a release binding.
func (h *handlerImpl) TriggerNativeCrash() error {
	return errors.New("libboxbind: native crash trigger not implemented")
}

func (h *handlerImpl) WriteDebugMessage(message string) {
	logLine("debug", "libbox: "+message)
}

func (h *handlerImpl) ConnectSSHAgent() (int32, error) {
	return -1, errors.New("libboxbind: ssh agent not supported")
}
