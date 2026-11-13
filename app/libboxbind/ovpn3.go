package libboxbind

import (
	"sync"
)

// OpenVPN 3 bridge (docs/openvpn3安卓接线.md): the Android
// OpenVPN slot of the protocol dispatch is served by the
// OpenVPN 3 core library running inside the shell's VPN
// service — a child process cannot run on Android, so the
// session is hosted natively and Go talks to it through this
// bridge, the same shape as ShellBridge for the libbox path.
//
// The native library is libovpn3android.so (pinned upstream
// openvpn3 taken under MPL-2.0, docs/openvpn3许可证审查.md),
// built by android/openvpn3/build-openvpn3-android.sh. When
// the shell registers no Ovpn3Bridge, the engine in
// ovpn3engine.go degrades to exactly the honest-unavailable
// behaviour the slot had before (KindPlatformUnavailable):
// a build without the native side must never pretend.

// Ovpn3Bridge is implemented by the Android shell (Kotlin) and
// registered via RegisterOvpn3Bridge. Methods are called from
// Go service goroutines; implementations must be thread-safe.
type Ovpn3Bridge interface {
	// StartOvpn3Session hands a rendered profile and its
	// credentials to the native session. The profile text
	// never contains the credentials (openvpn.RenderProfile
	// guarantees this); they travel as separate arguments
	// into the core's ProvideCreds. Returning an error means
	// the session could not even be launched (service start
	// failure, library missing); the session outcome itself
	// is reported asynchronously through NotifyOvpn3Event.
	StartOvpn3Session(profile string, username string, password string) error
	// StopOvpn3Session asks the native session to disconnect.
	// Idempotent; the terminal DISCONNECTED event follows
	// through NotifyOvpn3Event.
	StopOvpn3Session() error
}

var (
	ovpn3BridgeMu sync.RWMutex
	ovpn3Bridge   Ovpn3Bridge
)

// RegisterOvpn3Bridge is called by the shell once at process
// start when the OpenVPN 3 native side is present in the APK.
func RegisterOvpn3Bridge(b Ovpn3Bridge) {
	ovpn3BridgeMu.Lock()
	ovpn3Bridge = b
	ovpn3BridgeMu.Unlock()
}

func currentOvpn3Bridge() Ovpn3Bridge {
	ovpn3BridgeMu.RLock()
	defer ovpn3BridgeMu.RUnlock()
	return ovpn3Bridge
}

// NotifyOvpn3Event is the native side's event channel into
// Go, in the style of NotifyTunRevoked: the shell's OpenVPN 3
// client forwards every core event (name and info verbatim
// from ClientAPI::Event, fatal flag included) and the bridge
// engine classifies it onto the desktop adapter's stable
// taxonomy. Safe to call when no engine exists (dropped).
func NotifyOvpn3Event(name string, info string, fatal bool) {
	if e := activeOvpn3Engine.Load(); e != nil {
		e.onNativeEvent(name, info, fatal)
	}
}

// NotifyOvpn3Traffic feeds the session's byte counters (the
// shell polls the core's transport/interface statistics while
// connected). Counters are cumulative for the live session.
func NotifyOvpn3Traffic(uploadBytes int64, downloadBytes int64) {
	if e := activeOvpn3Engine.Load(); e != nil {
		e.onTraffic(uint64(uploadBytes), uint64(downloadBytes))
	}
}

// NotifyOvpn3Log forwards one line of native core log output
// into the engine's log sink (the client's local log view).
// Log text from the core never contains credentials: profiles
// reach the core without credential material, and the core
// does not echo ProvideCreds values.
func NotifyOvpn3Log(message string) {
	if e := activeOvpn3Engine.Load(); e != nil {
		e.logLine(message)
	}
}
