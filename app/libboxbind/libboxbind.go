// Package libboxbind is the gomobile facade that binds the
// Relavia client to the Android shell (libbox binding;
// docs/libbox绑定.md).
//
// This is the ONLY package bound into the Android AAR
// (gomobile bind, sagernet fork v0.1.13 — the toolchain
// sing-box v1.14.4's own Makefile pins). Everything exported
// here is a gomobile-safe primitive (string, int32, bool,
// error, structs of those); implementation types — the libbox
// PlatformInterface, the CommandServer handler, the VPNBinder
// and the TunnelStarter — stay unexported inside the package,
// so nothing outside the gomobile type system crosses the
// binding boundary.
//
// Division of labour (design doc §2):
//
//   - Kotlin shell (android/): owns android.net.VpnService —
//     consent, the TUN interface via VpnService.Builder,
//     protect(), notifications, interface monitoring. It
//     implements ShellBridge below.
//   - This package (Go): owns the sing-box data plane through
//     libbox (Setup, CommandServer lifecycle), compiles the
//     TUN configuration (core/singbox.CompileTunConfig), and
//     runs the Step 10 connection choreography
//     (app/android.Shell) with the production binder/starter
//     installed, replacing the "no binding ⇒ explicit failure"
//     placeholder contract.
//
// The fd contract: the shell establishes the TUN interface and
// owns the ParcelFileDescriptor; the choreography passes the
// raw fd number to the starter, which parks it as "pending";
// when libbox's tun inbound asks the platform interface to
// open the tun, the pending fd is returned and libbox dups it
// internally — sing-tun owns the duplicate, the shell keeps
// (and eventually closes) the original. protect() flows the
// other way: route.auto_detect_interface makes every outbound
// dial present its socket fd to AutoDetectInterfaceControl,
// which delegates to the shell's VpnService.protect — without
// it the box's own outbound sockets would be routed back into
// the tunnel and the tunnel would connect to itself.
package libboxbind

import (
	"errors"
	"sync"

	"openproxy/app/platform"
)

// TunParams is the bridge encoding of a TUN establishment
// request. Lists travel comma-joined because gomobile structs
// cannot carry slices (only []byte); every entry is a plain
// IP/CIDR string with no commas of its own.
type TunParams struct {
	// Inet4Address is a CIDR ("172.18.0.1/30"), "" when absent.
	Inet4Address string
	// Inet6Address is a CIDR ("fd00::1/126"), "" when absent.
	Inet6Address string
	// DNSServers is a comma-joined list of DNS server IPs.
	DNSServers string
	// Routes is a comma-joined list of CIDR routes; "" means
	// the default route (0.0.0.0/0, plus ::/0 when an IPv6
	// address is present).
	Routes string
	// MTU is the interface MTU.
	MTU int32
}

// ShellBridge is implemented by the Android shell (Kotlin) and
// registered via RegisterShellBridge. Every method is called
// from Go, possibly on libbox's own goroutines; the shell
// implementation must be thread-safe and must bound any wait
// it performs (consent, service start) so a stuck shell cannot
// wedge the data plane.
type ShellBridge interface {
	// Prepare reports whether VPN consent is currently
	// granted, obtaining it (via the consent activity) when
	// the shell can still show UI. false means the user (or
	// the system) refused.
	Prepare() (bool, error)
	// EstablishTun creates the TUN interface from params and
	// returns its raw fd. The shell keeps ownership of the
	// underlying ParcelFileDescriptor.
	EstablishTun(params *TunParams) (int32, error)
	// CloseTun closes the established interface, if any.
	// Idempotent.
	CloseTun() error
	// ProtectSocket is VpnService.protect(fd): it exempts the
	// socket from the VPN so the kernel's outbound dials do
	// not loop into the tunnel.
	ProtectSocket(fd int32) bool
	// Teardown stops the VPN service entirely (interface,
	// foreground state, process service). Idempotent.
	Teardown() error
	// ConnectionOwnerUid resolves the owning uid of a
	// connection (ConnectivityManager.getConnectionOwnerUid),
	// or -1 when unknown/unsupported (pre-API-29).
	ConnectionOwnerUid(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) int32
	// PackagesForUid returns the comma-joined package names
	// for a uid, "" when none.
	PackagesForUid(uid int32) string
	// StartInterfaceMonitor begins default-network callbacks;
	// changes are reported back through
	// NotifyDefaultInterface.
	StartInterfaceMonitor() error
	// StopInterfaceMonitor ends those callbacks.
	StopInterfaceMonitor() error
	// WifiState returns "ssid\nbssid" for the current Wi-Fi
	// network, or "" when unavailable or unpermitted.
	WifiState() string
	// PostNotification shows a kernel-originated notification.
	PostNotification(identifier string, title string, body string) error
	// CancelNotification dismisses it by identifier.
	CancelNotification(identifier string) error
}

var (
	bridgeMu sync.RWMutex
	bridge   ShellBridge
)

// RegisterShellBridge is called by the shell once at process
// start. It also installs the production VPNBinder into the
// app/platform registry, which is what upgrades
// BridgeVPNService (Step 10) from "explicitly unavailable" to
// the real shell binding.
func RegisterShellBridge(b ShellBridge) {
	bridgeMu.Lock()
	bridge = b
	bridgeMu.Unlock()
	if b != nil {
		platform.RegisterVPNBinder(shellBinder{})
	}
}

func currentBridge() ShellBridge {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	return bridge
}

// Setup records the shell's storage paths and performs cheap
// one-time wiring. basePath is the app's private files dir,
// workingPath libbox's working directory (created by libbox),
// tempPath a cache directory. The libbox runtime itself is
// set up lazily on first service start: libbox.Setup hijacks
// the process stderr into its crash log, which must not happen
// before the shell has finished starting.
//
// Setup is also the product UI's start signal
// (docs/android产品界面接入.md §4): every shell entry point
// funnels through it before any surface exists, and the
// gomobile library has no main of its own for Gio's Java side
// to run, so the window loop launches from here (Android
// builds only; a no-op elsewhere).
func Setup(basePath, workingPath, tempPath string) error {
	if err := manager.configure(basePath, workingPath, tempPath); err != nil {
		return err
	}
	maybeStartProductUI()
	return nil
}

// StartService starts (or reloads) the sing-box service with
// the given configuration content — the low-level libbox
// lifecycle entry, exported for the shell and for tests. The
// app session (StartSession) is the product path; this entry
// performs no node selection and no TUN choreography.
func StartService(configContent string) error {
	return manager.startOrReload(configContent)
}

// CloseService stops the sing-box service. The command server
// object survives; a later StartService reloads into it.
func CloseService() error {
	return manager.closeService()
}

// ServiceRunning reports whether the box is up.
func ServiceRunning() bool {
	return manager.serviceRunning()
}

// NotifyDefaultInterface is called by the shell's network
// callbacks whenever the default network changes; it forwards
// to the listener libbox registered through the platform
// interface (no-op when the service is not running).
func NotifyDefaultInterface(name string, index int32, expensive bool, constrained bool) {
	manager.platform.notifyDefaultInterface(name, index, expensive, constrained)
}

// NotifyTunRevoked is called by the shell when the system
// revokes the VPN (VpnService.onRevoke: another VPN app, user
// toggle, always-on conflict). The box is closed first — its
// dup'd fd is dead with the interface — then the app session
// is unwound best-effort so UI state cannot claim a connection
// that no longer exists.
func NotifyTunRevoked() {
	_ = manager.closeService()
	_ = stopSession()
}

// ErrNoBridge is returned by bridge-dependent operations when
// the shell has not registered (pure logic builds, tests on
// the host). It is a build/host condition, not a user-facing
// failure mode of the release APK (docs §5).
var ErrNoBridge = errors.New("libboxbind: shell bridge not registered")
