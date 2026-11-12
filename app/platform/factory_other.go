//go:build !windows && !android

package platform

// Non-Windows constructors for this step: the facilities are
// honestly unavailable (Linux/macOS platform work is phase 2,
// book 8.2). The UI still runs; it simply reports no tray and no
// system-proxy/TUN control, and the tests exercise the fakes.

func NewSystemProxy() SystemProxy { return UnsupportedSystemProxy{} }

func NewTUN() TUNDevice {
	return UnsupportedTUN{Why: "TUN is not available in this build (Windows Wintun lands with the Windows platform target; Android VpnService in Step 10)"}
}

func NewTray(ev TrayEvents) Tray { return NoopTray{Events: ev} }

// NewInstaller: no in-app install path on this platform yet
// (Step 16); the honest unsupported implementation.
func NewInstaller() Installer {
	return UnsupportedInstaller{Why: "in-app update install is not available on this platform"}
}
