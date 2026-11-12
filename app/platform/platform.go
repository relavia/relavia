// Package platform abstracts the OS network facilities the
// client needs (proposal book 5.4 platform network layer):
// system proxy settings, the TUN device, and the system tray.
//
// Honesty contract (book 3.3): every implementation reports its
// real capability. Facilities that are not implemented yet return
// ErrUnavailable rather than pretending to work; the UI surfaces
// that state verbatim. In this step (Step 9):
//
//   - Windows system proxy: real implementation against the
//     WinINet per-user settings (registry + InternetSetOption
//     refresh), COMPILE-VERIFIED ONLY — no Windows machine exists
//     in the build sandbox, so it is listed in the Step 9 report
//     as "implemented, pending real-machine verification".
//   - Windows TUN (Wintun): detection skeleton only; starting a
//     TUN device is Step 11/12 work and returns ErrUnavailable.
//   - Windows tray: real Shell_NotifyIcon implementation
//     (icon, tooltip, popup menu), compile-verified only.
//   - Non-Windows: unsupported implementations plus in-memory
//     fakes used by the tests and by Linux development builds.
package platform

import (
	"errors"
	"fmt"
)

// ErrUnavailable means the facility exists in the abstraction but
// is not available (yet) on this platform/build. Callers must
// surface it, never silently fall back.
var ErrUnavailable = errors.New("platform: facility unavailable")

// ProxySettings is a system-proxy configuration.
type ProxySettings struct {
	Enabled bool
	// Server is "host:port" (per-protocol servers are out of scope
	// for the WinINet unified setting used here).
	Server string
	// Bypass is the semicolon-separated exception list.
	Bypass string
}

// SystemProxy controls the OS-wide proxy setting.
type SystemProxy interface {
	// Get reads the current settings (so the client can restore
	// them later).
	Get() (ProxySettings, error)
	// Set enables the system proxy pointing at server.
	Set(server string) error
	// Clear disables the system proxy (restoring "direct").
	Clear() error
	// Available reports whether Set/Clear can work here.
	Available() bool
}

// TUNDevice is the platform TUN facility.
type TUNDevice interface {
	// Available reports whether a TUN device can be created here
	// (e.g. Wintun present on Windows).
	Available() bool
	// Detail explains the availability verdict for display/logging.
	Detail() string
}

// TrayMenuItem is one tray popup-menu entry. Labels are resolved
// by the caller (through i18n) every time the menu is (re)built,
// so a language switch is reflected without restart.
type TrayMenuItem struct {
	ID       string
	Label    string
	Disabled bool
}

// Tray is the system-tray facility. Handlers are invoked from the
// tray's own event loop; implementations must not block it.
type Tray interface {
	// Show installs the icon with a tooltip.
	Show(tooltip string) error
	// SetMenu replaces the popup menu items.
	SetMenu(items []TrayMenuItem)
	// SetTooltip updates the icon tooltip.
	SetTooltip(tooltip string)
	// Hide removes the icon.
	Hide() error
	// Available reports whether a tray exists on this platform.
	Available() bool
}

// TrayEvents are the callbacks a Tray implementation invokes.
type TrayEvents struct {
	OnShowWindow func()
	OnMenuItem   func(id string)
	OnQuit       func()
}

// Describe renders an availability error for logs.
func Describe(what string, err error) string {
	if errors.Is(err, ErrUnavailable) {
		return fmt.Sprintf("%s: unavailable on this platform/build", what)
	}
	return fmt.Sprintf("%s: %v", what, err)
}
