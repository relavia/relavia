package platform

import (
	"fmt"
	"sync"
)

// Update installation hand-off (Step 16). After the service
// layer has downloaded an update artifact and verified its
// SHA-256 and Ed25519 release signature, an Installer is the
// last step: handing the verified file to the operating system's
// install path. The verification itself never lives here — an
// Installer only ever receives files that already passed.
//
// Honesty contract (book 3.3), as everywhere in this package:
// an Installer that cannot really install reports
// Available() == false and Install returns ErrUnavailable; the
// service layer surfaces that as update.install_unavailable and
// the verified package is kept for manual installation. Nothing
// here pretends an install happened.

// Installer hands a verified update artifact to the OS.
type Installer interface {
	// Available reports whether Install can really work here.
	Available() bool
	// Install starts the platform install flow for the artifact
	// at path. Returning an error must leave the currently
	// installed version fully usable.
	Install(path string) error
}

// UnsupportedInstaller is the honest placeholder for platforms
// without an install path.
type UnsupportedInstaller struct{ Why string }

func (u UnsupportedInstaller) Available() bool { return false }

func (u UnsupportedInstaller) Install(string) error {
	if u.Why != "" {
		return fmt.Errorf("%w: %s", ErrUnavailable, u.Why)
	}
	return ErrUnavailable
}

// ---------------------------------------------------------------------------
// Android shell bridge (Step 10 shell owns the system installer)
// ---------------------------------------------------------------------------

// InstallBinder is the shell side of the Android install bridge,
// registered once at shell startup. The Kotlin shell implements
// it by firing the system package-installer intent for the APK
// at path (intent construction and the REQUEST_INSTALL_PACKAGES
// consent flow are shell-side; this Go interface is the seam
// Step 10's shell binds to, alongside VPNBinder in vpn.go).
type InstallBinder interface {
	InstallUpdate(path string) error
}

var (
	installBinderMu sync.RWMutex
	installBinder   InstallBinder
)

// RegisterInstallBinder installs the shell-side install binder;
// passing nil clears the registration (used by tests).
func RegisterInstallBinder(b InstallBinder) {
	installBinderMu.Lock()
	defer installBinderMu.Unlock()
	installBinder = b
}

// RegisteredInstallBinder returns the current binder, or nil.
func RegisteredInstallBinder() InstallBinder {
	installBinderMu.RLock()
	defer installBinderMu.RUnlock()
	return installBinder
}

// BridgeInstaller is the Go side of the Android bridge: it is
// available exactly when the shell has registered its binder.
type BridgeInstaller struct{}

func (BridgeInstaller) Available() bool { return RegisteredInstallBinder() != nil }

func (BridgeInstaller) Install(path string) error {
	b := RegisteredInstallBinder()
	if b == nil {
		return fmt.Errorf("%w: Android shell install bridge not registered in this build", ErrUnavailable)
	}
	return b.InstallUpdate(path)
}
