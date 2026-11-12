//go:build windows

package platform

// Windows constructors: real implementations (compile-verified in
// this step; real-machine verification is tracked in the Step 9
// report's pending checklist).

func NewSystemProxy() SystemProxy { return &winSystemProxy{} }

func NewTUN() TUNDevice { return &winTUN{} }

func NewTray(ev TrayEvents) Tray { return newWinTray(ev) }

// NewInstaller returns the Windows update installer (Step 16
// placeholder: reports unavailable pending real-machine
// verification — see installer_windows.go).
func NewInstaller() Installer { return winInstaller{} }
