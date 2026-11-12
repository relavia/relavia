//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

// Windows TUN detection skeleton (book 5.4: TUN mode is based on
// Wintun; the official prebuilt signed wintun.dll is the only
// permitted distribution form, per the Step 2 license audit).
//
// STATUS (Step 9): detection only. CREATING a Wintun adapter and
// wiring it into the kernel is Step 11/12 platform work; nothing
// in this step starts a TUN device, and the sing-box adapter
// independently reports Platform.TUN=false until then.

type winTUN struct {
	once   sync.Once
	avail  bool
	detail string
}

func (t *winTUN) probe() {
	dll := windows.NewLazyDLL("wintun.dll")
	if err := dll.Load(); err != nil {
		// Also look next to the executable (the distribution
		// layout ships wintun.dll beside relavia.exe).
		if exe, err2 := os.Executable(); err2 == nil {
			candidate := filepath.Join(filepath.Dir(exe), "wintun.dll")
			if _, err3 := os.Stat(candidate); err3 == nil {
				dll = windows.NewLazyDLL(candidate)
				err = dll.Load()
			}
		}
		if err != nil {
			t.avail = false
			t.detail = "wintun.dll not found (TUN device cannot be created; TUN start itself lands in Steps 11-12)"
			return
		}
	}
	if err := dll.NewProc("WintunCreateAdapter").Find(); err != nil {
		t.avail = false
		t.detail = "wintun.dll present but WintunCreateAdapter export missing (not the official Wintun build?)"
		return
	}
	t.avail = true
	t.detail = "wintun.dll present; TUN device creation lands in Steps 11-12 and is not wired up in this step"
}

func (t *winTUN) Available() bool {
	t.once.Do(t.probe)
	return t.avail
}

func (t *winTUN) Detail() string {
	t.once.Do(t.probe)
	return t.detail
}
