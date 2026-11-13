//go:build (linux || darwin) && !android

// Note the explicit !android: the android target satisfies
// the linux constraint, so without it this file would also
// be selected for Android builds and collide with
// openurl_android.go (verified against the toolchain).

package platform

import (
	"os/exec"
	"runtime"
)

// OpenURL opens url in the system default browser (xdg-open on
// Linux, open on macOS). Used for the in-app "illustrated
// guide" entry. A failure is returned to the caller, which
// logs it and tells the user the address in plain text — a
// failed open must never be silent.
func OpenURL(url string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.Command(name, url).Start()
}
