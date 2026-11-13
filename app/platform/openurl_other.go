//go:build !windows && !linux && !darwin

package platform

import "errors"

// ErrOpenURLUnsupported means this build has no browser-open
// mechanism wired (notably the Android build, where opening a
// URL needs an Android Intent bridge through the Kotlin shell —
// a separate follow-up, deliberately not faked here). The
// caller logs the failure and shows the guide address in plain
// text instead.
var ErrOpenURLUnsupported = errors.New("platform: opening a URL is not wired in this build")

// OpenURL always fails on this platform (see
// ErrOpenURLUnsupported).
func OpenURL(string) error {
	return ErrOpenURLUnsupported
}
