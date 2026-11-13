//go:build !windows && !linux && !darwin && !android

package platform

// OpenURL always fails on this platform: it has no
// browser-open mechanism and no shell bridge (Android, which
// has one, has its own file). The failure is
// ErrOpenURLUnsupported (openurl_bridge.go); the caller logs
// it and shows the guide address in plain text instead.
func OpenURL(string) error {
	return ErrOpenURLUnsupported
}
