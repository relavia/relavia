//go:build !windows

package platform

// SystemDarkMode reports whether the operating system is in a
// dark appearance. On platforms other than Windows there is no
// single supported query the app can make from here (Linux
// desktop environments each expose their own settings store),
// so ok is false and the caller falls back to the light
// background, saying so in the settings UI — the v3 design
// requires the fallback to be honest, not silent.
func SystemDarkMode() (dark bool, ok bool) {
	return false, false
}
