//go:build android

package platform

// OpenURL opens url in the system browser through the
// Android shell bridge (openurl_bridge.go): the Kotlin shell
// fires an ACTION_VIEW intent. Only https URLs are accepted
// — the one caller is the in-app guide entry — and anything
// else is rejected on the Go side before the bridge is
// consulted. When no shell binder is registered (an unbound
// build) it degrades to ErrOpenURLUnsupported; the caller
// logs the failure and shows the address in plain text
// instead — never a silent no-op.
func OpenURL(url string) error {
	return BridgeURLOpener{}.OpenURL(url)
}
