//go:build !android || !cgo

package libboxbind

// maybeStartProductUI is a no-op everywhere except the
// Android gomobile build: host builds (tests, vet) have no
// Android window to host, and the CGO-off android
// cross-compile gate cannot compile Gio's JNI driver. The
// real implementation is ui_android.go
// (docs/android产品界面接入.md §4).
func maybeStartProductUI() {}
