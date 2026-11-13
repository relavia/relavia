package platform

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Opening a URL in the system browser (the in-app guide
// entry). Desktop builds hand the URL to the OS directly
// (openurl.go / openurl_unix.go); Android cannot, so its
// OpenURL delegates to the shell through the bridge below —
// the same registry shape as InstallBinder (installer.go)
// and VPNBinder (vpn.go). The honesty contract matches the
// rest of this package: no registered binder, or a binder
// error, surfaces as a failure the caller logs before showing
// the address in plain text. Nothing pretends an open
// happened.

// ErrOpenURLUnsupported means this build has no browser-open
// mechanism wired: on Android that is exactly "no shell URL
// binder is registered" (an unbound build). The caller logs
// the failure and shows the guide address in plain text
// instead.
var ErrOpenURLUnsupported = errors.New("platform: opening a URL is not wired in this build")

// ErrOpenURLInvalid means the URL was rejected before any
// platform mechanism was consulted. Only non-empty https URLs
// may be opened: the one caller is the guide entry (a fixed
// https address), and accepting arbitrary schemes would let
// any future caller hand the shell intent an arbitrary
// handler (tel:, intent:, a local file) — refused by design.
var ErrOpenURLInvalid = errors.New("platform: refusing to open a non-https or empty URL")

// URLBinder is the shell side of the Android URL-open bridge,
// registered once at shell startup. The Kotlin shell
// implements it by firing an ACTION_VIEW intent for the URL;
// an error means the system could not open it (no browser
// installed, activity start refused).
type URLBinder interface {
	OpenURL(url string) error
}

var (
	urlBinderMu sync.RWMutex
	urlBinder   URLBinder
)

// RegisterURLBinder installs the shell-side URL binder;
// passing nil clears the registration (used by tests).
func RegisterURLBinder(b URLBinder) {
	urlBinderMu.Lock()
	defer urlBinderMu.Unlock()
	urlBinder = b
}

// RegisteredURLBinder returns the current binder, or nil.
func RegisteredURLBinder() URLBinder {
	urlBinderMu.RLock()
	defer urlBinderMu.RUnlock()
	return urlBinder
}

// BridgeURLOpener is the Go side of the Android bridge: it
// validates the URL, then delegates to the registered shell
// binder. It is available exactly when the shell has
// registered its binder.
type BridgeURLOpener struct{}

func (BridgeURLOpener) OpenURL(rawurl string) error {
	if err := validateOpenURL(rawurl); err != nil {
		return err
	}
	b := RegisteredURLBinder()
	if b == nil {
		return fmt.Errorf("%w: Android shell URL bridge not registered in this build", ErrOpenURLUnsupported)
	}
	return b.OpenURL(rawurl)
}

// validateOpenURL is the gate every bridge open passes
// first: non-empty, parseable, scheme https, host present.
func validateOpenURL(rawurl string) error {
	if strings.TrimSpace(rawurl) == "" {
		return fmt.Errorf("%w: empty URL", ErrOpenURLInvalid)
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOpenURLInvalid, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: %q", ErrOpenURLInvalid, rawurl)
	}
	return nil
}
