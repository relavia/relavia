package platform_test

import (
	"errors"
	"testing"

	"openproxy/app/platform"
)

// fakeURLBinder records what the bridge opener forwarded.
type fakeURLBinder struct {
	opened []string
	err    error
}

func (f *fakeURLBinder) OpenURL(url string) error {
	f.opened = append(f.opened, url)
	return f.err
}

func withURLBinder(t *testing.T, b platform.URLBinder) {
	t.Helper()
	prev := platform.RegisteredURLBinder()
	platform.RegisterURLBinder(b)
	t.Cleanup(func() { platform.RegisterURLBinder(prev) })
}

func TestBridgeURLOpenerForwardsToRegisteredBinder(t *testing.T) {
	fake := &fakeURLBinder{}
	withURLBinder(t, fake)

	const target = "https://relavia.github.io/guide.html"
	if err := (platform.BridgeURLOpener{}).OpenURL(target); err != nil {
		t.Fatalf("OpenURL: %v", err)
	}
	if len(fake.opened) != 1 || fake.opened[0] != target {
		t.Fatalf("binder received %v, want [%s]", fake.opened, target)
	}

	// A binder error (no browser, refused start) propagates
	// verbatim so the caller can log the real cause.
	boom := errors.New("no activity found to handle intent")
	fake.err = boom
	if err := (platform.BridgeURLOpener{}).OpenURL(target); !errors.Is(err, boom) {
		t.Fatalf("OpenURL error = %v, want %v", err, boom)
	}
}

func TestBridgeURLOpenerUnregisteredDegrades(t *testing.T) {
	withURLBinder(t, nil)

	err := (platform.BridgeURLOpener{}).OpenURL("https://relavia.github.io/guide.html")
	if !errors.Is(err, platform.ErrOpenURLUnsupported) {
		t.Fatalf("OpenURL error = %v, want ErrOpenURLUnsupported", err)
	}
}

func TestBridgeURLOpenerRejectsNonHTTPS(t *testing.T) {
	fake := &fakeURLBinder{}
	withURLBinder(t, fake)

	for _, bad := range []string{
		"",
		"   ",
		"http://relavia.github.io/guide.html",
		"relavia.github.io/guide.html",
		"intent://relavia.github.io/guide.html",
		"file:///data/local/tmp/guide.html",
		"https://",
	} {
		if err := (platform.BridgeURLOpener{}).OpenURL(bad); !errors.Is(err, platform.ErrOpenURLInvalid) {
			t.Fatalf("OpenURL(%q) error = %v, want ErrOpenURLInvalid", bad, err)
		}
	}
	if len(fake.opened) != 0 {
		t.Fatalf("binder must never be consulted for invalid URLs, got %v", fake.opened)
	}
}
