package libboxbind

import (
	"testing"

	"openproxy/app/platform"
)

// RegisterShellBridge must wire the platform URL binder to
// the shell bridge, so platform.OpenURL (Android build)
// reaches ShellBridge.OpenURL with the exact URL — and the
// platform-side https gate runs before the bridge is
// consulted.
func TestShellURLOpenerDelegatesToBridge(t *testing.T) {
	fake := &fakeBridge{}
	registerFake(t, fake)
	prev := platform.RegisteredURLBinder()
	t.Cleanup(func() { platform.RegisterURLBinder(prev) })

	opener := platform.BridgeURLOpener{}
	const target = "https://relavia.github.io/guide.html"
	if err := opener.OpenURL(target); err != nil {
		t.Fatalf("OpenURL: %v", err)
	}
	fake.mu.Lock()
	opened := append([]string(nil), fake.openedURLs...)
	fake.mu.Unlock()
	if len(opened) != 1 || opened[0] != target {
		t.Fatalf("bridge opened %v, want [%s]", opened, target)
	}

	// Non-https is refused on the Go side; the bridge must
	// not see it.
	if err := opener.OpenURL("http://relavia.github.io/guide.html"); err == nil {
		t.Fatal("OpenURL(http) must be rejected")
	}
	fake.mu.Lock()
	count := len(fake.openedURLs)
	fake.mu.Unlock()
	if count != 1 {
		t.Fatalf("bridge saw %d opens, want still 1", count)
	}
}
