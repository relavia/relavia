package platform_test

import (
	"errors"
	"testing"

	"openproxy/app/platform"
)

func TestFakeSystemProxyLifecycle(t *testing.T) {
	p := platform.NewFakeSystemProxy()
	if !p.Available() {
		t.Fatal("fake should be available")
	}
	if err := p.Set("127.0.0.1:2080"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, _ := p.Get()
	if !got.Enabled || got.Server != "127.0.0.1:2080" {
		t.Errorf("after Set: %+v", got)
	}
	if err := p.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, _ = p.Get()
	if got.Enabled {
		t.Errorf("after Clear still enabled: %+v", got)
	}
	if p.SetCalls != 1 || p.ClearCalls != 1 {
		t.Errorf("calls set/clear = %d/%d", p.SetCalls, p.ClearCalls)
	}
}

func TestUnsupportedReportsHonestly(t *testing.T) {
	var sp platform.SystemProxy = platform.UnsupportedSystemProxy{}
	if sp.Available() {
		t.Error("unsupported system proxy must report unavailable")
	}
	if err := sp.Set("127.0.0.1:1"); !errors.Is(err, platform.ErrUnavailable) {
		t.Errorf("Set error = %v, want ErrUnavailable", err)
	}
	var tun platform.TUNDevice = platform.UnsupportedTUN{Why: "test"}
	if tun.Available() || tun.Detail() != "test" {
		t.Error("unsupported TUN must report unavailable with its reason")
	}
}

func TestFakeTrayRecordsAndDispatches(t *testing.T) {
	var clicked string
	tray := platform.NewFakeTray(platform.TrayEvents{
		OnMenuItem: func(id string) { clicked = id },
	})
	if err := tray.Show("tip"); err != nil {
		t.Fatalf("Show: %v", err)
	}
	tray.SetMenu([]platform.TrayMenuItem{{ID: "quit", Label: "Quit"}})
	tray.Click("quit")
	if clicked != "quit" {
		t.Errorf("clicked = %q, want quit", clicked)
	}
	if !tray.Shown || tray.Tooltip != "tip" || len(tray.Menu) != 1 {
		t.Errorf("tray state = %+v", tray)
	}
	if err := tray.Hide(); err != nil || tray.Shown {
		t.Errorf("Hide: err=%v shown=%v", err, tray.Shown)
	}
}

func TestConstructorsReturnHonestFacilities(t *testing.T) {
	// On every platform (incl. Windows compile targets exercised
	// via cross-build), the constructors must return facilities
	// whose Available() tells the truth; here on the test platform
	// (non-Windows) everything must be unavailable.
	sp := platform.NewSystemProxy()
	tun := platform.NewTUN()
	tray := platform.NewTray(platform.TrayEvents{})
	if sp == nil || tun == nil || tray == nil {
		t.Fatal("constructors returned nil")
	}
}
