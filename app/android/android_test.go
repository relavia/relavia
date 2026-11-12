package android_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/app/android"
	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/platform"
	"openproxy/app/service"
)

// fakeStarter records the TUN data-plane hand-off.
type fakeStarter struct {
	startedFD   int
	startedNode string
	startErr    error
	stopCalls   int
}

func (f *fakeStarter) StartWithTUN(_ context.Context, n *specnode.Node, fd int, opts kernel.PlatformOptions) error {
	if opts.Mode != kernel.ModeTUN {
		return errors.New("starter invoked without TUN mode")
	}
	f.startedFD = fd
	f.startedNode = n.ID
	return f.startErr
}

func (f *fakeStarter) Stop(context.Context) error { f.stopCalls++; return nil }

func newTestShell(t *testing.T, vpn platform.VPNService, starter android.TunnelStarter) (*android.Shell, *service.Service) {
	t.Helper()
	store, err := service.OpenStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	// No kernel engine: TUN-mode choreography must not need one,
	// and manual-mode paths surface ErrNoEngine if misused.
	svc := service.New(store, nil)
	tr, err := i18n.New(locales.FS, locales.Supported, locales.Source, locales.Fallback)
	if err != nil {
		t.Fatalf("i18n.New: %v", err)
	}
	// Seed one node through the Step 8 import path.
	rep := svc.ImportText("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.0.2.1:8388#android-test")
	if rep == nil || rep.OK() != 1 {
		t.Fatalf("seed import: %+v", rep)
	}
	shell := android.NewShell(svc, tr, android.Options{VPN: vpn, Starter: starter})
	return shell, svc
}

func onlyNodeID(t *testing.T, svc *service.Service) string {
	t.Helper()
	nodes := svc.Nodes("")
	if len(nodes) != 1 {
		t.Fatalf("seeded nodes = %d, want 1", len(nodes))
	}
	return nodes[0].Record.Node.ID
}

func TestShellDefaultsToTUNMode(t *testing.T) {
	shell, svc := newTestShell(t, platform.NewFakeVPNService(), &fakeStarter{})
	if svc.Mode() != kernel.ModeTUN {
		t.Fatalf("Android shell mode = %q, want TUN (book 8.2)", svc.Mode())
	}
	if shell.Connected() {
		t.Fatal("fresh shell must not be connected")
	}
}

func TestConnectChoreographyHappyPath(t *testing.T) {
	vpn := platform.NewFakeVPNService()
	starter := &fakeStarter{}
	shell, svc := newTestShell(t, vpn, starter)
	id := onlyNodeID(t, svc)
	ctx := context.Background()

	if err := shell.Connect(ctx, id); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !shell.Connected() {
		t.Fatal("shell must report connected after successful choreography")
	}
	if vpn.PrepareCalls != 1 || vpn.EstablishCalls != 1 {
		t.Errorf("vpn calls prepare/establish = %d/%d, want 1/1", vpn.PrepareCalls, vpn.EstablishCalls)
	}
	if starter.startedNode != id || starter.startedFD < 0 {
		t.Errorf("starter got node=%q fd=%d", starter.startedNode, starter.startedFD)
	}
	if vpn.LastRequest.IPv4Address != "172.18.0.1/30" {
		t.Errorf("TUN request IPv4 = %q", vpn.LastRequest.IPv4Address)
	}
	// Second connect is refused while a session is live.
	if err := shell.Connect(ctx, id); !errors.Is(err, android.ErrAlreadyConnected) {
		t.Errorf("second Connect err = %v, want ErrAlreadyConnected", err)
	}

	if err := shell.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if shell.Connected() {
		t.Error("shell must report disconnected after Disconnect")
	}
	if starter.stopCalls != 1 || vpn.TeardownCalls != 1 {
		t.Errorf("stop/teardown calls = %d/%d, want 1/1", starter.stopCalls, vpn.TeardownCalls)
	}
	if !vpn.Handle.Closed() {
		t.Error("disconnect must close the TUN handle")
	}
}

func TestConnectPermissionDenied(t *testing.T) {
	vpn := platform.NewFakeVPNService()
	vpn.GrantConsent = false
	shell, svc := newTestShell(t, vpn, &fakeStarter{})
	err := shell.Connect(context.Background(), onlyNodeID(t, svc))
	if !errors.Is(err, android.ErrPermissionDenied) {
		t.Fatalf("Connect err = %v, want ErrPermissionDenied", err)
	}
	if vpn.EstablishCalls != 0 {
		t.Error("no interface may be established after consent denial")
	}
}

func TestConnectWithoutBinderIsUnavailable(t *testing.T) {
	shell, svc := newTestShell(t, platform.BridgeVPNService{}, &fakeStarter{})
	err := shell.Connect(context.Background(), onlyNodeID(t, svc))
	if !errors.Is(err, platform.ErrUnavailable) {
		t.Fatalf("Connect err = %v, want ErrUnavailable (honesty contract)", err)
	}
}

func TestConnectStarterFailureUnwindsSession(t *testing.T) {
	vpn := platform.NewFakeVPNService()
	boom := errors.New("data plane refused the fd")
	shell, svc := newTestShell(t, vpn, &fakeStarter{startErr: boom})
	err := shell.Connect(context.Background(), onlyNodeID(t, svc))
	if !errors.Is(err, boom) {
		t.Fatalf("Connect err = %v, want the starter error", err)
	}
	if shell.Connected() {
		t.Error("failed start must not leave the shell connected")
	}
	if !vpn.Handle.Closed() {
		t.Error("failed start must close the established handle")
	}
	if vpn.TeardownCalls != 1 {
		t.Errorf("failed start must tear the shell side down, teardown calls = %d", vpn.TeardownCalls)
	}
}

func TestConnectWithPlaceholderStarterIsUnavailable(t *testing.T) {
	vpn := platform.NewFakeVPNService()
	shell, svc := newTestShell(t, vpn, nil) // nil -> UnavailableTunnelStarter
	err := shell.Connect(context.Background(), onlyNodeID(t, svc))
	if !errors.Is(err, platform.ErrUnavailable) {
		t.Fatalf("Connect err = %v, want ErrUnavailable until libbox lands", err)
	}
}

func TestScanAndImportPlaceholder(t *testing.T) {
	shell, _ := newTestShell(t, platform.NewFakeVPNService(), &fakeStarter{})
	if _, err := shell.ScanAndImport(context.Background()); !errors.Is(err, android.ErrScanUnavailable) {
		t.Fatalf("ScanAndImport err = %v, want ErrScanUnavailable", err)
	}
}

func TestShellStringsResolveInAllPacks(t *testing.T) {
	tr, err := i18n.New(locales.FS, locales.Supported, locales.Source, locales.Fallback)
	if err != nil {
		t.Fatalf("i18n.New: %v", err)
	}
	keys := []string{
		"android.notif_channel_name",
		"android.notif_title_connected",
		"android.notif_text_connected",
		"android.notif_title_connecting",
		"android.notif_action_disconnect",
		"android.vpn_permission_title",
		"android.vpn_permission_body",
		"android.vpn_permission_denied",
		"android.scan_unavailable",
		"android.fake_vpn_notice",
	}
	for _, lang := range locales.Supported {
		if err := tr.SetLang(lang); err != nil {
			t.Fatalf("SetLang(%s): %v", lang, err)
		}
		for _, k := range keys {
			if got := tr.T(k, map[string]string{"node": "n1"}); got == "" || got == k {
				t.Errorf("lang %s key %s unresolved: %q", lang, k, got)
			}
		}
	}
}
