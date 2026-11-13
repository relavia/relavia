package libboxbind

// Host-side proof of the TUN engine wiring
// (docs/android产品界面接入.md §3): the service layer's
// Connect — the only path the product UI has — must reach the
// Step 10 choreography (consent -> establish -> starter)
// through the dispatch, a consent refusal must surface as
// android.ErrPermissionDenied, and Disconnect must unwind
// without recursing through the engine. The data plane itself
// is a fake starter here; the production starter's libbox
// start chain is covered by TestLibboxServiceLifecycleHost.

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"openproxy/app/android"
	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/platform"
	"openproxy/app/service"
	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// fakeTUNStarter records the choreography's data-plane hand-off.
type fakeTUNStarter struct {
	startedFD   atomic.Int64
	startedNode atomic.Value // string
	startErr    error
	stopCalls   atomic.Int64
}

func (f *fakeTUNStarter) StartWithTUN(_ context.Context, n *specnode.Node, fd int, opts kernel.PlatformOptions) error {
	if opts.Mode != kernel.ModeTUN {
		return errors.New("starter invoked without TUN mode")
	}
	f.startedFD.Store(int64(fd))
	f.startedNode.Store(n.ID)
	return f.startErr
}

func (f *fakeTUNStarter) Stop(context.Context) error {
	f.stopCalls.Add(1)
	return nil
}

// buildEngineSession assembles the production shape — store,
// dispatch with the TUN engine in the sing-box slot, shell
// with fakes — the way ensureBuiltLocked does, minus libbox.
func buildEngineSession(t *testing.T, vpn *platform.FakeVPNService, starter *fakeTUNStarter) (*service.Service, *tunEngine) {
	t.Helper()
	store, err := service.OpenStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	probe := service.NewSingBoxEngine(func(string, string) {})
	eng := newTUNEngine(probe)
	svc := service.New(store, service.NewDispatchEngine(eng, service.NewAndroidOpenVPNEngine()))
	rep := svc.ImportText("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.0.2.1:8388#engine-test")
	if rep == nil || rep.OK() != 1 {
		t.Fatalf("seed import: %+v", rep)
	}
	tr, err := i18n.New(locales.FS, locales.Supported, locales.Source, locales.Fallback)
	if err != nil {
		t.Fatalf("i18n.New: %v", err)
	}
	shell := android.NewShell(svc, tr, android.Options{VPN: vpn, Starter: starter})
	eng.bind(shell)
	return svc, eng
}

func seededNodeID(t *testing.T, svc *service.Service) string {
	t.Helper()
	nodes := svc.Nodes("")
	if len(nodes) != 1 {
		t.Fatalf("seeded nodes = %d, want 1", len(nodes))
	}
	return nodes[0].Record.Node.ID
}

func TestTUNEngineConnectViaService(t *testing.T) {
	starter := &fakeTUNStarter{}
	svc, eng := buildEngineSession(t, platform.NewFakeVPNService(), starter)
	id := seededNodeID(t, svc)

	if err := svc.Connect(context.Background(), id); err != nil {
		t.Fatalf("svc.Connect: %v", err)
	}
	if got := starter.startedNode.Load(); got != id {
		t.Fatalf("starter saw node %v, want %s", got, id)
	}
	if svc.Status().State != kernel.StateRunning {
		t.Fatalf("status after connect = %v, want running", svc.Status().State)
	}
	if eng.Status().State != kernel.StateRunning {
		t.Fatalf("engine status after connect = %v, want running", eng.Status().State)
	}

	if err := svc.Disconnect(context.Background()); err != nil {
		t.Fatalf("svc.Disconnect: %v", err)
	}
	if starter.stopCalls.Load() != 1 {
		t.Fatalf("starter stops = %d, want 1", starter.stopCalls.Load())
	}
	if svc.Status().State != kernel.StateIdle {
		t.Fatalf("status after disconnect = %v, want idle", svc.Status().State)
	}
	// A second Disconnect (idle) must be a no-op, not a
	// recursion through engine -> shell -> service.
	if err := svc.Disconnect(context.Background()); err != nil {
		t.Fatalf("idle svc.Disconnect: %v", err)
	}
}

func TestTUNEngineConsentRefused(t *testing.T) {
	starter := &fakeTUNStarter{}
	vpn := platform.NewFakeVPNService()
	vpn.GrantConsent = false
	svc, _ := buildEngineSession(t, vpn, starter)
	id := seededNodeID(t, svc)

	err := svc.Connect(context.Background(), id)
	if !errors.Is(err, android.ErrPermissionDenied) {
		t.Fatalf("connect with refused consent = %v, want ErrPermissionDenied", err)
	}
	if starter.startedNode.Load() != nil {
		t.Fatal("starter must not run when consent is refused")
	}
	if svc.Status().State != kernel.StateIdle {
		t.Fatalf("status after refused connect = %v, want idle", svc.Status().State)
	}
}

func TestTUNEngineCapabilities(t *testing.T) {
	eng := newTUNEngine(service.NewSingBoxEngine(func(string, string) {}))
	caps := eng.Capabilities()
	if caps.Platform.Platform != "android" || !caps.Platform.TUN {
		t.Fatalf("platform caps = %+v, want android with TUN", caps.Platform)
	}
	if caps.Platform.SystemProxy || caps.Platform.KillSwitch || caps.Platform.IPv6 {
		t.Fatalf("platform caps overclaim: %+v", caps.Platform)
	}
	if !caps.Platform.RequiresVPNPermission {
		t.Fatal("RequiresVPNPermission must be reported (VpnService consent)")
	}
	if caps.Features.TrafficStats {
		t.Fatal("TrafficStats must be false: QueryTraffic honestly fails on this path")
	}
	if _, err := eng.QueryTraffic(context.Background()); err == nil {
		t.Fatal("QueryTraffic must fail explicitly, not fabricate counters")
	}
	if eng.MixedAddr() != "" {
		t.Fatal("MixedAddr must be empty: TUN mode has no local listener")
	}
	// Unbound engine: StartNode refuses, Stop stays a no-op.
	if err := eng.StartNode(context.Background(), &specnode.Node{}, kernel.PlatformOptions{}); !errors.Is(err, platform.ErrUnavailable) {
		t.Fatalf("unbound StartNode = %v, want ErrUnavailable", err)
	}
	if err := eng.Stop(context.Background()); err != nil {
		t.Fatalf("unbound Stop: %v", err)
	}
}
