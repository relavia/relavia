package service_test

import (
	"testing"

	"openproxy/core/selfdev"

	"openproxy/app/service"
)

// Assembly proof for the self-developed Shadowsocks route: the
// production primary engine must BE the composite adapter, and
// the persisted backend gear must reach the adapter's policy —
// the object that makes the routing decision at connection
// time — through the exact assembly the entry points build
// (composite engine inside the dispatch engine inside
// Service.New). This test exists because the composite once
// shipped fully tested inside the core module while no
// production path imported it; a green core suite must never
// again be mistaken for a wired product.

func TestCompositeEngineCarriesSelfdevAdapter(t *testing.T) {
	eng := service.NewCompositeEngine(nil)
	if eng.Adapter == nil {
		t.Fatal("CompositeEngine.Adapter is nil: the composite adapter is not constructed")
	}
	if eng.SingBox == nil {
		t.Fatal("CompositeEngine.SingBox is nil: the wrapped sing-box adapter is not constructed")
	}
	if got := eng.Capabilities().KernelID; got != "selfdev" {
		t.Errorf("Capabilities().KernelID = %q, want %q (the composite reports its own kernel ID)", got, "selfdev")
	}
	if got := eng.Adapter.Policy(); got != selfdev.PolicySingbox {
		t.Errorf("initial policy = %v, want PolicySingbox (the default gear)", got)
	}
	// The gear switch must move the adapter's policy — the
	// decision-point state — for every gear, with unknown
	// names falling back to the default.
	for name, want := range map[string]selfdev.Policy{
		service.BackendAuto:    selfdev.PolicyAuto,
		service.BackendSelfdev: selfdev.PolicySelfdev,
		service.BackendSingbox: selfdev.PolicySingbox,
		"bogus":                selfdev.PolicySingbox,
	} {
		eng.SetBackendPolicy(name)
		if got := eng.Adapter.Policy(); got != want {
			t.Errorf("SetBackendPolicy(%q): adapter policy = %v, want %v", name, got, want)
		}
		if got := eng.BackendPolicy(); got != want.String() {
			t.Errorf("SetBackendPolicy(%q): BackendPolicy() = %q, want %q", name, got, want.String())
		}
	}
}

func TestBackendGearReachesAdapterThroughProductionAssembly(t *testing.T) {
	store, err := service.OpenStore("") // in-memory
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	// A gear persisted by a previous run must be live in the
	// adapter the moment the service is assembled — no entry
	// point applies it by hand.
	store.UpdateSettings(func(st *service.Settings) { st.Backend = service.BackendSelfdev })

	primary := service.NewCompositeEngine(nil)
	dispatch := service.NewDispatchEngine(primary, nil)
	svc := service.New(store, dispatch)

	if got := primary.Adapter.Policy(); got != selfdev.PolicySelfdev {
		t.Fatalf("after Service.New with persisted gear %q: adapter policy = %v, want PolicySelfdev",
			service.BackendSelfdev, got)
	}
	if got := svc.BackendPolicy(); got != service.BackendSelfdev {
		t.Errorf("Service.BackendPolicy() = %q, want %q", got, service.BackendSelfdev)
	}
	if got := dispatch.BackendPolicy(); got != service.BackendSelfdev {
		t.Errorf("DispatchEngine.BackendPolicy() = %q, want %q", got, service.BackendSelfdev)
	}

	// Switching the gear through the service moves the
	// adapter and persists the normalized value.
	svc.SetBackendPolicy(service.BackendAuto)
	if got := primary.Adapter.Policy(); got != selfdev.PolicyAuto {
		t.Errorf("after SetBackendPolicy(auto): adapter policy = %v, want PolicyAuto", got)
	}
	if got := store.Settings().Backend; got != service.BackendAuto {
		t.Errorf("persisted gear = %q, want %q", got, service.BackendAuto)
	}

	svc.SetBackendPolicy("bogus")
	if got := primary.Adapter.Policy(); got != selfdev.PolicySingbox {
		t.Errorf("after SetBackendPolicy(bogus): adapter policy = %v, want PolicySingbox", got)
	}
	if got := store.Settings().Backend; got != service.BackendSingbox {
		t.Errorf("persisted gear after bogus = %q, want normalized %q", got, service.BackendSingbox)
	}
}
