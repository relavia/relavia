package singbox

import (
	"context"
	"testing"

	"openproxy/core/kernel"
	"openproxy/core/killswitch"
)

// Step 12 adapter hook: the kill-switch capability must come
// from the REAL graded status source, never from the mere
// existence of the policy layer.

func TestKillSwitchHookAbsentStaysFalse(t *testing.T) {
	a := New(Options{})
	if a.Capabilities().Platform.KillSwitch {
		t.Fatal("no source attached: KillSwitch must report false")
	}
	if got := a.KillSwitchReadiness(); got != killswitch.ReadinessUnavailable {
		t.Fatalf("readiness = %s, want unavailable", got)
	}
}

func TestKillSwitchHookPolicyReadyStillFalse(t *testing.T) {
	// A real Controller over a FakeEnforcer is the Step 12
	// deliverable state: policy ready, NOT enforceable.
	ctl, err := killswitch.NewController(
		killswitch.Config{Mode: killswitch.ModeWhenConnected},
		&killswitch.FakeEnforcer{}, killswitch.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	a := New(Options{KillSwitchReport: ctl.Report})
	if got := a.KillSwitchReadiness(); got != killswitch.ReadinessPolicyReady {
		t.Fatalf("readiness = %s, want policy-ready", got)
	}
	if a.Capabilities().Platform.KillSwitch {
		t.Fatal("policy-ready must NOT be rounded up to KillSwitch=true")
	}
	ctx := context.Background()
	cfg := &kernel.Config{Node: ssKernelNode()}
	err = a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeManual, KillSwitch: true})
	if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("start with kill switch at policy-ready: err = %v, want platform_unavailable", err)
	}
}

func TestKillSwitchHookEnforceableOpensGate(t *testing.T) {
	a := New(Options{KillSwitchReport: func() killswitch.Report {
		return killswitch.Report{Readiness: killswitch.ReadinessEnforceable, State: killswitch.StateEngaged, Blocking: true}
	}})
	if !a.Capabilities().Platform.KillSwitch {
		t.Fatal("enforceable source must report KillSwitch=true")
	}
	ctx := context.Background()
	cfg := &kernel.Config{Node: ssKernelNode()}
	if err := a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeManual, KillSwitch: true}); err != nil {
		t.Fatalf("start with enforceable kill switch: %v", err)
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
