package killswitch

import (
	"errors"
	"path/filepath"
	"testing"
)

func newTestController(t *testing.T, mode Mode) (*Controller, *FakeEnforcer, *MemoryStore) {
	t.Helper()
	enf := &FakeEnforcer{}
	store := NewMemoryStore()
	c, err := NewController(Config{Mode: mode, Endpoints: []Endpoint{{Address: "203.0.113.7", Port: 443}}}, enf, store)
	if err != nil {
		t.Fatal(err)
	}
	return c, enf, store
}

func engage(t *testing.T, c *Controller) {
	t.Helper()
	if err := c.SessionStart(); err != nil {
		t.Fatalf("SessionStart: %v", err)
	}
	if err := c.TunnelUp(); err != nil {
		t.Fatalf("TunnelUp: %v", err)
	}
	if st := c.Status(); st.State != StateEngaged || !st.Blocking || !st.EnforcerApplied {
		t.Fatalf("not engaged: %+v", st)
	}
}

// --- fault injection: tunnel crash / kernel failure -----------

func TestTunnelCrashKeepsBlocking(t *testing.T) {
	c, enf, _ := newTestController(t, ModeWhenConnected)
	engage(t, c)
	applies := enf.ApplyCalls
	if err := c.TunnelDown(ReasonKernelFailed); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if st.State != StateRecovering {
		t.Errorf("state = %s, want recovering", st.State)
	}
	if !st.Blocking || !st.EnforcerApplied {
		t.Errorf("blocking must persist through kernel failure: %+v", st)
	}
	if enf.RemoveCalls != 0 {
		t.Error("TunnelDown touched the enforcer's Remove — that is the leak path")
	}
	if enf.ApplyCalls != applies {
		t.Error("TunnelDown re-applied rules (invariant I5: blocking-state transitions never touch the enforcer)")
	}
	if st.LastFault != ReasonKernelFailed {
		t.Errorf("LastFault = %q", st.LastFault)
	}
}

func TestTunnelDroppedAndNetworkLostKeepBlocking(t *testing.T) {
	for _, reason := range []FaultReason{ReasonTunnelDropped, ReasonNetworkLost} {
		c, enf, _ := newTestController(t, ModeAlwaysOn)
		engage(t, c)
		if err := c.TunnelDown(reason); err != nil {
			t.Fatal(err)
		}
		if st := c.Status(); !st.Blocking || enf.RemoveCalls != 0 {
			t.Errorf("reason %s released the block: %+v removes=%d", reason, st, enf.RemoveCalls)
		}
	}
}

// --- fault injection: process kill + restart ------------------

func TestProcessKillRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ks.json")
	cfg := Config{Mode: ModeWhenConnected, Endpoints: []Endpoint{{Address: "203.0.113.7", Port: 443}}}

	enf1 := &FakeEnforcer{}
	c1, err := NewController(cfg, enf1, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	engage(t, c1)
	// === process killed here: c1 is abandoned with no
	// UserDisconnect/Disable, rules "still applied" in enf1's
	// world — but a real reboot also clears OS rules, so the
	// new process gets a FRESH enforcer with nothing applied.
	enf2 := &FakeEnforcer{}
	c2, err := NewController(cfg, enf2, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	st := c2.Status()
	if st.State != StateRecovering {
		t.Errorf("restored state = %s, want recovering (engaged cannot survive its process)", st.State)
	}
	if !st.Blocking || !st.RestoredAfterCrash {
		t.Errorf("restored controller must be blocking + flagged: %+v", st)
	}
	if enf2.ApplyCalls != 1 || !enf2.Applied() {
		t.Errorf("restore must re-apply before anything else: applies=%d applied=%v", enf2.ApplyCalls, enf2.Applied())
	}
	if st.LastFault != ReasonProcessKilled {
		t.Errorf("LastFault = %q, want process-killed", st.LastFault)
	}
	if !st.SessionActive {
		t.Error("session must restore as active")
	}
}

func TestProcessKillWhileArmedRestoresArmed(t *testing.T) {
	store := NewMemoryStore()
	cfg := Config{Mode: ModeAlwaysOn}
	c1, _ := NewController(cfg, &FakeEnforcer{}, store)
	if err := c1.SessionStart(); err != nil {
		t.Fatal(err)
	}
	c2, _ := NewController(cfg, &FakeEnforcer{}, store)
	if err := c2.Restore(); err != nil {
		t.Fatal(err)
	}
	if st := c2.Status(); st.State != StateArmed || !st.Blocking {
		t.Errorf("restored = %+v, want armed+blocking", st)
	}
}

func TestRestoreCleanOffStaysOff(t *testing.T) {
	c, enf, _ := newTestController(t, ModeWhenConnected)
	if err := c.Restore(); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.State != StateOff || enf.ApplyCalls != 0 {
		t.Errorf("fresh restore must stay off: %+v applies=%d", st, enf.ApplyCalls)
	}
}

// --- fault injection: sleep / wake ----------------------------

func TestWakeReappliesAndNeverReleases(t *testing.T) {
	c, enf, _ := newTestController(t, ModeWhenConnected)
	engage(t, c)
	before := enf.ApplyCalls
	if err := c.Wake(); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if st.State != StateEngaged {
		t.Errorf("wake changed state to %s (wake alone must not demote engaged; liveness is reported separately)", st.State)
	}
	if enf.ApplyCalls != before+1 {
		t.Error("wake must re-apply the rules before returning (invariant I4)")
	}
	if enf.RemoveCalls != 0 {
		t.Error("wake removed rules — forbidden")
	}
	// Wake in recovering also keeps recovering.
	_ = c.TunnelDown(ReasonNetworkLost)
	if err := c.Wake(); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.State != StateRecovering || !st.Blocking {
		t.Errorf("wake in recovering: %+v", st)
	}
}

func TestWakeApplyFailureDegradesNotReleases(t *testing.T) {
	c, enf, _ := newTestController(t, ModeWhenConnected)
	engage(t, c)
	enf.FailApply = errors.New("nft: permission denied")
	if err := c.Wake(); err == nil {
		t.Fatal("wake with failing enforcer must return the error")
	}
	st := c.Status()
	if !st.Blocking || !st.Degraded {
		t.Errorf("failed re-apply must keep intent + flag degraded: %+v", st)
	}
}

// --- the only two exits to off ---------------------------------

func TestUserDisconnectReleasesWhenConnected(t *testing.T) {
	c, enf, store := newTestController(t, ModeWhenConnected)
	engage(t, c)
	if err := c.UserDisconnect(); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if st.State != StateOff || st.Blocking || st.EnforcerApplied {
		t.Errorf("after user disconnect: %+v", st)
	}
	if enf.RemoveCalls != 1 {
		t.Errorf("remove calls = %d, want 1", enf.RemoveCalls)
	}
	rec, _ := store.Load()
	if rec == nil || rec.State != StateOff {
		t.Errorf("persisted record must be off after disconnect: %+v", rec)
	}
}

func TestUserDisconnectAlwaysOnKeepsBlock(t *testing.T) {
	c, enf, _ := newTestController(t, ModeAlwaysOn)
	engage(t, c)
	if err := c.UserDisconnect(); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if st.State != StateArmed || !st.Blocking || !st.EnforcerApplied {
		t.Errorf("always-on disconnect must end session but keep block (armed): %+v", st)
	}
	if enf.RemoveCalls != 0 {
		t.Error("always-on disconnect removed rules — forbidden")
	}
	if st.SessionActive {
		t.Error("session must be over")
	}
}

func TestDisableReleasesEvenAlwaysOn(t *testing.T) {
	c, enf, _ := newTestController(t, ModeAlwaysOn)
	engage(t, c)
	if err := c.Disable(); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.State != StateOff || enf.RemoveCalls != 1 {
		t.Errorf("disable: %+v removes=%d", st, enf.RemoveCalls)
	}
}

func TestNoFaultEventReleasesBlock(t *testing.T) {
	// Invariant I2, exhaustively over the non-exit events.
	events := map[string]func(*Controller) error{
		"SessionStart": func(c *Controller) error { return c.SessionStart() },
		"TunnelUp":     func(c *Controller) error { return c.TunnelUp() },
		"TunnelDown":   func(c *Controller) error { return c.TunnelDown(ReasonKernelFailed) },
		"Wake":         func(c *Controller) error { return c.Wake() },
	}
	for name, ev := range events {
		c, enf, _ := newTestController(t, ModeWhenConnected)
		engage(t, c)
		if err := ev(c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st := c.Status(); st.State == StateOff || !st.Blocking {
			t.Errorf("event %s released the block: %+v", name, st)
		}
		if enf.RemoveCalls != 0 {
			t.Errorf("event %s removed rules", name)
		}
	}
}

// --- apply failure at arm time ---------------------------------

func TestSessionStartApplyFailureIsExplicit(t *testing.T) {
	enf := &FakeEnforcer{FailApply: errors.New("firewall: access denied")}
	c, err := NewController(Config{Mode: ModeWhenConnected}, enf, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SessionStart(); err == nil {
		t.Fatal("SessionStart with failing enforcer must error (never silently run unprotected)")
	}
	st := c.Status()
	// Intent is armed (fail-closed representation) but the gap
	// is explicit: Degraded and not EnforcerApplied.
	if st.State != StateArmed || !st.Degraded || st.EnforcerApplied {
		t.Errorf("apply-failure status = %+v, want armed+degraded+not-applied", st)
	}
	if st.Readiness != ReadinessPolicyReady {
		t.Errorf("fake enforcer readiness = %s, want policy-ready", st.Readiness)
	}
}

// --- mode off ---------------------------------------------------

func TestModeOffIsFullyInert(t *testing.T) {
	c, enf, _ := newTestController(t, ModeOff)
	for _, ev := range []func() error{c.SessionStart, c.TunnelUp, c.Wake,
		func() error { return c.TunnelDown(ReasonKernelFailed) }, c.UserDisconnect} {
		if err := ev(); err != nil {
			t.Fatal(err)
		}
	}
	if st := c.Status(); st.State != StateOff {
		t.Errorf("mode off state = %s", st.State)
	}
	if enf.ApplyCalls != 0 || enf.RemoveCalls != 0 {
		t.Error("mode off must never touch the enforcer")
	}
}

// --- restore with a config that now says off -------------------

func TestRestoreBlockingIntentSurvivesBareConfigChange(t *testing.T) {
	// A persisted blocking intent must not be silently disarmed
	// by the process restarting with a Mode=off config that
	// never went through Disable() (I2/I3: release is an act,
	// not a side effect).
	store := NewMemoryStore()
	on, _ := NewController(Config{Mode: ModeAlwaysOn}, &FakeEnforcer{}, store)
	if err := on.SessionStart(); err != nil {
		t.Fatal(err)
	}
	off, _ := NewController(Config{Mode: ModeOff}, &FakeEnforcer{}, store)
	if err := off.Restore(); err != nil {
		t.Fatal(err)
	}
	if st := off.Status(); !st.Blocking {
		t.Errorf("persisted block was silently dropped by config change: %+v", st)
	}
}
