package killswitch

import (
	"fmt"
	"sync"
	"time"
)

// State is the enforcement state of the kill switch. The state
// is an INTENT backed by an Enforcer: in every state except
// StateOff the compiled rules are supposed to be applied at OS
// level. If the enforcer reports them missing (or an apply
// failed), Status.Degraded says so explicitly — the state never
// silently pretends protection that is not there.
type State string

const (
	// StateOff: no blocking. The only state in which direct
	// traffic may flow freely.
	StateOff State = "off"
	// StateArmed: blocking applied; tunnel not (yet) up —
	// session starting, or always-on with no session.
	StateArmed State = "armed"
	// StateEngaged: blocking applied; tunnel up.
	StateEngaged State = "engaged"
	// StateRecovering: blocking applied; the tunnel faulted
	// (crash, kernel failure, network loss, process restart)
	// and the session has NOT been ended by the user.
	StateRecovering State = "recovering"
)

// Blocking reports whether the state intends OS-level blocking.
func (s State) Blocking() bool { return s != StateOff && s != "" }

// FaultReason classifies a TunnelDown event for diagnostics.
// All reasons have identical state-machine semantics: blocking
// persists. (Adapter StateFailed maps to ReasonKernelFailed;
// a dead TUN device to ReasonTunnelDropped; OS connectivity
// loss and sleep/wake tunnel death to ReasonNetworkLost.)
type FaultReason string

const (
	ReasonKernelFailed  FaultReason = "kernel-failed"
	ReasonTunnelDropped FaultReason = "tunnel-dropped"
	ReasonNetworkLost   FaultReason = "network-lost"
	ReasonProcessKilled FaultReason = "process-killed"
)

// Status is a snapshot of the Controller for UI/diagnostics
// and for the adapter's capability hook (Report).
type Status struct {
	State              State
	Mode               Mode
	Blocking           bool // intent: rules should be applied
	EnforcerApplied    bool // fact reported by the enforcer
	Degraded           bool // intent != fact, or an apply/remove failed
	SessionActive      bool
	RestoredAfterCrash bool // this process restored a persisted blocking intent
	LastFault          FaultReason
	Readiness          Readiness
}

// Report is the graded capability view consumed by
// core/singbox (Options.KillSwitchReport). The adapter may
// report Platform.KillSwitch=true only when Readiness is
// ReadinessEnforceable.
type Report struct {
	Readiness Readiness
	State     State
	Blocking  bool
}

// Controller drives the kill-switch state machine. All events
// are methods; the transition rules are:
//
//	off        --SessionStart (mode != off)--> armed     [apply]
//	off        --TunnelUp (mode != off)------> engaged   [apply]
//	armed      --TunnelUp--------------------> engaged
//	recovering --TunnelUp--------------------> engaged
//	engaged    --TunnelDown------------------> recovering [NO enforcer change]
//	armed      --TunnelDown------------------> recovering [NO enforcer change]
//	engaged    --Wake------------------------> engaged   [re-apply first]
//	armed      --Wake------------------------> armed     [re-apply first]
//	recovering --Wake------------------------> recovering [re-apply first]
//	*blocking* --UserDisconnect (when-connected)--> off  [remove]
//	engaged/recovering --UserDisconnect (always-on)--> armed [session ends, block stays]
//	*any*      --Disable---------------------> off       [remove]
//	boot       --Restore---------------------> persisted intent (engaged restores as recovering) [apply]
//
// Invariants (all covered by fault-injection tests):
//
//	I1. Blocking holds in armed/engaged/recovering; only in
//	    off may direct traffic flow.
//	I2. The ONLY exits to off are UserDisconnect in
//	    when-connected mode and Disable. No fault, wake,
//	    tunnel or session event can release the block.
//	I3. Blocking intent is PERSISTED BEFORE the enforcer is
//	    asked to apply, and release intent is persisted before
//	    removal: a process kill at any point reboots into the
//	    persisted intent (fail-closed), never into amnesia.
//	I4. Wake and Restore re-apply the rules BEFORE returning
//	    — resuming from sleep or from a crash must never open
//	    a window where the machine believes itself protected
//	    while the OS rules are gone.
//	I5. The ruleset applied is identical in armed, engaged
//	    and recovering: transitions between blocking states
//	    never touch the enforcer, so there is no re-apply gap
//	    for traffic to slip through.
type Controller struct {
	mu    sync.Mutex
	cfg   Config
	desc  Descriptors
	enf   Enforcer
	store Store
	state State
	sess  bool
	degr  bool
	restd bool
	fault FaultReason
	nowFn func() time.Time
}

// NewController compiles the Config and returns a Controller in
// StateOff. Call Restore after construction to pick up a
// persisted intent from a previous process. A nil Enforcer is
// an error (a controller that cannot enforce must not exist);
// a nil Store degrades persistence to memory-only.
func NewController(cfg Config, enf Enforcer, store Store) (*Controller, error) {
	desc, err := Compile(cfg)
	if err != nil {
		return nil, err
	}
	if enf == nil {
		return nil, fmt.Errorf("killswitch: nil enforcer (policy without enforcement is not a kill switch)")
	}
	if store == nil {
		store = NewMemoryStore()
	}
	return &Controller{
		cfg: cfg, desc: desc, enf: enf, store: store,
		state: StateOff, nowFn: time.Now,
	}, nil
}

// Descriptors returns the compiled descriptors this controller
// enforces (for platform executors and diagnostics).
func (c *Controller) Descriptors() Descriptors { return c.desc }

// Config returns the controller's configuration.
func (c *Controller) Config() Config { return c.cfg }

// Readiness grades the attached enforcer (see package docs).
func (c *Controller) Readiness() Readiness {
	if c.enf == nil {
		return ReadinessUnavailable
	}
	if c.enf.Enforceable() {
		return ReadinessEnforceable
	}
	return ReadinessPolicyReady
}

// Report implements the adapter capability hook view.
func (c *Controller) Report() Report {
	st := c.Status()
	return Report{Readiness: st.Readiness, State: st.State, Blocking: st.Blocking}
}

// Status returns a consistent snapshot.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	applied := c.enf != nil && c.enf.Applied()
	degr := c.degr || (c.state.Blocking() && !applied)
	return Status{
		State:              c.state,
		Mode:               c.cfg.Mode,
		Blocking:           c.state.Blocking(),
		EnforcerApplied:    applied,
		Degraded:           degr,
		SessionActive:      c.sess,
		RestoredAfterCrash: c.restd,
		LastFault:          c.fault,
		Readiness:          c.Readiness(),
	}
}

// persistLocked records the current intent BEFORE the enforcer
// is touched (invariant I3).
func (c *Controller) persistLocked() {
	_ = c.store.Save(Record{
		Mode:          c.cfg.Mode,
		State:         c.state,
		SessionActive: c.sess,
		UpdatedAt:     c.nowFn(),
	})
}

// applyLocked asks the enforcer to apply the compiled rules.
// An error marks the controller degraded; the intent state is
// kept (fail-closed representation — see state.go docs).
func (c *Controller) applyLocked() error {
	if err := c.enf.Apply(c.desc); err != nil {
		c.degr = true
		return fmt.Errorf("killswitch: apply rules: %w", err)
	}
	c.degr = false
	return nil
}

// removeLocked asks the enforcer to remove the rules.
func (c *Controller) removeLocked() error {
	if err := c.enf.Remove(); err != nil {
		c.degr = true
		return fmt.Errorf("killswitch: remove rules: %w", err)
	}
	c.degr = false
	return nil
}

// SessionStart marks the beginning of a connection session.
// In ModeOff it is a no-op (feature disabled). Otherwise the
// intent is persisted and the rules applied BEFORE the tunnel
// is allowed to come up, so the connection-establishment phase
// is already covered.
func (c *Controller) SessionStart() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Mode == ModeOff {
		return nil
	}
	c.sess = true
	if c.state == StateOff {
		c.state = StateArmed
		c.persistLocked()
		return c.applyLocked()
	}
	c.persistLocked()
	return nil
}

// TunnelUp reports the tunnel established. Transitions to
// engaged without touching the enforcer (invariant I5). From
// off it defensively performs the full arm+apply first.
func (c *Controller) TunnelUp() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Mode == ModeOff {
		return nil
	}
	c.sess = true
	switch c.state {
	case StateEngaged:
		return nil
	case StateOff:
		c.state = StateEngaged
		c.persistLocked()
		return c.applyLocked()
	default: // armed, recovering
		c.state = StateEngaged
		c.persistLocked()
		return nil
	}
}

// TunnelDown reports an UNEXPECTED tunnel loss: kernel failed,
// TUN device dropped, network lost. Blocking persists — this
// event exists precisely for the failure the kill switch
// protects against (book 5.4). It never touches the enforcer.
// A user-initiated disconnect is UserDisconnect, not this.
func (c *Controller) TunnelDown(reason FaultReason) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.Mode == ModeOff {
		return nil
	}
	switch c.state {
	case StateEngaged, StateArmed:
		c.state = StateRecovering
		c.fault = reason
		c.persistLocked()
	}
	return nil
}

// Wake reports a resume-from-sleep (or an equivalent OS
// liveness checkpoint). It re-applies the rules BEFORE
// returning and never changes or releases the state by itself
// (invariant I4): whether the tunnel survived sleep is for the
// engine to report via TunnelUp/TunnelDown afterwards.
func (c *Controller) Wake() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.Blocking() {
		return nil
	}
	return c.applyLocked()
}

// UserDisconnect is the user explicitly ending the session.
// In when-connected mode it releases the block (one of only
// two exits to off, invariant I2). In always-on mode it ends
// the session but the block stays (armed).
func (c *Controller) UserDisconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sess = false
	if c.cfg.Mode == ModeAlwaysOn {
		if c.state == StateEngaged || c.state == StateRecovering {
			c.state = StateArmed
			c.persistLocked()
		}
		return nil
	}
	if c.state == StateOff {
		c.persistLocked()
		return nil
	}
	c.state = StateOff
	c.persistLocked()
	return c.removeLocked()
}

// Disable is the user turning the kill-switch setting off
// (Mode changed to off at the settings layer). It is the
// second and only other exit to off. Callers that change the
// mode must route through here so the release is explicit and
// persisted, never a side effect of a config edit.
func (c *Controller) Disable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sess = false
	if c.state == StateOff {
		c.persistLocked()
		return nil
	}
	c.state = StateOff
	c.persistLocked()
	return c.removeLocked()
}

// Restore picks up the intent persisted by a previous process
// (boot path; also the process-kill recovery path). A persisted
// blocking intent is re-applied IMMEDIATELY, before the caller
// does anything else (invariant I4); an engaged record restores
// as recovering because the tunnel cannot outlive the process
// that owned it — the fault is recorded as ReasonProcessKilled.
// A persisted off intent ensures removal (idempotent cleanup
// for a crash that happened mid-release).
func (c *Controller) Restore() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, err := c.store.Load()
	if err != nil {
		return fmt.Errorf("killswitch: load persisted state: %w", err)
	}
	if rec == nil {
		return nil
	}
	c.sess = rec.SessionActive
	if !rec.State.Blocking() {
		c.state = StateOff
		if c.enf.Applied() {
			return c.removeLocked()
		}
		return nil
	}
	c.restd = true
	c.state = rec.State
	if c.state == StateEngaged {
		c.state = StateRecovering
		c.fault = ReasonProcessKilled
	}
	c.persistLocked()
	return c.applyLocked()
}
