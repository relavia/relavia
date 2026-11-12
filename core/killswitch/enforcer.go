package killswitch

import (
	"errors"
	"sync"
)

// ErrEnforcerUnavailable is returned by enforcer stubs on
// platforms without a real implementation.
var ErrEnforcerUnavailable = errors.New("killswitch: no real platform enforcer on this platform/build")

// Enforcer applies and removes the compiled Descriptors at OS
// level. Apply must be idempotent (Wake and Restore re-apply
// as a matter of routine); Remove must be idempotent and must
// not fail merely because nothing is applied.
type Enforcer interface {
	Apply(d Descriptors) error
	Remove() error
	// Applied reports whether the enforcer believes its rules
	// are currently in force. It is the FACT half of Status;
	// the state machine's state is the INTENT half.
	Applied() bool
	// Enforceable reports whether this is a REAL platform
	// enforcer (as opposed to a fake or a skeleton). It drives
	// the Readiness grading — only real enforcers may let the
	// adapter report Platform.KillSwitch=true.
	Enforceable() bool
}

// FakeEnforcer is an in-memory Enforcer for tests and for
// exercising the client logic on platforms without a real
// enforcer. It is NOT enforceable by definition: a build whose
// only enforcer is the fake reports ReadinessPolicyReady.
type FakeEnforcer struct {
	mu          sync.Mutex
	applied     bool
	ApplyCalls  int
	RemoveCalls int
	LastApplied Descriptors
	// FailApply, when non-nil, makes Apply return it (fault
	// injection). FailRemove likewise.
	FailApply  error
	FailRemove error
}

func (f *FakeEnforcer) Apply(d Descriptors) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ApplyCalls++
	if f.FailApply != nil {
		return f.FailApply
	}
	f.applied = true
	f.LastApplied = d
	return nil
}

func (f *FakeEnforcer) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.RemoveCalls++
	if f.FailRemove != nil {
		return f.FailRemove
	}
	f.applied = false
	return nil
}

func (f *FakeEnforcer) Applied() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

func (f *FakeEnforcer) Enforceable() bool { return false }
