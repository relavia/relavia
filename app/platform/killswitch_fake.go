package platform

import "openproxy/core/killswitch"

// FakeKillSwitch records executor calls in memory. Used by
// unit tests and by development builds on platforms without a
// real executor, so service-level kill-switch logic (session
// wiring, degraded surfacing) stays exercisable everywhere.
// It enforces NOTHING and never pretends to.
type FakeKillSwitch struct {
	AvailableFlag bool
	AppliedFlag   bool
	ApplyCalls    int
	RemoveCalls   int
	LastApplied   killswitch.Descriptors
	// FailApply injects an Apply error (fault injection).
	FailApply error
}

func NewFakeKillSwitch() *FakeKillSwitch { return &FakeKillSwitch{AvailableFlag: true} }

func (f *FakeKillSwitch) Apply(d killswitch.Descriptors) error {
	f.ApplyCalls++
	if f.FailApply != nil {
		return f.FailApply
	}
	f.AppliedFlag = true
	f.LastApplied = d
	return nil
}

func (f *FakeKillSwitch) Remove() error {
	f.RemoveCalls++
	f.AppliedFlag = false
	return nil
}

func (f *FakeKillSwitch) Applied() bool   { return f.AppliedFlag }
func (f *FakeKillSwitch) Available() bool { return f.AvailableFlag }
func (f *FakeKillSwitch) Detail() string  { return "fake executor (records calls, enforces nothing)" }
