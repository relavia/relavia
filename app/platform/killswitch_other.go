//go:build !windows && !linux

package platform

import "openproxy/core/killswitch"

// UnsupportedKillSwitch is the kill-switch facility on
// platforms without an executor in this step (macOS is a
// phase-2 platform, book 8.2; Android does not live in this Go
// module — see killswitch.go's header). It follows the same
// honesty contract as the other unsupported facilities:
// Apply returns ErrUnavailable, never a silent success.
type UnsupportedKillSwitch struct{ Why string }

func (u UnsupportedKillSwitch) Apply(killswitch.Descriptors) error { return ErrUnavailable }
func (u UnsupportedKillSwitch) Remove() error                      { return ErrUnavailable }
func (u UnsupportedKillSwitch) Applied() bool                      { return false }
func (u UnsupportedKillSwitch) Available() bool                    { return false }
func (u UnsupportedKillSwitch) Detail() string {
	if u.Why != "" {
		return u.Why
	}
	return "kill switch executor is not available on this platform/build"
}

// NewKillSwitch returns the unsupported facility.
func NewKillSwitch() KillSwitch {
	return UnsupportedKillSwitch{Why: "kill switch executor lands with this platform's network layer (book 8.2 phase 2; Android via the Step 10 bridge)"}
}
