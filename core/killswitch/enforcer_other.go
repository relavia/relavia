//go:build !linux

package killswitch

// NFTEnforcer stub off Linux: nftables is a Linux facility.
// The Windows and Android enforcement paths live in the
// platform shells (app/platform skeleton for Windows; the
// Step 10 bridge for Android) and report their own readiness.
type NFTEnforcer struct {
	NFTPath string
}

func (e *NFTEnforcer) Apply(Descriptors) error { return ErrEnforcerUnavailable }
func (e *NFTEnforcer) Remove() error           { return ErrEnforcerUnavailable }
func (e *NFTEnforcer) Applied() bool           { return false }
func (e *NFTEnforcer) Enforceable() bool       { return false }
