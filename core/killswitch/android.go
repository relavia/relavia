package killswitch

import "context"

// This file is Step 12's INTERFACE PROPOSAL to Step 10
// (Android client MVP), written from the kill-switch side
// only. Step 10 was still in flight when this landed; nothing
// here modifies Step 10 code. When Step 10's platform bridge
// settles, the shell implements this interface (or an agreed
// successor via the normal review path) and the app service
// feeds its events into the Controller.
//
// Background (see compile.go's AndroidMapping): Android gives
// an app NO firewall API. The OS-level guarantee comes from
// the system lockdown mode ("Always-on VPN" + "Block
// connections without VPN"), which only the user can enable.
// The bridge therefore exists to (a) read the lockdown FACT,
// (b) take the user to the settings page, and (c) surface
// VpnService revocation events into the state machine.

// LockdownState is the system lockdown fact for this app, as
// reported by the platform — never inferred by the app.
type LockdownState int

const (
	// LockdownUnknown: the platform cannot or has not yet
	// reported (e.g. bridge not wired). UI must show unknown,
	// not "off" and not "on".
	LockdownUnknown LockdownState = iota
	// LockdownEnabled: Always-on + block-without-VPN is on
	// for Relavia in system settings.
	LockdownEnabled
	// LockdownDisabled: the user has not enabled it (or has
	// turned it off). The kill switch on Android is then
	// app-level best-effort only, and the UI must say so
	// (AndroidMapping.WithoutOptIn).
	LockdownDisabled
)

func (s LockdownState) String() string {
	switch s {
	case LockdownEnabled:
		return "enabled"
	case LockdownDisabled:
		return "disabled"
	}
	return "unknown"
}

// LockdownBridge is the Android shell's side of the contract.
type LockdownBridge interface {
	// LockdownState reports the current system lockdown fact.
	LockdownState(ctx context.Context) (LockdownState, error)
	// OpenLockdownSettings deep-links the user to the system
	// VPN settings (AndroidMapping.SettingsIntent).
	OpenLockdownSettings() error
	// Revocations delivers VpnService revocation/tunnel-death
	// events. The consumer maps each event to
	// Controller.TunnelDown(ReasonTunnelDropped).
	Revocations() <-chan struct{}
}

// AndroidReadiness combines the bridge fact with the state
// machine's mode into the honest Android readiness: only a
// user-enabled system lockdown makes Android enforcement
// OS-guaranteed; anything else is policy-ready at best. The
// sing-box adapter's Android Platform.KillSwitch report should
// follow this once the Step 10 bridge exists.
func AndroidReadiness(mode Mode, ls LockdownState) Readiness {
	if mode == ModeOff {
		return ReadinessUnavailable
	}
	if ls == LockdownEnabled {
		return ReadinessEnforceable
	}
	return ReadinessPolicyReady
}
