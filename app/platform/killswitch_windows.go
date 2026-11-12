//go:build windows

package platform

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"openproxy/core/killswitch"
)

// Windows kill-switch executor (Step 12): translates the
// compiled descriptor into netsh advfirewall commands via
// BuildWindowsApplyCommands / BuildWindowsRemoveCommands.
//
// STATUS: SKELETON, COMPILE-VERIFIED ONLY. No Windows machine
// exists in the build sandbox, so not one command here has run
// against a real Windows Firewall. Real-machine verification
// (rules land in all profiles, traffic actually stops, the
// user's inbound policy is preserved/restored) is tracked in
// docs/step12-断网保护.md's pending checklist. Accordingly the
// Enforcer view of this executor reports Enforceable()=false:
// flipping that to true is a one-line change that may only be
// made AFTER the real-machine checklist passes.

type winKillSwitch struct {
	mu      sync.Mutex
	applied bool
	last    killswitch.Descriptors
	hasLast bool
}

// NewKillSwitch returns the Windows executor skeleton.
func NewKillSwitch() KillSwitch { return &winKillSwitch{} }

func (k *winKillSwitch) run(cmds []WinCommand) error {
	for _, c := range cmds {
		out, err := exec.Command("netsh", c.Args...).CombinedOutput()
		if err != nil && !c.BestEffort {
			return fmt.Errorf("netsh %s: %w (%s)", strings.Join(c.Args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (k *winKillSwitch) Apply(desc killswitch.Descriptors) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	cmds, err := BuildWindowsApplyCommands(desc)
	if err != nil {
		return err
	}
	if err := k.run(cmds); err != nil {
		return err
	}
	k.applied = true
	k.last = desc
	k.hasLast = true
	return nil
}

func (k *winKillSwitch) Remove() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.hasLast {
		return nil // nothing of ours was ever applied
	}
	if err := k.run(BuildWindowsRemoveCommands(k.last)); err != nil {
		return err
	}
	k.applied = false
	return nil
}

// Applied is process-local bookkeeping in this skeleton: it
// reports what THIS process successfully applied. Verifying
// the live firewall state (e.g. after a crash, where Windows
// Firewall rules persist) is part of the real-machine work.
func (k *winKillSwitch) Applied() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.applied
}

func (k *winKillSwitch) Available() bool { return true }

func (k *winKillSwitch) Detail() string {
	return "Windows Firewall executor (netsh skeleton): compile-verified only, pending real-machine verification (Step 12) — must not be reported as enforced yet"
}

// windowsEnforcer adapts the executor to the killswitch
// state machine's Enforcer contract. Enforceable stays false
// until real-machine verification lands (see file header).
type windowsEnforcer struct{ ks *winKillSwitch }

func (e windowsEnforcer) Apply(d killswitch.Descriptors) error { return e.ks.Apply(d) }
func (e windowsEnforcer) Remove() error                        { return e.ks.Remove() }
func (e windowsEnforcer) Applied() bool                        { return e.ks.Applied() }
func (e windowsEnforcer) Enforceable() bool                    { return false }
