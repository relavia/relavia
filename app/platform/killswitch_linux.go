//go:build linux

package platform

import (
	"os/exec"

	"openproxy/core/killswitch"
)

// Linux kill-switch executor (Step 12): a thin facility
// wrapper over core/killswitch's NFTEnforcer, which loads the
// compiled nftables ruleset into the kernel. Linux is a
// phase-2 platform (book 8.2); this executor is real (it is
// what the Step 12 netns rig exercises) but needs CAP_NET_ADMIN
// in the current network namespace — Available() only claims
// the tooling exists; Apply surfaces permission failures
// verbatim rather than pretending.

type linuxKillSwitch struct {
	enf *killswitch.NFTEnforcer
}

// NewKillSwitch returns the Linux nftables executor.
func NewKillSwitch() KillSwitch { return &linuxKillSwitch{enf: &killswitch.NFTEnforcer{}} }

func (k *linuxKillSwitch) Apply(desc killswitch.Descriptors) error { return k.enf.Apply(desc) }
func (k *linuxKillSwitch) Remove() error                           { return k.enf.Remove() }
func (k *linuxKillSwitch) Applied() bool                           { return k.enf.Applied() }

func (k *linuxKillSwitch) Available() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

func (k *linuxKillSwitch) Detail() string {
	if !k.Available() {
		return "nft binary not found (nftables executor unavailable)"
	}
	return "nftables executor (table " + killswitch.NFTTable + "); requires CAP_NET_ADMIN in the current network namespace"
}

// Enforcer exposes the underlying real enforcer for the
// killswitch Controller; it grades ReadinessEnforceable.
func (k *linuxKillSwitch) Enforcer() killswitch.Enforcer { return k.enf }
