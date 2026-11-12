//go:build linux

package killswitch

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// NFTEnforcer is the real Linux enforcer: it loads the
// compiled nftables ruleset into the kernel with `nft -f -`
// and removes the table on release. Linux is a phase-2
// platform (book 8.2) — this enforcer exists for the Step 12
// test rig (scripts/killswitch-check.sh), for the future Linux
// client, and as the reference implementation of the Enforcer
// contract; it makes no v1.0 platform claim.
//
// It operates on the CURRENT network namespace and needs
// CAP_NET_ADMIN there; failures are returned, never swallowed.
type NFTEnforcer struct {
	// NFTPath is the nft binary (default "nft", PATH lookup).
	NFTPath string
}

func (e *NFTEnforcer) nft(args ...string) (string, error) {
	bin := e.NFTPath
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// Apply loads the ruleset. It first deletes any existing table
// so re-application (Wake/Restore) is a clean replace rather
// than a merge — the applied rules are always exactly the
// compiled descriptors, never an accretion of generations.
func (e *NFTEnforcer) Apply(d Descriptors) error {
	_, _ = e.nft("delete", "table", "inet", NFTTable) // absence is fine
	cmd := exec.Command(e.nftBin(), "-f", "-")
	cmd.Stdin = strings.NewReader(d.LinuxNFT)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f -: %w (%s)", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func (e *NFTEnforcer) nftBin() string {
	if e.NFTPath != "" {
		return e.NFTPath
	}
	return "nft"
}

// Remove deletes the kill-switch table. Idempotent.
func (e *NFTEnforcer) Remove() error {
	out, err := e.nft("delete", "table", "inet", NFTTable)
	if err != nil && strings.Contains(out, "No such file or directory") {
		return nil
	}
	return err
}

// Applied reports whether the table currently exists.
func (e *NFTEnforcer) Applied() bool {
	_, err := e.nft("list", "table", "inet", NFTTable)
	return err == nil
}

// Enforceable: this is a real kernel-backed enforcer.
func (e *NFTEnforcer) Enforceable() bool { return true }
