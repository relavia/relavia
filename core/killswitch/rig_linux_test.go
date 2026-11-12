//go:build linux

package killswitch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompiledRulesetKernelAcceptance loads the COMPILED
// ruleset into a real kernel netfilter inside a throwaway
// user+net namespace and reads it back. This proves the
// generated ruleset is kernel-acceptable as-is (not merely
// plausible text). It does NOT prove traffic blocking — in
// this sandbox no non-loopback packet can be generated at all
// (see TestSandboxTrafficProbe evidence); the traffic rig for
// privileged environments is scripts/killswitch-check.sh.
//
// Skips (does not fail) where unshare/nft are unavailable.
func TestCompiledRulesetKernelAcceptance(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}
	if out, err := exec.Command("unshare", "-Urn", "true").CombinedOutput(); err != nil {
		t.Skipf("user+net namespace not permitted here: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	d, err := Compile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rules := filepath.Join(dir, "ks.nft")
	if err := os.WriteFile(rules, []byte(d.LinuxNFT), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "nft -f " + rules + " && nft list table inet " + NFTTable
	out, err := exec.Command("unshare", "-Urn", "bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("kernel rejected the compiled ruleset: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{"chain output", "counter", "drop"} {
		if !strings.Contains(got, want) {
			t.Errorf("kernel readback missing %q:\n%s", want, got)
		}
	}
	// Also round-trip through the real NFTEnforcer inside the
	// namespace? The enforcer execs nft in the CURRENT ns, so
	// it is exercised by scripts/killswitch-check.sh phase 1b
	// (go test cannot cross into the child ns). Logged as a
	// note, not silently assumed.
	t.Logf("kernel readback ok (%d bytes)", len(got))
}

// TestNFTEnforcerInNamespace exercises NFTEnforcer end-to-end
// by re-executing this test binary inside unshare -Urn, where
// the enforcer's nft calls run with CAP_NET_ADMIN over the
// namespace. Skips where namespaces are unavailable.
func TestNFTEnforcerInNamespace(t *testing.T) {
	if os.Getenv("RELVIA_KS_INSIDE_NS") == "1" {
		// Inside the namespace: real apply/list/remove.
		d, err := Compile(testConfig())
		if err != nil {
			t.Fatal(err)
		}
		e := &NFTEnforcer{}
		if !e.Enforceable() {
			t.Fatal("NFTEnforcer must be enforceable")
		}
		if err := e.Apply(d); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if !e.Applied() {
			t.Fatal("Applied() = false right after Apply")
		}
		if err := e.Apply(d); err != nil {
			t.Fatalf("re-Apply (idempotency) : %v", err)
		}
		if err := e.Remove(); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if e.Applied() {
			t.Fatal("Applied() = true after Remove")
		}
		if err := e.Remove(); err != nil {
			t.Fatalf("re-Remove must be idempotent: %v", err)
		}
		return
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no test binary path: %v", err)
	}
	cmd := exec.Command("unshare", "-Urn", exe, "-test.run", "^TestNFTEnforcerInNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), "RELVIA_KS_INSIDE_NS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "operation not permitted") || strings.Contains(string(out), "Operation not permitted") {
			t.Skipf("namespaces not permitted here: %s", strings.TrimSpace(string(out)))
		}
		t.Fatalf("in-namespace enforcer test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("in-namespace run did not report PASS:\n%s", out)
	}
}

// TestSandboxTrafficProbe documents, with live evidence, why
// this sandbox cannot produce non-loopback traffic: any
// connect()/sendto() to a non-loopback destination fails with
// EPERM at syscall level in the initial namespace AND inside
// a fresh user+net namespace alike (an egress policy above
// the namespace layer; loopback TCP works). The probe LOGS
// the verdict and never fails the suite: on a normal machine
// the same probe reports traffic generation as possible, and
// scripts/killswitch-check.sh then runs its full traffic rig.
func TestSandboxTrafficProbe(t *testing.T) {
	probe := `
import socket
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("10.0.0.1", 8080)); print("VERDICT: connect ok")
except OSError as e:
    print("VERDICT: connect blocked:", e)
`
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.py")
	if err := os.WriteFile(script, []byte(probe), 0o600); err != nil {
		t.Fatal(err)
	}
	shell := "ip link set lo up; ip link add vA type veth peer name vB; " +
		"ip addr add 10.0.0.1/24 dev vA; ip link set vA up; ip link set vB up; " +
		"python3 " + script
	out, err := exec.Command("unshare", "-Urn", "bash", "-c", shell).CombinedOutput()
	if err != nil {
		t.Logf("traffic probe could not run here (%v): %s", err, strings.TrimSpace(string(out)))
		return
	}
	t.Logf("in-namespace traffic probe: %s", strings.TrimSpace(string(out)))
}
