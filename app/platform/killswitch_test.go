package platform

import (
	"strings"
	"testing"

	"openproxy/core/killswitch"
)

func testDescriptors(t *testing.T) killswitch.Descriptors {
	t.Helper()
	d, err := killswitch.Compile(killswitch.Config{
		Mode:      killswitch.ModeWhenConnected,
		Endpoints: []killswitch.Endpoint{{Address: "203.0.113.7", Port: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestBuildWindowsApplyCommands(t *testing.T) {
	cmds, err := BuildWindowsApplyCommands(testDescriptors(t))
	if err != nil {
		t.Fatal(err)
	}
	var sawRule, sawPolicy bool
	for _, c := range cmds {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "add rule") && strings.Contains(joined, "tunnel endpoint 203.0.113.7:443") {
			sawRule = true
			if !strings.Contains(joined, "remoteip=203.0.113.7") || !strings.Contains(joined, "remoteport=443") {
				t.Errorf("endpoint rule malformed: %s", joined)
			}
		}
		if strings.Contains(joined, "firewallpolicy") && strings.Contains(joined, "blockoutbound") {
			sawPolicy = true
		}
	}
	if !sawRule || !sawPolicy {
		t.Errorf("apply commands incomplete: rule=%v policy=%v\n%v", sawRule, sawPolicy, cmds)
	}
}

func TestBuildWindowsRemoveCommands(t *testing.T) {
	cmds := BuildWindowsRemoveCommands(testDescriptors(t))
	var sawDelete, sawRestore bool
	for _, c := range cmds {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "delete rule") && strings.Contains(joined, killswitch.RuleNamePrefix) {
			sawDelete = true
		}
		if strings.Contains(joined, "firewallpolicy") && strings.Contains(joined, "allowoutbound") {
			sawRestore = true
		}
	}
	if !sawDelete || !sawRestore {
		t.Errorf("remove commands incomplete: delete=%v restore=%v", sawDelete, sawRestore)
	}
}

func TestNetshRemoteIPTranslation(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":    "203.0.113.7",
		"127.0.0.0/8":    "127.0.0.0/255.0.0.0",
		"10.0.0.0/8":     "10.0.0.0/255.0.0.0",
		"192.168.0.0/16": "192.168.0.0/255.255.0.0",
		"::1/128":        "::1/128",
		"fe80::/10":      "fe80::/10",
	}
	for in, want := range cases {
		got, err := netshRemoteIP(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("netshRemoteIP(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := netshRemoteIP("not-an-ip"); err == nil {
		t.Error("garbage address must error, not pass through")
	}
}

func TestFakeKillSwitch(t *testing.T) {
	f := NewFakeKillSwitch()
	if !f.Available() {
		t.Fatal("fake must be available")
	}
	if err := f.Apply(testDescriptors(t)); err != nil {
		t.Fatal(err)
	}
	if !f.Applied() || f.ApplyCalls != 1 {
		t.Errorf("after apply: applied=%v calls=%d", f.Applied(), f.ApplyCalls)
	}
	if err := f.Remove(); err != nil {
		t.Fatal(err)
	}
	if f.Applied() {
		t.Error("applied after remove")
	}
}

func TestNewKillSwitchFacilityShape(t *testing.T) {
	ks := NewKillSwitch()
	if ks == nil {
		t.Fatal("NewKillSwitch returned nil")
	}
	// Do NOT call Apply on the real platform executor in unit
	// tests (it would touch the host firewall); the builder
	// and fake tests above cover the logic. Just the shape:
	_ = ks.Available()
	if ks.Detail() == "" {
		t.Error("Detail must explain itself")
	}
}
