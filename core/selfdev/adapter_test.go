package selfdev

import (
	"strings"
	"testing"

	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

func ssNode(method, password string) *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "n1",
		Protocol:      "shadowsocks",
		Server:        "127.0.0.1",
		Port:          8388,
		Shadowsocks:   &specnode.CredShadowsocks{Method: method, Password: password},
	}
}

func TestSelfdevEligible(t *testing.T) {
	cases := []struct {
		name string
		node *specnode.Node
		want bool
		why  string
	}{
		{"eligible 2017", ssNode("aes-256-gcm", "pw"), true, ""},
		{"eligible 2022", ssNode("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="), true, ""},
		{"legacy method", ssNode("aes-256-cfb", "pw"), false, "method outside"},
		{"plugin", func() *specnode.Node {
			n := ssNode("aes-256-gcm", "pw")
			n.Shadowsocks.Plugin = "v2ray-plugin"
			return n
		}(), false, "plugin transport"},
		{"multi psk", ssNode("2022-blake3-aes-256-gcm", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="), false, "multi-segment PSK"},
		{"not shadowsocks", &specnode.Node{Protocol: "trojan"}, false, "not a shadowsocks"},
		{"missing creds", &specnode.Node{Protocol: "shadowsocks"}, false, "missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := selfdevEligible(tc.node)
			if ok != tc.want {
				t.Fatalf("eligible = %v (%s), want %v", ok, why, tc.want)
			}
			if !ok && !strings.Contains(why, tc.why) {
				t.Fatalf("reason %q does not mention %q", why, tc.why)
			}
		})
	}
}

func TestRoutePolicies(t *testing.T) {
	newAdapter := func(p Policy) *Adapter {
		return &Adapter{policy: p, pins: map[string]string{}}
	}
	node := ssNode("aes-256-gcm", "pw")

	if b, _ := newAdapter(PolicySingbox).route(node); b != BackendSingbox {
		t.Fatalf("singbox policy routed to %s", b)
	}
	if b, _ := newAdapter(PolicySelfdev).route(node); b != BackendSelfdev {
		t.Fatalf("selfdev policy routed to %s", b)
	}
	if b, _ := newAdapter(PolicyAuto).route(node); b != BackendSelfdev {
		t.Fatalf("auto policy routed to %s", b)
	}
	pluginNode := ssNode("aes-256-gcm", "pw")
	pluginNode.Shadowsocks.Plugin = "obfs-local"
	if b, r := newAdapter(PolicySelfdev).route(pluginNode); b != BackendSingbox || !strings.Contains(r, "plugin") {
		t.Fatalf("plugin node under selfdev policy = %s (%s)", b, r)
	}
}

func TestAutoPinning(t *testing.T) {
	a := &Adapter{policy: PolicyAuto, pins: map[string]string{}}
	node := ssNode("aes-256-gcm", "pw")
	if b, _ := a.route(node); b != BackendSelfdev {
		t.Fatalf("before pin: %s", b)
	}
	a.pin(node)
	if b, r := a.route(node); b != BackendSingbox || !strings.Contains(r, "pinned") {
		t.Fatalf("after pin: %s (%s)", b, r)
	}
	// Node data changes: the pin stops applying.
	changed := ssNode("aes-256-gcm", "other-password")
	changed.ID = node.ID
	if b, _ := a.route(changed); b != BackendSelfdev {
		t.Fatalf("after node change: %s", b)
	}
	// Manual reset clears the pin for the unchanged node too.
	a.ResetPins()
	if b, _ := a.route(node); b != BackendSelfdev {
		t.Fatalf("after reset: %s", b)
	}
}

func TestCapabilitiesKernelID(t *testing.T) {
	a := New(singbox.New(singbox.Options{}), Options{})
	caps := a.Capabilities()
	if caps.KernelID != "selfdev" {
		t.Fatalf("KernelID = %q, want selfdev", caps.KernelID)
	}
	sbCaps := singbox.New(singbox.Options{}).Capabilities()
	if len(caps.Protocols) != len(sbCaps.Protocols) {
		t.Fatal("composite must report the sing-box union, nothing more")
	}
}
