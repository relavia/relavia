package routecfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The shipped default policy JSON files must be exactly the
// constructors in defaults.go (semantically), must compile,
// and must satisfy the safety invariants the step promises.

func loadDefault(t *testing.T, name string) Policy {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("defaults", name))
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

func TestDefaultFilesMatchConstructors(t *testing.T) {
	if got, want := loadDefault(t, "system-proxy.policy.json"), DefaultSystemProxyPolicy(); !reflect.DeepEqual(got, want) {
		t.Fatalf("system-proxy.policy.json drifted from DefaultSystemProxyPolicy()\n got: %+v\nwant: %+v", got, want)
	}
	if got, want := loadDefault(t, "tun.policy.json"), DefaultTUNPolicy(); !reflect.DeepEqual(got, want) {
		t.Fatalf("tun.policy.json drifted from DefaultTUNPolicy()\n got: %+v\nwant: %+v", got, want)
	}
}

func TestDefaultsCompileWithSafetyInvariants(t *testing.T) {
	for name, p := range map[string]Policy{
		"system-proxy": DefaultSystemProxyPolicy(),
		"tun":          DefaultTUNPolicy(),
	} {
		frag, err := Compile(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		route, dns := roundTrip(t, frag)
		if route["final"] != OutboundProxy {
			t.Errorf("%s: route final must be the node", name)
		}
		if _, present := route["default_domain_resolver"]; present {
			t.Errorf("%s: route.default_domain_resolver must stay UNSET in sing-box 1.14 — both its forms defeat the DNS rule mirror (see compile.go)", name)
		}
		if dns["final"] != DNSServerRemote {
			t.Errorf("%s: dns final must be remote (no plaintext fallback)", name)
		}
		servers, _ := dns["servers"].([]any)
		for _, raw := range servers {
			if raw.(map[string]any)["type"] == "fakeip" {
				t.Errorf("%s: fake-ip must be OFF by default", name)
			}
		}
	}
	if DefaultTUNPolicy().IPv6 != IPv6Tunnel {
		t.Error("TUN default must pin IPv6 to tunnel-only")
	}
	if DefaultSystemProxyPolicy().IPv6 != IPv6On {
		t.Error("system-proxy default IPv6 posture is on (see defaults.go rationale)")
	}
}
