package vpngate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/parsers"
	"openproxy/core/specnode"
)

type fakeTester struct {
	res *kernel.HandshakeResult
	err error
	got *specnode.Node
}

func (f *fakeTester) TestHandshakeNode(_ context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	f.got = n
	return f.res, f.err
}

func ovpnParsersNode(udp bool) *parsers.Node {
	u := udp
	return &parsers.Node{
		SchemaVersion: "1.0",
		ID:            "44444444-4444-4444-4444-444444444444",
		Name:          "jp-vpngate",
		Protocol:      "openvpn",
		Server:        "127.0.0.1",
		Port:          1194,
		Credential:    []byte(`{"configContent":"client\ndev tun\nremote 127.0.0.1 1194\n"}`),
		UDP:           &u,
		Source:        parsers.SourceRef{Kind: "plugin", Ref: "vpngate", Authorization: "vpngate-official-csv"},
	}
}

func TestHandshakeProberVerified(t *testing.T) {
	ft := &fakeTester{res: &kernel.HandshakeResult{OK: true, Latency: 123 * time.Millisecond}}
	hp := &HandshakeProber{Tester: ft} // no TCP pre-filter
	res := hp.ProbeHandshake(context.Background(), ovpnParsersNode(true))
	if res.Level != ProbeLevelHandshakeVerified || !res.Reachable {
		t.Fatalf("res = %+v, want handshake-verified/reachable", res)
	}
	if res.Latency != 123*time.Millisecond {
		t.Errorf("latency = %v", res.Latency)
	}
	if ft.got == nil || ft.got.OpenVPN == nil || !strings.Contains(ft.got.OpenVPN.ConfigContent, "remote 127.0.0.1") {
		t.Errorf("tester received a mangled node: %+v", ft.got)
	}
}

func TestHandshakeProberFailedKeepsLevel(t *testing.T) {
	ft := &fakeTester{res: &kernel.HandshakeResult{OK: false, Error: kernel.NewError(
		kernel.KindHandshakeFailed, "TestHandshake", "auth_failed: server rejected the credentials (AUTH_FAILED)", nil)}}
	hp := &HandshakeProber{Tester: ft}
	res := hp.ProbeHandshake(context.Background(), ovpnParsersNode(true))
	if res.Level != ProbeLevelNone || res.Reachable {
		t.Fatalf("failed handshake must not raise the level: %+v", res)
	}
	if !strings.Contains(res.Detail, "auth_failed") {
		t.Errorf("detail should carry the classification: %q", res.Detail)
	}
}

func TestHandshakeProberEngineMissingIsNotDowngraded(t *testing.T) {
	ft := &fakeTester{err: errors.New("kernel: LocateBinary [platform_unavailable]: OpenVPN executable not found")}
	hp := &HandshakeProber{Tester: ft}
	res := hp.ProbeHandshake(context.Background(), ovpnParsersNode(true))
	if res.Level == ProbeLevelHandshakeVerified {
		t.Fatal("engine-missing must never read as verified")
	}
	if !strings.Contains(res.Detail, "could not run") {
		t.Errorf("detail should say the handshake could not run: %q", res.Detail)
	}
	// And a prober with no tester at all must say so, not fall
	// back to a reachability claim.
	res = (&HandshakeProber{}).ProbeHandshake(context.Background(), ovpnParsersNode(true))
	if !strings.Contains(res.Detail, "no OpenVPN engine wired") {
		t.Errorf("detail should name the wiring error: %q", res.Detail)
	}
}

func TestHandshakeProberNonOpenVPN(t *testing.T) {
	n := ovpnParsersNode(false)
	n.Protocol = "trojan"
	res := (&HandshakeProber{Tester: &fakeTester{}}).ProbeHandshake(context.Background(), n)
	if res.Level != ProbeLevelNone {
		t.Fatalf("non-openvpn node level = %q", res.Level)
	}
}
