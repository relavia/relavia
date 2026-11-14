package libboxbind

// Host-side proof of the OpenVPN 3 bridge engine
// (docs/openvpn3安卓接线.md): the dispatch's Android OpenVPN
// slot must behave like the desktop adapter — consent first,
// profile rendered by the shared builders (credentials never
// inside the profile text), CONNECTED completes the start,
// fatal core events classify onto the desktop taxonomy
// (openvpn.CodeOf), and with no native bridge registered the
// engine degrades to the exact honest-unavailable behaviour
// the slot had before. The native side is a fake bridge here;
// the real core is a CI/device matter (build spike doc).

import (
	"context"
	"strings"
	"testing"
	"time"

	"openproxy/app/android"
	"openproxy/app/platform"
	"openproxy/core/kernel"
	"openproxy/core/openvpn"
	"openproxy/core/specnode"
)

// fakeOvpn3Bridge records what the engine handed over and
// replays a scripted core event synchronously (the engine's
// waiter channel is buffered, so ordering is deterministic).
type fakeOvpn3Bridge struct {
	script   string // event name to emit on start; "" = none
	fatal    bool
	profile  string
	username string
	password string
	starts   int
	stops    int
}

func (f *fakeOvpn3Bridge) StartOvpn3Session(profile, username, password string) error {
	f.starts++
	f.profile, f.username, f.password = profile, username, password
	if f.script != "" {
		NotifyOvpn3Event(f.script, "fake core event", f.fatal)
	}
	return nil
}

func (f *fakeOvpn3Bridge) StopOvpn3Session() error {
	f.stops++
	NotifyOvpn3Event("DISCONNECTED", "fake core event", false)
	return nil
}

// fakeConsentBinder implements platform.VPNBinder with a
// scripted consent answer; Establish is never reached by the
// OpenVPN 3 engine (the core builds its own TUN natively).
type fakeConsentBinder struct{ granted bool }

func (b fakeConsentBinder) Prepare(context.Context) (bool, error) { return b.granted, nil }
func (b fakeConsentBinder) Establish(context.Context, platform.TUNRequest) (platform.TUNHandle, error) {
	return nil, platform.ErrUnavailable
}
func (b fakeConsentBinder) Teardown(context.Context) error { return nil }

func withConsent(t *testing.T, granted bool) {
	t.Helper()
	prev := platform.RegisteredBinder()
	platform.RegisterVPNBinder(fakeConsentBinder{granted: granted})
	t.Cleanup(func() { platform.RegisterVPNBinder(prev) })
}

func withBridge(t *testing.T, b Ovpn3Bridge) {
	t.Helper()
	prev := currentOvpn3Bridge()
	RegisterOvpn3Bridge(b)
	t.Cleanup(func() { RegisterOvpn3Bridge(prev) })
}

func ovpn3Node() *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "22222222-2222-2222-2222-222222222222",
		Name:          "pool-jp",
		Protocol:      specnode.ProtocolOpenVPN,
		OpenVPN: &specnode.CredOpenVPN{
			ConfigContent: "client\ndev tun\nproto tcp\nremote 203.0.113.7 443\nresolv-retry infinite\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n",
			Username:      "vpn",
			Password:      "s3cret-value",
		},
		Source: specnode.SourceRef{Kind: "plugin", Ref: "vpngate", Authorization: "public"},
	}
}

func TestOvpn3EngineNoBridgeIsHonestlyUnavailable(t *testing.T) {
	withBridge(t, nil)
	e := newOvpn3Engine(nil)
	if e.ConnectAvailable() {
		t.Fatal("ConnectAvailable = true with no bridge registered")
	}
	err := e.StartNode(context.Background(), ovpn3Node(), kernel.PlatformOptions{})
	if kernel.KindOf(err) != kernel.KindPlatformUnavailable {
		t.Fatalf("StartNode kind = %v, want platform_unavailable (%v)", kernel.KindOf(err), err)
	}
	if e.Capabilities().Platform.TUN {
		t.Error("Capabilities claim TUN without a native bridge")
	}
	res, _ := e.TestHandshakeNode(context.Background(), ovpn3Node())
	if res.OK || res.Error == nil || res.Error.Kind != kernel.KindPlatformUnavailable {
		t.Errorf("handshake without bridge = %+v, want platform_unavailable result", res)
	}
}

func TestOvpn3EngineConnectViaFakeBridge(t *testing.T) {
	withConsent(t, true)
	bridge := &fakeOvpn3Bridge{script: "CONNECTED"}
	withBridge(t, bridge)
	e := newOvpn3Engine(nil)

	if !e.ConnectAvailable() {
		t.Fatal("ConnectAvailable = false with a bridge registered")
	}
	if err := e.StartNode(context.Background(), ovpn3Node(), kernel.PlatformOptions{}); err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	if bridge.starts != 1 {
		t.Fatalf("native starts = %d, want 1", bridge.starts)
	}
	// The profile is rendered by the shared builders and the
	// password never travels inside it.
	if !strings.Contains(bridge.profile, "remote 203.0.113.7 443") {
		t.Errorf("profile lost the remote line:\n%s", bridge.profile)
	}
	if strings.Contains(bridge.profile, "s3cret-value") {
		t.Error("password leaked into the profile text handed to the core")
	}
	if bridge.username != "vpn" || bridge.password != "s3cret-value" {
		t.Errorf("creds handed over = %q/%q, want the node's as separate args", bridge.username, bridge.password)
	}
	if st := e.Status(); st.State != kernel.StateRunning || st.ActiveNodeID == "" {
		t.Errorf("Status = %+v, want running with the active node", st)
	}
	NotifyOvpn3Traffic(1024, 4096)
	ts, err := e.QueryTraffic(context.Background())
	if err != nil || ts.UploadBytes != 1024 || ts.DownloadBytes != 4096 {
		t.Errorf("QueryTraffic = %+v, %v; want the notified counters", ts, err)
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if bridge.stops != 1 {
		t.Errorf("native stops = %d, want 1", bridge.stops)
	}
	if st := e.Status(); st.State != kernel.StateIdle {
		t.Errorf("Status after Stop = %+v, want idle", st)
	}
}

func TestOvpn3EngineConsentRefused(t *testing.T) {
	withConsent(t, false)
	bridge := &fakeOvpn3Bridge{script: "CONNECTED"}
	withBridge(t, bridge)
	e := newOvpn3Engine(nil)
	err := e.StartNode(context.Background(), ovpn3Node(), kernel.PlatformOptions{})
	if err != android.ErrPermissionDenied {
		t.Fatalf("StartNode = %v, want android.ErrPermissionDenied", err)
	}
	if bridge.starts != 0 {
		t.Error("native session launched despite refused consent")
	}
}

func TestOvpn3EngineAuthFailureClassification(t *testing.T) {
	withConsent(t, true)
	bridge := &fakeOvpn3Bridge{script: "AUTH_FAILED", fatal: true}
	withBridge(t, bridge)
	e := newOvpn3Engine(nil)
	err := e.StartNode(context.Background(), ovpn3Node(), kernel.PlatformOptions{})
	if err == nil {
		t.Fatal("StartNode succeeded on an AUTH_FAILED core")
	}
	if got := openvpn.CodeOf(err); got != openvpn.CodeAuthFailed {
		t.Errorf("CodeOf = %q, want %q (err %v)", got, openvpn.CodeAuthFailed, err)
	}
	if k := kernel.KindOf(err); k != kernel.KindHandshakeFailed {
		t.Errorf("KindOf = %q, want handshake_failed", k)
	}
	if st := e.Status(); st.State != kernel.StateFailed || st.LastError == nil {
		t.Errorf("Status = %+v, want failed with LastError", st)
	}
}

func TestOvpn3EngineHandshakeProbe(t *testing.T) {
	withConsent(t, true)
	bridge := &fakeOvpn3Bridge{script: "CONNECTED"}
	withBridge(t, bridge)
	e := newOvpn3Engine(nil)

	res, err := e.TestHandshakeNode(context.Background(), ovpn3Node())
	if err != nil {
		t.Fatalf("TestHandshakeNode error: %v", err)
	}
	if !res.OK || res.Latency <= 0 {
		t.Errorf("probe = %+v, want OK with measured latency", res)
	}
	if bridge.stops != 1 {
		t.Errorf("probe left the session up: stops = %d, want 1 (probe tears down)", bridge.stops)
	}
	if st := e.Status(); st.State != kernel.StateIdle {
		t.Errorf("Status after probe = %+v, want idle", st)
	}
}

func TestOvpn3EngineValidateAndCredsGate(t *testing.T) {
	e := newOvpn3Engine(nil)
	if err := e.ValidateSpec(context.Background(), &specnode.Node{Protocol: specnode.ProtocolTrojan}); err == nil {
		t.Error("ValidateSpec accepted a non-OpenVPN node")
	}
	// auth-user-pass profile without credentials must refuse
	// with the shared classification before any native start.
	n := ovpn3Node()
	n.OpenVPN.Username = ""
	n.OpenVPN.Password = ""
	err := e.ValidateSpec(context.Background(), n)
	if got := openvpn.CodeOf(err); got != openvpn.CodeAuthNoCredentials {
		t.Errorf("CodeOf = %q, want %q (err %v)", got, openvpn.CodeAuthNoCredentials, err)
	}
}

// TestOvpn3EngineStartCanceled is the 2026-11-14 fix-batch
// engine half of the chain-cancellation fix: a start waiting
// on a silent core must unwind as CANCELED (not timeout) as
// soon as the caller's context dies — this is what lets
// Disconnect interrupt a manual connect and a chain attempt
// without burning the full 45 s bound.
func TestOvpn3EngineStartCanceled(t *testing.T) {
	withConsent(t, true)
	bridge := &fakeOvpn3Bridge{script: ""} // core never answers
	withBridge(t, bridge)
	e := newOvpn3Engine(nil)
	e.connectTimeout = 30 * time.Second // must NOT be what ends the wait

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := e.StartNode(ctx, ovpn3Node(), kernel.PlatformOptions{})
	if err == nil {
		t.Fatal("StartNode succeeded against a silent core")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("StartNode took %v; caller cancellation did not unwind the wait", elapsed)
	}
	if k := kernel.KindOf(err); k != kernel.KindCanceled {
		t.Errorf("KindOf = %q, want canceled (err %v)", k, err)
	}
	if bridge.stops != 1 {
		t.Errorf("native stops = %d, want 1 (cancel must stop the core)", bridge.stops)
	}
}

func TestOvpn3EngineStartTimeout(t *testing.T) {
	withConsent(t, true)
	bridge := &fakeOvpn3Bridge{script: ""} // core never answers
	withBridge(t, bridge)
	e := newOvpn3Engine(nil)
	e.connectTimeout = 150 * time.Millisecond

	start := time.Now()
	err := e.StartNode(context.Background(), ovpn3Node(), kernel.PlatformOptions{})
	if err == nil {
		t.Fatal("StartNode succeeded against a silent core")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("StartNode took %v; the shrunk bound did not apply", elapsed)
	}
	if got := openvpn.CodeOf(err); got != openvpn.CodeConnectTimeout {
		t.Errorf("CodeOf = %q, want %q (err %v)", got, openvpn.CodeConnectTimeout, err)
	}
	if k := kernel.KindOf(err); k != kernel.KindTimeout {
		t.Errorf("KindOf = %q, want timeout", k)
	}
	if bridge.stops != 1 {
		t.Errorf("native stops = %d, want 1 (timeout must stop the core)", bridge.stops)
	}
	if st := e.Status(); st.State != kernel.StateFailed {
		t.Errorf("Status = %+v, want failed after timeout", st)
	}
}
