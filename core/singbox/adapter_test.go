package singbox

import (
	"context"
	"testing"

	"openproxy/core/kernel"
)

// Lifecycle and gating semantics exercised against a REAL sing-box
// instance (started on loopback; the outbound is lazy so no
// external server is needed for these state tests).

func ssKernelNode() *kernel.Node {
	return &kernel.Node{
		ID:       "n-ss",
		Name:     "loopback-ss",
		Protocol: kernel.ProtocolShadowsocks,
		Server:   "127.0.0.1",
		Port:     8388,
		Credential: kernel.Credential{
			Method:   "2022-blake3-aes-256-gcm",
			Password: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", // base64 of a 32-byte SS2022 key
		},
		Transport: kernel.Transport{Type: kernel.TransportNative},
		Security:  kernel.Security{Type: kernel.SecurityAEAD},
		UDP:       true,
	}
}

func TestAdapterLifecycle(t *testing.T) {
	ctx := context.Background()
	a := New(Options{})

	if got := a.Status().State; got != kernel.StateIdle {
		t.Fatalf("initial state = %s", got)
	}
	ts, err := a.QueryTraffic(ctx)
	if err != nil || ts.UploadBytes != 0 || ts.DownloadBytes != 0 {
		t.Fatalf("traffic before first run: %+v, %v", ts, err)
	}
	// Idempotent stop from idle.
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("Stop from idle: %v", err)
	}

	cfg := &kernel.Config{Node: ssKernelNode()}
	if err := a.ValidateConfig(ctx, cfg); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if err := a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st := a.Status()
	if st.State != kernel.StateRunning || st.ActiveNodeID != "n-ss" {
		t.Fatalf("status after start: %+v", st)
	}
	if a.MixedAddr() == "" {
		t.Fatal("MixedAddr empty while running")
	}
	// Second Start must be refused.
	if err := a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeManual}); !kernel.IsKind(err, kernel.KindWrongState) {
		t.Fatalf("second Start err = %v, want wrong_state", err)
	}
	ts, err = a.QueryTraffic(ctx)
	if err != nil {
		t.Fatalf("QueryTraffic while running: %v", err)
	}
	if ts.SessionStartedAt.IsZero() {
		t.Fatal("SessionStartedAt not set while running")
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := a.Status().State; got != kernel.StateStopped {
		t.Fatalf("state after stop = %s", got)
	}
	if a.MixedAddr() != "" {
		t.Fatal("MixedAddr must be empty after stop")
	}
	// Restart after stop is allowed by the interface contract.
	if err := a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeManual}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatalf("final stop: %v", err)
	}
}

func TestAdapterPlatformGates(t *testing.T) {
	ctx := context.Background()
	a := New(Options{})
	cfg := &kernel.Config{Node: ssKernelNode()}

	if err := a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeTUN}); !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("TUN start err = %v, want platform_unavailable", err)
	}
	if err := a.Start(ctx, cfg, kernel.PlatformOptions{Mode: kernel.ModeManual, KillSwitch: true}); !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("kill-switch start err = %v, want platform_unavailable", err)
	}
	if got := a.Status().State; got != kernel.StateIdle {
		t.Fatalf("state after refused starts = %s, want idle (refusals must not change state)", got)
	}
	caps := a.Capabilities()
	if caps.Platform.TUN || caps.Platform.KillSwitch || caps.Platform.SystemProxy {
		t.Fatalf("platform caps must be honestly false in this step: %+v", caps.Platform)
	}
}

func TestAdapterValidationErrors(t *testing.T) {
	ctx := context.Background()
	a := New(Options{})

	// OpenVPN: known protocol, but independent-process only.
	ovpn := &kernel.Node{
		ID: "n-ovpn", Protocol: kernel.ProtocolOpenVPN,
		Server: "127.0.0.1", Port: 1194,
		Transport: kernel.Transport{Type: kernel.TransportUDP},
		Security:  kernel.Security{Type: kernel.SecurityTLS},
	}
	err := a.ValidateConfig(ctx, &kernel.Config{Node: ovpn})
	if err == nil {
		t.Fatal("openvpn ValidateConfig passed, want error")
	}
	// Either the matrix check (unsupported) fires — the openvpn
	// node is not in this adapter's matrix at all.
	if k := kernel.KindOf(err); k != kernel.KindUnsupported {
		t.Fatalf("openvpn kind = %s, want unsupported (%v)", k, err)
	}

	// WireGuard through the placeholder path: the placeholder
	// cannot carry keys, so the error must name the gap precisely
	// (invalid_config), never a silent wrong configuration.
	wg := &kernel.Node{
		ID: "n-wg", Protocol: kernel.ProtocolWireGuard,
		Server: "127.0.0.1", Port: 51820,
		Transport: kernel.Transport{Type: kernel.TransportNative},
		Security:  kernel.Security{Type: kernel.SecurityNone},
	}
	if featureWireGuard {
		err = a.ValidateConfig(ctx, &kernel.Config{Node: wg})
		if !kernel.IsKind(err, kernel.KindInvalidConfig) {
			t.Fatalf("wireguard placeholder err = %v, want invalid_config naming the missing keys", err)
		}
	}

	// Reality without public key is a structural error.
	bad := ssKernelNode()
	bad.Protocol = kernel.ProtocolVLESS
	bad.Credential = kernel.Credential{UUID: "20000000-0000-4000-8000-000000000004"}
	bad.Transport = kernel.Transport{Type: kernel.TransportTCP}
	bad.Security = kernel.Security{Type: kernel.SecurityReality}
	if err := a.ValidateConfig(ctx, &kernel.Config{Node: bad}); !kernel.IsKind(err, kernel.KindInvalidConfig) {
		t.Fatalf("reality-no-key err = %v, want invalid_config", err)
	}
}
