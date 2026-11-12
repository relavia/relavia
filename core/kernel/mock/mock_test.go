package mock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/kernel/mock"
)

func validNode() *kernel.Node {
	return &kernel.Node{
		ID:       "node-1",
		Name:     "test vless",
		Protocol: kernel.ProtocolVLESS,
		Server:   "example.com",
		Port:     443,
		Credential: kernel.Credential{
			UUID: "00000000-0000-0000-0000-000000000001",
			Flow: "xtls-rprx-vision",
		},
		Transport: kernel.Transport{Type: kernel.TransportTCP},
		Security: kernel.Security{
			Type:      kernel.SecurityReality,
			PublicKey: "test-public-key",
		},
		UDP:    true,
		Source: kernel.Source{Kind: "manual"},
	}
}

func validConfig() *kernel.Config { return &kernel.Config{Node: validNode()} }

func TestStartStopStateMachine(t *testing.T) {
	ctx := context.Background()
	m := mock.New(mock.Options{})

	if got := m.Status().State; got != kernel.StateIdle {
		t.Fatalf("initial state = %s, want idle", got)
	}
	if err := m.Start(ctx, validConfig(), kernel.PlatformOptions{Mode: kernel.ModeTUN}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st := m.Status()
	if st.State != kernel.StateRunning {
		t.Fatalf("state after Start = %s, want running", st.State)
	}
	if st.ActiveNodeID != "node-1" {
		t.Fatalf("ActiveNodeID = %q, want node-1", st.ActiveNodeID)
	}

	// Double start must be rejected as wrong state.
	err := m.Start(ctx, validConfig(), kernel.PlatformOptions{})
	if !kernel.IsKind(err, kernel.KindWrongState) {
		t.Fatalf("second Start err = %v, want kind wrong_state", err)
	}

	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := m.Status().State; got != kernel.StateStopped {
		t.Fatalf("state after Stop = %s, want stopped", got)
	}
	// Stop is idempotent.
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	// Restart after stop works.
	if err := m.Start(ctx, validConfig(), kernel.PlatformOptions{}); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	if got := m.Status().State; got != kernel.StateRunning {
		t.Fatalf("state after restart = %s, want running", got)
	}
}

func TestStartInvalidConfigKeepsState(t *testing.T) {
	ctx := context.Background()
	m := mock.New(mock.Options{})
	err := m.Start(ctx, &kernel.Config{Node: &kernel.Node{}}, kernel.PlatformOptions{})
	if !kernel.IsKind(err, kernel.KindInvalidConfig) {
		t.Fatalf("Start invalid err = %v, want kind invalid_config", err)
	}
	if got := m.Status().State; got != kernel.StateIdle {
		t.Fatalf("state after rejected Start = %s, want idle (unchanged)", got)
	}
}

func TestStartSimulatedInternalFailure(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	m := mock.New(mock.Options{StartError: boom})
	err := m.Start(ctx, validConfig(), kernel.PlatformOptions{})
	if !kernel.IsKind(err, kernel.KindInternal) {
		t.Fatalf("Start err = %v, want kind internal", err)
	}
	st := m.Status()
	if st.State != kernel.StateFailed {
		t.Fatalf("state = %s, want failed", st.State)
	}
	if st.LastError == nil {
		t.Fatal("Status.LastError is nil after failed start")
	}
	// Stop from failed clears to stopped.
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop after failure: %v", err)
	}
	if got := m.Status().State; got != kernel.StateStopped {
		t.Fatalf("state = %s, want stopped", got)
	}
}

func TestValidateConfigRejections(t *testing.T) {
	ctx := context.Background()
	m := mock.New(mock.Options{})

	cases := []struct {
		name string
		cfg  *kernel.Config
		kind kernel.Kind
	}{
		{"nil config", nil, kernel.KindInvalidConfig},
		{"nil node", &kernel.Config{}, kernel.KindInvalidConfig},
		{"empty node", &kernel.Config{Node: &kernel.Node{}}, kernel.KindInvalidConfig},
		{"port zero", &kernel.Config{Node: &kernel.Node{
			Protocol: kernel.ProtocolVLESS, Server: "a.com", Port: 0,
			Transport: kernel.Transport{Type: kernel.TransportTCP},
		}}, kernel.KindInvalidConfig},
		{"port too large", &kernel.Config{Node: &kernel.Node{
			Protocol: kernel.ProtocolVLESS, Server: "a.com", Port: 70000,
			Transport: kernel.Transport{Type: kernel.TransportTCP},
		}}, kernel.KindInvalidConfig},
		{"unknown protocol", &kernel.Config{Node: &kernel.Node{
			Protocol: "carrier-pigeon", Server: "a.com", Port: 443,
			Transport: kernel.Transport{Type: kernel.TransportTCP},
		}}, kernel.KindInvalidConfig},
		{"reality without public key", &kernel.Config{Node: &kernel.Node{
			Protocol: kernel.ProtocolVLESS, Server: "a.com", Port: 443,
			Transport: kernel.Transport{Type: kernel.TransportTCP},
			Security:  kernel.Security{Type: kernel.SecurityReality},
		}}, kernel.KindInvalidConfig},
		{"unsupported combination", &kernel.Config{Node: &kernel.Node{
			Protocol: kernel.ProtocolVLESS, Server: "a.com", Port: 443,
			Transport: kernel.Transport{Type: kernel.TransportQUIC},
			Security:  kernel.Security{Type: kernel.SecurityTLS},
		}}, kernel.KindUnsupported},
		{"orchestrated-only protocol", &kernel.Config{Node: &kernel.Node{
			Protocol: kernel.ProtocolL2TP, Server: "a.com", Port: 1701,
			Transport: kernel.Transport{Type: kernel.TransportNative},
			Security:  kernel.Security{Type: kernel.SecurityTLS},
		}}, kernel.KindUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.ValidateConfig(ctx, tc.cfg)
			if !kernel.IsKind(err, tc.kind) {
				t.Fatalf("ValidateConfig err = %v, want kind %s", err, tc.kind)
			}
		})
	}

	if err := m.ValidateConfig(ctx, validConfig()); err != nil {
		t.Fatalf("ValidateConfig(valid) = %v, want nil", err)
	}
}

func TestHandshakeSuccess(t *testing.T) {
	ctx := context.Background()
	exit := &kernel.ExitInfo{IP: "203.0.113.7", Country: "JP"}
	m := mock.New(mock.Options{
		HandshakeLatency: 5 * time.Millisecond,
		HandshakeExit:    exit,
	})
	res, err := m.TestHandshake(ctx, validNode())
	if err != nil {
		t.Fatalf("TestHandshake err = %v", err)
	}
	if !res.OK {
		t.Fatalf("res.OK = false, err in result: %v", res.Error)
	}
	if res.Latency != 5*time.Millisecond {
		t.Fatalf("Latency = %v, want configured 5ms", res.Latency)
	}
	if res.Exit == nil || res.Exit.Country != "JP" {
		t.Fatalf("Exit = %+v, want country JP", res.Exit)
	}
}

func TestHandshakeConfiguredFailureIsResultNotError(t *testing.T) {
	ctx := context.Background()
	m := mock.New(mock.Options{FailNodeIDs: map[string]bool{"node-1": true}})
	res, err := m.TestHandshake(ctx, validNode())
	if err != nil {
		t.Fatalf("TestHandshake err = %v, want nil (failure belongs in result)", err)
	}
	if res.OK {
		t.Fatal("res.OK = true, want false for configured failure")
	}
	if res.Error == nil || res.Error.Kind != kernel.KindHandshakeFailed {
		t.Fatalf("res.Error = %v, want kind handshake_failed", res.Error)
	}
}

func TestHandshakeInvalidNode(t *testing.T) {
	ctx := context.Background()
	m := mock.New(mock.Options{})
	_, err := m.TestHandshake(ctx, &kernel.Node{})
	if !kernel.IsKind(err, kernel.KindInvalidConfig) {
		t.Fatalf("err = %v, want kind invalid_config", err)
	}
}

func TestHandshakeContextCancel(t *testing.T) {
	m := mock.New(mock.Options{HandshakeLatency: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.TestHandshake(ctx, validNode())
	if err == nil || kernel.KindOf(err) != kernel.KindCanceled {
		t.Fatalf("err = %v, want context canceled (kind canceled)", err)
	}
}

func TestCapabilitiesSelfReport(t *testing.T) {
	m := mock.New(mock.Options{})
	caps := m.Capabilities()
	if caps.KernelID != "mock" {
		t.Fatalf("KernelID = %q, want mock", caps.KernelID)
	}
	mustSupport := []struct {
		p  kernel.Protocol
		tr kernel.TransportType
		s  kernel.SecurityType
	}{
		{kernel.ProtocolVLESS, kernel.TransportTCP, kernel.SecurityReality},
		{kernel.ProtocolVLESS, kernel.TransportGRPC, kernel.SecurityTLS},
		{kernel.ProtocolShadowsocks, kernel.TransportNative, kernel.SecurityAEAD},
		{kernel.ProtocolTrojan, kernel.TransportWS, kernel.SecurityTLS},
		{kernel.ProtocolHysteria2, kernel.TransportQUIC, kernel.SecurityTLS},
		{kernel.ProtocolWireGuard, kernel.TransportNative, kernel.SecurityNone},
		{kernel.ProtocolOpenVPN, kernel.TransportUDP, kernel.SecurityTLS},
	}
	for _, tc := range mustSupport {
		if !caps.Supports(tc.p, tc.tr, tc.s) {
			t.Errorf("Supports(%s,%s,%s) = false, want true", tc.p, tc.tr, tc.s)
		}
	}
	mustNotSupport := []struct {
		p  kernel.Protocol
		tr kernel.TransportType
		s  kernel.SecurityType
	}{
		{kernel.ProtocolVLESS, kernel.TransportQUIC, kernel.SecurityTLS},
		{kernel.ProtocolL2TP, kernel.TransportNative, kernel.SecurityTLS},
		{kernel.ProtocolShadowsocks, kernel.TransportTCP, kernel.SecurityAEAD},
	}
	for _, tc := range mustNotSupport {
		if caps.Supports(tc.p, tc.tr, tc.s) {
			t.Errorf("Supports(%s,%s,%s) = true, want false", tc.p, tc.tr, tc.s)
		}
	}
	if !caps.Platform.TUN || !caps.Platform.KillSwitch {
		t.Error("default platform capabilities should report TUN and kill switch")
	}
}

func TestStartPlatformUnavailable(t *testing.T) {
	ctx := context.Background()
	caps := mock.DefaultCapabilities()
	caps.Platform.TUN = false
	m := mock.New(mock.Options{Capabilities: caps})
	err := m.Start(ctx, validConfig(), kernel.PlatformOptions{Mode: kernel.ModeTUN})
	if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("err = %v, want kind platform_unavailable", err)
	}
}

func TestQueryTrafficLifecycle(t *testing.T) {
	ctx := context.Background()
	m := mock.New(mock.Options{UploadRateBps: 100_000, DownloadRateBps: 200_000})

	// Before start: zero counters, no error.
	ts, err := m.QueryTraffic(ctx)
	if err != nil {
		t.Fatalf("QueryTraffic before start: %v", err)
	}
	if ts.UploadBytes != 0 || ts.DownloadBytes != 0 {
		t.Fatalf("counters before start = %d/%d, want 0/0", ts.UploadBytes, ts.DownloadBytes)
	}

	if err := m.Start(ctx, validConfig(), kernel.PlatformOptions{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	ts1, _ := m.QueryTraffic(ctx)
	if ts1.UploadBytes == 0 || ts1.DownloadBytes == 0 {
		t.Fatalf("counters while running = %d/%d, want > 0", ts1.UploadBytes, ts1.DownloadBytes)
	}
	if ts1.DownloadBytes <= ts1.UploadBytes {
		t.Fatalf("download (%d) should exceed upload (%d) at 2x rate",
			ts1.DownloadBytes, ts1.UploadBytes)
	}

	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	ts2, _ := m.QueryTraffic(ctx)
	time.Sleep(30 * time.Millisecond)
	ts3, _ := m.QueryTraffic(ctx)
	if ts2.UploadBytes != ts3.UploadBytes || ts2.DownloadBytes != ts3.DownloadBytes {
		t.Fatal("counters must freeze after Stop")
	}
}
