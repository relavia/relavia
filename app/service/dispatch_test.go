package service_test

import (
	"context"

	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/app/service"
)

// recEngine is a recording Engine for dispatch routing tests:
// it remembers which nodes it was asked to start / test and
// never touches a real kernel.
type recEngine struct {
	id        string
	started   []*specnode.Node
	tested    []*specnode.Node
	validated []*specnode.Node
	stopped   bool
	protocols map[kernel.Protocol]kernel.ProtocolSupport
}

func (e *recEngine) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{KernelID: e.id, Protocols: e.protocols}
}

func (e *recEngine) ValidateSpec(_ context.Context, n *specnode.Node) error {
	e.validated = append(e.validated, n)
	return nil
}

func (e *recEngine) StartNode(_ context.Context, n *specnode.Node, _ kernel.PlatformOptions) error {
	e.started = append(e.started, n)
	return nil
}

func (e *recEngine) Stop(_ context.Context) error { e.stopped = true; return nil }

func (e *recEngine) Status() kernel.Status {
	if len(e.started) > 0 && !e.stopped {
		return kernel.Status{State: kernel.StateRunning, ActiveNodeID: e.started[len(e.started)-1].ID}
	}
	return kernel.Status{State: kernel.StateIdle}
}

func (e *recEngine) TestHandshakeNode(_ context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	e.tested = append(e.tested, n)
	return &kernel.HandshakeResult{NodeID: n.ID, OK: true, TestedAt: time.Now()}, nil
}

func (e *recEngine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	return &kernel.TrafficStats{}, nil
}

func (e *recEngine) MixedAddr() string { return "" }

func protoNode(id, protocol string) *specnode.Node {
	return &specnode.Node{ID: id, Name: id, Protocol: protocol, Server: "127.0.0.1", Port: 443}
}

func TestDispatchRoutesByProtocolFamily(t *testing.T) {
	primary := &recEngine{id: "primary"}
	ovpn := &recEngine{id: "openvpn"}
	d := service.NewDispatchEngine(primary, ovpn)
	ctx := context.Background()

	for _, proto := range []string{
		specnode.ProtocolShadowsocks, specnode.ProtocolTrojan,
		specnode.ProtocolVMess, specnode.ProtocolVLESS,
		specnode.ProtocolHysteria2, specnode.ProtocolTUIC,
		specnode.ProtocolWireGuard,
		specnode.ProtocolSOCKS5, specnode.ProtocolHTTP,
	} {
		n := protoNode("n-"+proto, proto)
		if err := d.StartNode(ctx, n, kernel.PlatformOptions{}); err != nil {
			t.Fatalf("StartNode(%s): %v", proto, err)
		}
		if err := d.Stop(ctx); err != nil {
			t.Fatalf("Stop after %s: %v", proto, err)
		}
		if _, err := d.TestHandshakeNode(ctx, n); err != nil {
			t.Fatalf("TestHandshakeNode(%s): %v", proto, err)
		}
	}
	if len(primary.started) != 9 || len(primary.tested) != 9 {
		t.Fatalf("primary got started=%d tested=%d, want 9/9", len(primary.started), len(primary.tested))
	}
	if len(ovpn.started) != 0 || len(ovpn.tested) != 0 {
		t.Fatalf("openvpn slot must stay untouched for sing-box families, got started=%d tested=%d",
			len(ovpn.started), len(ovpn.tested))
	}

	ovpnNode := protoNode("pool-1", specnode.ProtocolOpenVPN)
	if err := d.StartNode(ctx, ovpnNode, kernel.PlatformOptions{}); err != nil {
		t.Fatalf("StartNode(openvpn): %v", err)
	}
	if len(ovpn.started) != 1 || ovpn.started[0] != ovpnNode {
		t.Fatalf("openvpn node did not reach the openvpn slot: %+v", ovpn.started)
	}
	if st := d.Status(); st.State != kernel.StateRunning || st.ActiveNodeID != "pool-1" {
		t.Fatalf("Status must follow the active (openvpn) session, got %+v", st)
	}
	if err := d.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !ovpn.stopped {
		t.Fatal("Stop must reach the engine running the active session")
	}
	primary.stopped = false
	if _, err := d.TestHandshakeNode(ctx, ovpnNode); err != nil {
		t.Fatal(err)
	}
	if len(ovpn.tested) != 1 {
		t.Fatalf("openvpn handshake test misrouted: tested=%d", len(ovpn.tested))
	}
}

func TestDispatchRejectsUnknownProtocol(t *testing.T) {
	d := service.NewDispatchEngine(&recEngine{id: "p"}, &recEngine{id: "o"})
	bad := protoNode("bad", "carrier-pigeon")
	ctx := context.Background()
	if err := d.StartNode(ctx, bad, kernel.PlatformOptions{}); kernel.KindOf(err) != kernel.KindUnsupported {
		t.Fatalf("StartNode unknown protocol: kind=%v err=%v", kernel.KindOf(err), err)
	}
	if _, err := d.TestHandshakeNode(ctx, bad); kernel.KindOf(err) != kernel.KindUnsupported {
		t.Fatalf("TestHandshakeNode unknown protocol: kind=%v err=%v", kernel.KindOf(err), err)
	}
	if err := d.ValidateSpec(ctx, bad); kernel.KindOf(err) != kernel.KindUnsupported {
		t.Fatalf("ValidateSpec unknown protocol: kind=%v err=%v", kernel.KindOf(err), err)
	}
	if d.CanConnect("carrier-pigeon") {
		t.Fatal("CanConnect must be false for an unknown protocol")
	}
}

func TestDispatchCapabilitiesOverlay(t *testing.T) {
	sup := kernel.ProtocolSupport{Transports: map[kernel.TransportType]kernel.TransportSupport{
		kernel.TransportTCP: {UDP: false},
	}}
	primary := &recEngine{id: "p", protocols: map[kernel.Protocol]kernel.ProtocolSupport{
		kernel.ProtocolShadowsocks: sup,
	}}
	ovpn := &recEngine{id: "o", protocols: map[kernel.Protocol]kernel.ProtocolSupport{
		kernel.ProtocolOpenVPN: sup,
	}}
	d := service.NewDispatchEngine(primary, ovpn)
	caps := d.Capabilities()
	_, hasSS := caps.Protocols[kernel.ProtocolShadowsocks]
	_, hasOVPN := caps.Protocols[kernel.ProtocolOpenVPN]
	if !hasSS || !hasOVPN {
		t.Fatalf("capabilities must carry both families: %+v", caps.Protocols)
	}
}

func TestDispatchCanConnectWiring(t *testing.T) {
	primary := &recEngine{id: "p"}
	// Android wiring: OpenVPN slot present but unavailable.
	d := service.NewDispatchEngine(primary, &service.UnavailableEngine{Reason: "no child processes on Android"})
	if d.CanConnect(specnode.ProtocolOpenVPN) {
		t.Fatal("openvpn must not be connectable through the unavailable slot")
	}
	if !d.CanConnect(specnode.ProtocolShadowsocks) {
		t.Fatal("sing-box families stay connectable")
	}
	// Desktop wiring: real slot.
	d2 := service.NewDispatchEngine(primary, &recEngine{id: "o"})
	if !d2.CanConnect(specnode.ProtocolOpenVPN) {
		t.Fatal("openvpn must be connectable with a real engine wired")
	}
	// Unwired slot: explicit refusal, not a panic.
	d3 := service.NewDispatchEngine(primary, nil)
	if d3.CanConnect(specnode.ProtocolOpenVPN) {
		t.Fatal("openvpn must not be connectable when no engine is wired")
	}
	if err := d3.StartNode(context.Background(), protoNode("x", specnode.ProtocolOpenVPN), kernel.PlatformOptions{}); err == nil {
		t.Fatal("StartNode with no openvpn engine wired must fail explicitly")
	}
}

func TestUnavailableEngineHonestFailures(t *testing.T) {
	e := &service.UnavailableEngine{Reason: "test reason"}
	ctx := context.Background()
	n := protoNode("x", specnode.ProtocolOpenVPN)
	if err := e.StartNode(ctx, n, kernel.PlatformOptions{}); kernel.KindOf(err) != kernel.KindPlatformUnavailable {
		t.Fatalf("StartNode: kind=%v err=%v", kernel.KindOf(err), err)
	}
	if _, err := e.TestHandshakeNode(ctx, n); kernel.KindOf(err) != kernel.KindPlatformUnavailable {
		t.Fatalf("TestHandshakeNode: kind=%v err=%v", kernel.KindOf(err), err)
	}
	if err := e.ValidateSpec(ctx, n); kernel.KindOf(err) != kernel.KindPlatformUnavailable {
		t.Fatalf("ValidateSpec: kind=%v err=%v", kernel.KindOf(err), err)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatalf("Stop must stay idempotent-nil: %v", err)
	}
	if st := e.Status(); st.State != kernel.StateIdle {
		t.Fatalf("Status: %+v", st)
	}
	if e.ConnectAvailable() {
		t.Fatal("ConnectAvailable must be false")
	}
}

func TestServiceCanConnect(t *testing.T) {
	// Bare (non-dispatch) engine: the fallback speaks for the
	// only production single engine, sing-box.
	svc, _ := newTestService(t, &fakeEngine{})
	if svc.CanConnect(specnode.ProtocolOpenVPN) {
		t.Fatal("bare sing-box wiring cannot connect openvpn")
	}
	if !svc.CanConnect(specnode.ProtocolShadowsocks) {
		t.Fatal("bare sing-box wiring connects its families")
	}
	// No engine at all: nothing is connectable.
	svcNil, _ := newTestService(t, nil)
	if svcNil.CanConnect(specnode.ProtocolShadowsocks) {
		t.Fatal("nil engine must connect nothing")
	}
	// Dispatch wiring flows through.
	d := service.NewDispatchEngine(&fakeEngine{}, &service.UnavailableEngine{Reason: "x"})
	svcD, _ := newTestService(t, d)
	if svcD.CanConnect(specnode.ProtocolOpenVPN) {
		t.Fatal("dispatch+unavailable slot must report openvpn unconnectable")
	}
	if !svcD.CanConnect(specnode.ProtocolTrojan) {
		t.Fatal("dispatch wiring keeps sing-box families connectable")
	}
}
