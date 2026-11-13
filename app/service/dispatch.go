package service

import (
	"context"
	"sync"

	"openproxy/core/kernel"
	"openproxy/core/openvpn"
	"openproxy/core/specnode"
)

// Protocol dispatch (docs/openvpn进程适配.md §7 item 3): the
// service layer used to hold exactly one engine (sing-box), so
// OpenVPN nodes — including the whole VPN Gate pool — could be
// imported and probed but never connected or handshake-tested
// from the app. DispatchEngine restores the routing the unified
// model always implied:
//
//   - the nine sing-box protocol families go to the sing-box
//     adapter (Primary);
//   - openvpn nodes go to the OpenVPN independent-process
//     adapter (OpenVPN);
//   - anything else is refused explicitly with KindUnsupported —
//     there is no silent fallback to the other engine.
//
// Platform wiring chooses the OpenVPN slot: desktop builds wire
// the real process adapter; Android builds wire
// UnavailableEngine, because a child-process engine cannot run
// there (no exec of bundled binaries on modern Android) — pool
// nodes stay importable and probeable, and connects fail with
// the honest KindPlatformUnavailable instead of pretending.

// OpenVPNEngine adapts *openvpn.Adapter to Engine.
type OpenVPNEngine struct {
	Adapter *openvpn.Adapter
}

// NewOpenVPNEngine builds the production OpenVPN process engine.
// onLog receives redacted child output lines for the client's
// local log view.
func NewOpenVPNEngine(onLog func(level, message string)) *OpenVPNEngine {
	return &OpenVPNEngine{Adapter: openvpn.New(openvpn.Options{OnLog: onLog})}
}

func (e *OpenVPNEngine) Capabilities() kernel.Capabilities { return e.Adapter.Capabilities() }

func (e *OpenVPNEngine) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	return e.Adapter.ValidateSpec(ctx, n)
}

func (e *OpenVPNEngine) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	return e.Adapter.StartNode(ctx, n, opts)
}

func (e *OpenVPNEngine) Stop(ctx context.Context) error { return e.Adapter.Stop(ctx) }

func (e *OpenVPNEngine) Status() kernel.Status { return e.Adapter.Status() }

func (e *OpenVPNEngine) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return e.Adapter.TestHandshakeNode(ctx, n)
}

func (e *OpenVPNEngine) QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error) {
	return e.Adapter.QueryTraffic(ctx)
}

// MixedAddr is empty: a child-process TUN tunnel exposes no
// local mixed listener (honest absence, not a fake address).
func (e *OpenVPNEngine) MixedAddr() string { return "" }

// UnavailableEngine is an Engine slot that exists only to fail
// honestly: every operation returns KindPlatformUnavailable
// carrying the fixed reason. It marks a protocol family that
// this build/platform cannot serve (Android's OpenVPN slot).
type UnavailableEngine struct {
	// Reason is the internal, log-facing explanation (the UI
	// renders its own localized string for the error kind).
	Reason string
}

// ConnectAvailable reports that no connect can ever succeed
// through this engine.
func (e *UnavailableEngine) ConnectAvailable() bool { return false }

func (e *UnavailableEngine) fail(op string) error {
	reason := e.Reason
	if reason == "" {
		reason = "engine unavailable on this platform"
	}
	return kernel.NewError(kernel.KindPlatformUnavailable, op, reason, nil)
}

func (e *UnavailableEngine) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{KernelID: "unavailable"}
}

func (e *UnavailableEngine) ValidateSpec(_ context.Context, _ *specnode.Node) error {
	return e.fail("ValidateSpec")
}

func (e *UnavailableEngine) StartNode(_ context.Context, _ *specnode.Node, _ kernel.PlatformOptions) error {
	return e.fail("Start")
}

func (e *UnavailableEngine) Stop(context.Context) error { return nil }

func (e *UnavailableEngine) Status() kernel.Status { return kernel.Status{State: kernel.StateIdle} }

func (e *UnavailableEngine) TestHandshakeNode(_ context.Context, _ *specnode.Node) (*kernel.HandshakeResult, error) {
	return nil, e.fail("TestHandshake")
}

func (e *UnavailableEngine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	return &kernel.TrafficStats{}, nil
}

func (e *UnavailableEngine) MixedAddr() string { return "" }

// NewAndroidOpenVPNEngine returns the OpenVPN slot for Android
// builds: the independent-process adapter cannot run there —
// modern Android gives an app no way to execute a bundled
// child-process binary — so the slot fails every operation
// honestly (KindPlatformUnavailable) instead of pretending.
// Pool nodes on Android stay importable and TCP-probeable; the
// OpenVPN 3 library route is the tracked future option
// (docs/openvpn进程适配.md §6).
func NewAndroidOpenVPNEngine() *UnavailableEngine {
	return &UnavailableEngine{Reason: "the OpenVPN process adapter cannot run on Android (no child-process execution for bundled binaries); OpenVPN nodes are import/probe-only on this platform"}
}

// DispatchEngine routes Engine operations to the adapter that
// serves the node's protocol family. Lifecycle state (which
// adapter currently runs a session) is tracked so Stop / Status
// / Traffic / MixedAddr follow the active session.
type DispatchEngine struct {
	Primary Engine // sing-box families
	OpenVPN Engine // may be nil: openvpn then fails as unwired

	mu     sync.Mutex
	active Engine
}

// NewDispatchEngine builds the routing engine. primary must be
// non-nil; openvpnEng may be nil (OpenVPN nodes then fail with
// an explicit "not wired" platform error) or an
// *UnavailableEngine (the Android wiring).
func NewDispatchEngine(primary, openvpnEng Engine) *DispatchEngine {
	return &DispatchEngine{Primary: primary, OpenVPN: openvpnEng}
}

// EngineFor resolves the adapter serving one protocol family.
func (d *DispatchEngine) EngineFor(protocol string) (Engine, error) {
	switch protocol {
	case specnode.ProtocolOpenVPN:
		if d.OpenVPN == nil {
			return nil, kernel.NewError(kernel.KindPlatformUnavailable, "Dispatch",
				"no OpenVPN engine is wired in this build", nil)
		}
		return d.OpenVPN, nil
	case specnode.ProtocolShadowsocks, specnode.ProtocolTrojan,
		specnode.ProtocolVMess, specnode.ProtocolVLESS,
		specnode.ProtocolHysteria2, specnode.ProtocolTUIC,
		specnode.ProtocolWireGuard,
		specnode.ProtocolSOCKS5, specnode.ProtocolHTTP:
		if d.Primary == nil {
			return nil, kernel.NewError(kernel.KindPlatformUnavailable, "Dispatch",
				"no primary engine is wired in this build", nil)
		}
		return d.Primary, nil
	default:
		return nil, kernel.NewError(kernel.KindUnsupported, "Dispatch",
			"unknown protocol family "+protocol, nil)
	}
}

// CanConnect reports whether this build can connect a node of
// the given protocol family: the family must resolve to an
// engine, and that engine must not be an unavailable slot. (A
// wired desktop OpenVPN engine still surfaces its own honest
// failure at connect time when the binary is missing —
// CanConnect is about build wiring, not machine state.)
func (d *DispatchEngine) CanConnect(protocol string) bool {
	eng, err := d.EngineFor(protocol)
	if err != nil {
		return false
	}
	if ca, ok := eng.(interface{ ConnectAvailable() bool }); ok {
		return ca.ConnectAvailable()
	}
	return true
}

func (d *DispatchEngine) Capabilities() kernel.Capabilities {
	caps := d.Primary.Capabilities()
	if d.OpenVPN != nil {
		if oc := d.OpenVPN.Capabilities(); len(oc.Protocols) > 0 {
			if caps.Protocols == nil {
				caps.Protocols = map[kernel.Protocol]kernel.ProtocolSupport{}
			}
			for p, sup := range oc.Protocols {
				caps.Protocols[p] = sup
			}
		}
	}
	return caps
}

func (d *DispatchEngine) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	eng, err := d.EngineFor(n.Protocol)
	if err != nil {
		return err
	}
	return eng.ValidateSpec(ctx, n)
}

func (d *DispatchEngine) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	eng, err := d.EngineFor(n.Protocol)
	if err != nil {
		return err
	}
	if err := eng.StartNode(ctx, n, opts); err != nil {
		return err
	}
	d.mu.Lock()
	d.active = eng
	d.mu.Unlock()
	return nil
}

func (d *DispatchEngine) Stop(ctx context.Context) error {
	d.mu.Lock()
	active := d.active
	d.active = nil
	d.mu.Unlock()
	if active != nil {
		return active.Stop(ctx)
	}
	// Nothing tracked as running: stop both slots so a session
	// started before this engine existed (or after a failed
	// tracking update) cannot leak. Adapters treat Stop as
	// idempotent.
	var firstErr error
	if err := d.Primary.Stop(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if d.OpenVPN != nil {
		if err := d.OpenVPN.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (d *DispatchEngine) activeOrPrimary() Engine {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active != nil {
		return d.active
	}
	return d.Primary
}

func (d *DispatchEngine) Status() kernel.Status {
	return d.activeOrPrimary().Status()
}

func (d *DispatchEngine) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	eng, err := d.EngineFor(n.Protocol)
	if err != nil {
		return nil, err
	}
	return eng.TestHandshakeNode(ctx, n)
}

func (d *DispatchEngine) QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error) {
	return d.activeOrPrimary().QueryTraffic(ctx)
}

func (d *DispatchEngine) MixedAddr() string {
	return d.activeOrPrimary().MixedAddr()
}

// CanConnect implements the service-level support query for a
// protocol family on this service's engine wiring.
func (s *Service) CanConnect(protocol string) bool {
	if s.engine == nil {
		return false
	}
	if c, ok := s.engine.(interface{ CanConnect(string) bool }); ok {
		return c.CanConnect(protocol)
	}
	// A bare single engine is the pre-dispatch wiring (tests,
	// embeddings): the only production single engine is
	// sing-box, which serves its nine families but not OpenVPN.
	return protocol != specnode.ProtocolOpenVPN
}
