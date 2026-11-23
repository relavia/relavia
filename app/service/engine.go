package service

import (
	"context"
	"fmt"

	"openproxy/core/kernel"
	"openproxy/core/selfdev"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// Engine is the slice of the Step 7 kernel adapter the service
// layer consumes. It is an interface so the service can be tested
// against a fake engine with no kernel present (and so Step 10 can
// substitute a platform engine without touching service code).
//
// The production implementation is the composite adapter
// (selfdev.Adapter over the sing-box adapter) speaking the
// full-fidelity unified-model entry points (StartNode /
// ValidateSpec / TestHandshakeNode), NOT the placeholder-typed
// kernel.Adapter methods: configurations are compiled from the
// unified model, per the Step 7 docking decision.
type Engine interface {
	Capabilities() kernel.Capabilities
	ValidateSpec(ctx context.Context, n *specnode.Node) error
	StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error
	Stop(ctx context.Context) error
	Status() kernel.Status
	TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error)
	QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error)
	MixedAddr() string
}

// SingBoxEngine adapts *singbox.Adapter to Engine.
type SingBoxEngine struct {
	Adapter *singbox.Adapter
}

// NewSingBoxEngine builds the production engine. onLog receives
// kernel log lines for the client's local log view (book 8.1:
// connection log view, local only).
func NewSingBoxEngine(onLog func(level, message string)) *SingBoxEngine {
	return &SingBoxEngine{Adapter: singbox.New(singbox.Options{OnLog: onLog})}
}

func (e *SingBoxEngine) Capabilities() kernel.Capabilities { return e.Adapter.Capabilities() }

func (e *SingBoxEngine) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	return e.Adapter.ValidateSpec(ctx, n)
}

func (e *SingBoxEngine) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	return e.Adapter.StartNode(ctx, n, opts)
}

func (e *SingBoxEngine) Stop(ctx context.Context) error { return e.Adapter.Stop(ctx) }

func (e *SingBoxEngine) Status() kernel.Status { return e.Adapter.Status() }

func (e *SingBoxEngine) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return e.Adapter.TestHandshakeNode(ctx, n)
}

func (e *SingBoxEngine) QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error) {
	return e.Adapter.QueryTraffic(ctx)
}

func (e *SingBoxEngine) MixedAddr() string { return e.Adapter.MixedAddr() }

// --- Self-developed backend gear ----------------------------------

// Backend gear values (Settings.Backend), the service-level
// names of the composite adapter's policy gears
// (core/selfdev.Policy). The gear governs only protocols that
// have a self-developed implementation — today Shadowsocks —
// and only at connection-establishment decision points; it
// never switches a live connection.
const (
	// BackendSingbox: the standard engine serves everything.
	// The default.
	BackendSingbox = "singbox"
	// BackendAuto: the self-developed engine is tried first
	// for eligible nodes; a node whose self-developed
	// handshake fails is pinned to the standard engine until
	// its data changes or the pins are reset.
	BackendAuto = "auto"
	// BackendSelfdev: every eligible node uses the
	// self-developed engine. A testing gear, never the
	// default.
	BackendSelfdev = "selfdev"
)

// backendPolicyOf maps a gear name onto the composite
// adapter's policy; unknown names read as the default gear.
func backendPolicyOf(name string) selfdev.Policy {
	switch name {
	case BackendAuto:
		return selfdev.PolicyAuto
	case BackendSelfdev:
		return selfdev.PolicySelfdev
	default:
		return selfdev.PolicySingbox
	}
}

// backendPolicyEngine is implemented by engines whose backend
// gear can be switched at runtime (the composite engine, and
// the dispatch engine by forwarding to its primary slot).
type backendPolicyEngine interface {
	SetBackendPolicy(name string)
	BackendPolicy() string
}

// CompositeEngine adapts *selfdev.Adapter to Engine: the
// composite wraps the sing-box adapter and routes Shadowsocks
// work between the standard engine and the project's own
// engine under the backend gear, at decision points only. It
// is the production primary engine — the self-developed route
// (docs/自研协议路线-01-shadowsocks.md) reaches real traffic
// exclusively through this wiring.
type CompositeEngine struct {
	Adapter *selfdev.Adapter
	SingBox *singbox.Adapter
}

// NewCompositeEngine builds the production primary engine: a
// sing-box adapter constructed exactly as NewSingBoxEngine
// builds it, wrapped by the composite adapter. The initial
// gear is the default (BackendSingbox); Service.New applies
// the persisted gear on top.
func NewCompositeEngine(onLog func(level, message string)) *CompositeEngine {
	sb := singbox.New(singbox.Options{OnLog: onLog})
	ad := selfdev.New(sb, selfdev.Options{
		Logf: func(format string, args ...any) {
			if onLog != nil {
				onLog("info", fmt.Sprintf(format, args...))
			}
		},
	})
	return &CompositeEngine{Adapter: ad, SingBox: sb}
}

func (e *CompositeEngine) Capabilities() kernel.Capabilities { return e.Adapter.Capabilities() }

func (e *CompositeEngine) ValidateSpec(ctx context.Context, n *specnode.Node) error {
	return e.Adapter.ValidateSpec(ctx, n)
}

func (e *CompositeEngine) StartNode(ctx context.Context, n *specnode.Node, opts kernel.PlatformOptions) error {
	return e.Adapter.StartNode(ctx, n, opts)
}

func (e *CompositeEngine) Stop(ctx context.Context) error { return e.Adapter.Stop(ctx) }

func (e *CompositeEngine) Status() kernel.Status { return e.Adapter.Status() }

func (e *CompositeEngine) TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return e.Adapter.TestHandshakeNode(ctx, n)
}

func (e *CompositeEngine) QueryTraffic(ctx context.Context) (*kernel.TrafficStats, error) {
	return e.Adapter.QueryTraffic(ctx)
}

func (e *CompositeEngine) MixedAddr() string { return e.Adapter.MixedAddr() }

// SetBackendPolicy switches the backend gear at runtime; it
// takes effect at the next connection-establishment decision
// point and never touches a live session.
func (e *CompositeEngine) SetBackendPolicy(name string) {
	e.Adapter.SetPolicy(backendPolicyOf(name))
}

// BackendPolicy reports the current gear name.
func (e *CompositeEngine) BackendPolicy() string {
	return e.Adapter.Policy().String()
}
