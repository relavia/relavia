package service

import (
	"context"

	"openproxy/core/kernel"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// Engine is the slice of the Step 7 kernel adapter the service
// layer consumes. It is an interface so the service can be tested
// against a fake engine with no kernel present (and so Step 10 can
// substitute a platform engine without touching service code).
//
// The production implementation is the sing-box adapter's
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
