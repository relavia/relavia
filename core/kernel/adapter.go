// Package kernel defines the kernel adapter interface described in
// section 5.3 of the project proposal book (docs/项目方案书-v0.1.md).
//
// The adapter layer is the ONLY contract between the application service
// layer / UI and any concrete proxy kernel. Implementations may wrap an
// existing open-source kernel or the project's own gradually developed
// kernel modules (proposal book chapter 6); callers must never depend on
// a concrete kernel's types. This package therefore imports nothing from
// any concrete kernel.
//
// Status of this package: Step 6 deliverable, PENDING REVIEW. The
// interface is not frozen until the Step 6 review passes.
package kernel

import "context"

// Adapter is the kernel adapter interface. It is the engineering
// expansion of the minimal set in proposal book 5.3:
//
//	ValidateConfig(model) -> errors
//	Start(model, platformOptions) / Stop() / Status()
//	TestHandshake(node) -> latency, error
//	QueryTraffic() -> up, down
//	Capabilities() -> protocolMatrix
//
// Expansions relative to 5.3 (each documented in core/README.md):
//   - every blocking method takes a context.Context;
//   - errors are structured (see errors.go) instead of a bare error list;
//   - results are structured values (HandshakeResult, TrafficStats,
//     Status, Capabilities) instead of scalar tuples.
type Adapter interface {
	// Capabilities reports what this kernel can do: the protocol x
	// transport x security support matrix (proposal book 4.1) and the
	// platform capabilities of the current environment (5.4). It never
	// fails and must be cheap to call; the UI uses it to grey out
	// unsupported combinations instead of failing silently (5.3).
	Capabilities() Capabilities

	// ValidateConfig statically validates a configuration before it is
	// handed to Start. It performs structural validation (see
	// ValidateNode) plus a support check against Capabilities.
	// A nil return means the configuration is structurally valid AND
	// supported by this adapter. Failures are returned as *Error with
	// Kind KindInvalidConfig or KindUnsupported.
	ValidateConfig(ctx context.Context, cfg *Config) error

	// Start brings the kernel up with the given configuration and
	// platform options. It validates the configuration first (same
	// semantics as ValidateConfig). Start on an adapter whose state is
	// not StateIdle or StateStopped returns KindWrongState. On success
	// the state is StateRunning when Start returns.
	Start(ctx context.Context, cfg *Config, opts PlatformOptions) error

	// Stop tears the kernel down. Stop is idempotent: calling it while
	// StateIdle or StateStopped is a no-op returning nil. After a
	// successful Stop the state is StateStopped and the adapter may be
	// started again.
	Stop(ctx context.Context) error

	// Status returns a snapshot of the adapter lifecycle state. It
	// never blocks and never fails.
	Status() Status

	// TestHandshake performs a REAL protocol handshake against the
	// node and reports the measured latency. Implementations must not
	// substitute an ICMP ping for a protocol handshake (proposal book
	// 5.3 and 15: "no ping masquerading").
	//
	// A failed handshake is a result, not a Go error: the returned
	// HandshakeResult has OK=false and Error set (Kind
	// KindHandshakeFailed). The Go error return is reserved for
	// problems that prevent the test itself: structurally invalid
	// node, unsupported combination, or context cancellation.
	TestHandshake(ctx context.Context, node *Node) (*HandshakeResult, error)

	// QueryTraffic returns cumulative traffic counters for the current
	// (or most recent) session. While the kernel is not running it
	// returns the counters of the last session, or zero values if the
	// kernel never ran; it does not return an error for that case.
	QueryTraffic(ctx context.Context) (*TrafficStats, error)
}
