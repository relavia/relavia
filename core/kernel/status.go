package kernel

import "time"

// State is the adapter lifecycle state. Legal transitions:
//
//	idle ──Start──▶ starting ──ok──▶ running ──Stop──▶ stopping ──▶ stopped
//	                  │                                ▲
//	                  └──fail──▶ failed ────Stop───────┘
//	stopped ──Start──▶ starting   (restart is allowed)
//	failed  ──Start──▶ starting   (retry is allowed)
//
// Stop from idle or stopped is a no-op. Start from running, starting
// or stopping returns KindWrongState. Implementations that perform
// start/stop synchronously may pass through starting/stopping without
// those states ever being observed via Status.
type State string

const (
	StateIdle     State = "idle"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateStopped  State = "stopped"
	StateFailed   State = "failed"
)

// Status is a point-in-time snapshot returned by Adapter.Status.
type Status struct {
	State State
	// Since is when the current state was entered.
	Since time.Time
	// ActiveNodeID is the ID of the node the kernel is running with;
	// empty unless State is StateRunning (or StateStopping).
	ActiveNodeID string
	// Mode is the run mode of the current/last session, if any.
	Mode RunMode
	// LastError is the most recent failure that put the adapter into
	// StateFailed, or nil. Cleared on the next successful Start.
	LastError *Error
}

// TrafficStats are cumulative counters (book 5.3 QueryTraffic ->
// up, down), expanded with sampling metadata.
type TrafficStats struct {
	UploadBytes   uint64
	DownloadBytes uint64
	// SampledAt is when the counters were read.
	SampledAt time.Time
	// SessionStartedAt is when the current/last session started;
	// zero if the kernel never ran.
	SessionStartedAt time.Time
}

// ExitInfo describes the observed exit point of a connection.
// All fields are optional and best-effort; an adapter that cannot
// determine them leaves the pointer nil.
type ExitInfo struct {
	IP      string
	Country string // ISO 3166-1 alpha-2, e.g. "JP"
	ASN     string
}

// HandshakeResult is the outcome of Adapter.TestHandshake.
type HandshakeResult struct {
	NodeID string
	OK     bool
	// Latency is the measured handshake round-trip time; zero when
	// OK is false.
	Latency time.Duration
	// TestedAt is when the test ran.
	TestedAt time.Time
	// Error classifies a failed handshake. Nil iff OK.
	// A failed handshake is reported here, NOT via the Go error
	// return of TestHandshake (see adapter.go).
	Error *Error
	// Exit is optional exit-point information observed during the
	// handshake, when the adapter can determine it.
	Exit *ExitInfo
}
