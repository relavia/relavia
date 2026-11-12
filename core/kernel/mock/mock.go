// Package mock provides an in-memory fake implementation of
// kernel.Adapter (proposal book Step 6). It performs no network I/O.
//
// Purposes:
//   - let the UI team develop in parallel against the adapter
//     interface before any real kernel adapter exists (Step 6
//     acceptance criterion);
//   - serve as the reference for the interface's semantics;
//   - scaffold later differential tests (book 6.2): the mock's
//     deterministic behavior is the baseline shape real adapters
//     are compared against.
//
// Behavior is deterministic given Options: handshake latency and
// failures are configured, traffic accrues at configured rates.
package mock

import (
	"context"
	"sync"
	"time"

	"openproxy/core/kernel"
)

// Options configures a Mock. The zero value is usable: default
// capabilities, no simulated latency, no failures, no traffic.
type Options struct {
	// Capabilities is the mock's self-reported capability set.
	// Zero value = DefaultCapabilities().
	Capabilities kernel.Capabilities

	// HandshakeLatency is the simulated handshake duration. The
	// mock waits this long (context permitting) and reports it as
	// the measured latency.
	HandshakeLatency time.Duration

	// FailNodeIDs marks node IDs whose handshakes always fail.
	FailNodeIDs map[string]bool
	// FailProtocols marks protocols whose handshakes always fail.
	FailProtocols map[kernel.Protocol]bool

	// HandshakeExit is returned as ExitInfo on successful
	// handshakes. Nil = no exit info reported.
	HandshakeExit *kernel.ExitInfo

	// StartError, when non-nil, makes every Start fail as if the
	// kernel hit an internal error: state becomes StateFailed and
	// the error is returned wrapped in KindInternal. For UI
	// failure-path development.
	StartError error

	// UploadRateBps / DownloadRateBps are the simulated traffic
	// accrual rates (bytes per second) while running.
	UploadRateBps   uint64
	DownloadRateBps uint64
}

// Mock is a fake kernel.Adapter. Safe for concurrent use.
type Mock struct {
	mu   sync.Mutex
	opts Options
	caps kernel.Capabilities

	state     kernel.State
	since     time.Time
	activeID  string
	mode      kernel.RunMode
	lastError *kernel.Error

	sessionStart time.Time
	accumUp      uint64 // traffic frozen from finished sessions
	accumDown    uint64
}

// New creates a Mock in StateIdle.
func New(opts Options) *Mock {
	caps := opts.Capabilities
	if caps.KernelID == "" {
		caps = DefaultCapabilities()
	}
	return &Mock{
		opts:  opts,
		caps:  caps,
		state: kernel.StateIdle,
		since: time.Now(),
	}
}

// DefaultCapabilities returns the mock's default self-report: the
// full first-tier matrix of proposal book 4.1 plus SoftEther, on a
// fully capable fictional platform. L2TP/SSTP are intentionally NOT
// reported (they are OS-orchestrated, book 4.1 second tier), so the
// UI can exercise its unsupported-combination greying against them.
func DefaultCapabilities() kernel.Capabilities {
	return kernel.Capabilities{
		KernelID:      "mock",
		KernelVersion: "0.1.0",
		Protocols: map[kernel.Protocol]kernel.ProtocolSupport{
			kernel.ProtocolShadowsocks: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityAEAD}, UDP: true},
			}},
			kernel.ProtocolTrojan: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportTCP: {Security: []kernel.SecurityType{kernel.SecurityTLS}},
				kernel.TransportWS:  {Security: []kernel.SecurityType{kernel.SecurityTLS}},
			}},
			kernel.ProtocolVMess: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportTCP:   {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}, UDP: true},
				kernel.TransportWS:    {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}},
				kernel.TransportHTTP2: {Security: []kernel.SecurityType{kernel.SecurityAEAD, kernel.SecurityTLS}},
			}},
			kernel.ProtocolVLESS: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportTCP:  {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS, kernel.SecurityReality, kernel.SecurityXTLSVision}, UDP: true},
				kernel.TransportWS:   {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
				kernel.TransportGRPC: {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
			}},
			kernel.ProtocolHysteria2: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportQUIC: {Security: []kernel.SecurityType{kernel.SecurityTLS}, UDP: true},
			}},
			kernel.ProtocolTUIC: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportQUIC: {Security: []kernel.SecurityType{kernel.SecurityTLS}, UDP: true},
			}},
			kernel.ProtocolWireGuard: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityNone}, UDP: true},
			}},
			kernel.ProtocolOpenVPN: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportTCP: {Security: []kernel.SecurityType{kernel.SecurityTLS}},
				kernel.TransportUDP: {Security: []kernel.SecurityType{kernel.SecurityTLS}},
			}},
			kernel.ProtocolSOCKS5: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityNone}},
			}},
			kernel.ProtocolHTTP: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityNone, kernel.SecurityTLS}},
			}},
			kernel.ProtocolSoftEther: {Transports: map[kernel.TransportType]kernel.TransportSupport{
				kernel.TransportNative: {Security: []kernel.SecurityType{kernel.SecurityTLS}},
			}},
		},
		Platform: kernel.PlatformCapabilities{
			Platform:              "mock",
			TUN:                   true,
			SystemProxy:           true,
			KillSwitch:            true,
			IPv6:                  true,
			RequiresVPNPermission: false,
		},
		Features: kernel.FeatureSet{
			HandshakeTest: true,
			TrafficStats:  true,
			UDP:           true,
		},
	}
}

// Capabilities implements kernel.Adapter.
func (m *Mock) Capabilities() kernel.Capabilities { return m.caps }

// ValidateConfig implements kernel.Adapter using the shared
// validation semantics of the kernel package.
func (m *Mock) ValidateConfig(_ context.Context, cfg *kernel.Config) error {
	return kernel.ValidateAgainst(cfg, m.caps)
}

// Start implements kernel.Adapter. Synchronous: on success the state
// is StateRunning when Start returns.
func (m *Mock) Start(_ context.Context, cfg *kernel.Config, opts kernel.PlatformOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.state {
	case kernel.StateRunning, kernel.StateStarting, kernel.StateStopping:
		return kernel.NewError(kernel.KindWrongState, "Start",
			"kernel already running or transitioning", nil)
	}
	if err := kernel.ValidateAgainst(cfg, m.caps); err != nil {
		return err // state unchanged
	}
	if opts.Mode == kernel.ModeTUN && !m.caps.Platform.TUN {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"TUN mode requested but not available on this platform", nil)
	}
	if opts.Mode == kernel.ModeSystemProxy && !m.caps.Platform.SystemProxy {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"system-proxy mode requested but not available on this platform", nil)
	}
	if opts.KillSwitch && !m.caps.Platform.KillSwitch {
		return kernel.NewError(kernel.KindPlatformUnavailable, "Start",
			"kill switch requested but not available on this platform", nil)
	}
	if m.opts.StartError != nil {
		m.setStateLocked(kernel.StateFailed)
		m.lastError = kernel.NewError(kernel.KindInternal, "Start",
			"simulated kernel start failure", m.opts.StartError)
		return m.lastError
	}

	m.setStateLocked(kernel.StateRunning)
	m.activeID = cfg.Node.ID
	m.mode = opts.Mode
	m.lastError = nil
	m.sessionStart = time.Now()
	return nil
}

// Stop implements kernel.Adapter. Idempotent.
func (m *Mock) Stop(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == kernel.StateRunning {
		m.freezeTrafficLocked()
	}
	switch m.state {
	case kernel.StateRunning, kernel.StateFailed:
		m.setStateLocked(kernel.StateStopped)
		m.activeID = ""
	}
	return nil
}

// Status implements kernel.Adapter.
func (m *Mock) Status() kernel.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return kernel.Status{
		State:        m.state,
		Since:        m.since,
		ActiveNodeID: m.activeID,
		Mode:         m.mode,
		LastError:    m.lastError,
	}
}

// TestHandshake implements kernel.Adapter. Failure configured via
// Options is reported in the result, not as a Go error.
func (m *Mock) TestHandshake(ctx context.Context, node *kernel.Node) (*kernel.HandshakeResult, error) {
	if err := kernel.ValidateNode(node); err != nil {
		return nil, err
	}
	if !m.caps.SupportsNode(node) {
		return nil, kernel.NewError(kernel.KindUnsupported, "TestHandshake",
			"combination not supported by this kernel", nil)
	}

	if m.opts.HandshakeLatency > 0 {
		timer := time.NewTimer(m.opts.HandshakeLatency)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	res := &kernel.HandshakeResult{
		NodeID:   node.ID,
		TestedAt: time.Now(),
	}
	if m.opts.FailNodeIDs[node.ID] || m.opts.FailProtocols[node.Protocol] {
		res.OK = false
		res.Error = kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake",
			"simulated handshake failure", nil)
		return res, nil
	}
	res.OK = true
	res.Latency = m.opts.HandshakeLatency
	res.Exit = m.opts.HandshakeExit
	return res, nil
}

// QueryTraffic implements kernel.Adapter. Traffic accrues at the
// configured rates while running and freezes when stopped.
func (m *Mock) QueryTraffic(_ context.Context) (*kernel.TrafficStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	up, down := m.accumUp, m.accumDown
	var started time.Time
	if !m.sessionStart.IsZero() {
		started = m.sessionStart
	}
	if m.state == kernel.StateRunning {
		elapsed := time.Since(m.sessionStart).Seconds()
		up += uint64(elapsed * float64(m.opts.UploadRateBps))
		down += uint64(elapsed * float64(m.opts.DownloadRateBps))
	}
	return &kernel.TrafficStats{
		UploadBytes:      up,
		DownloadBytes:    down,
		SampledAt:        time.Now(),
		SessionStartedAt: started,
	}, nil
}

func (m *Mock) setStateLocked(s kernel.State) {
	m.state = s
	m.since = time.Now()
}

func (m *Mock) freezeTrafficLocked() {
	elapsed := time.Since(m.sessionStart).Seconds()
	m.accumUp += uint64(elapsed * float64(m.opts.UploadRateBps))
	m.accumDown += uint64(elapsed * float64(m.opts.DownloadRateBps))
}
