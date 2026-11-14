// Package service is the platform-independent application
// service layer of the client (proposal book 5.1): node/group
// management, import, handshake scheduling, connection control
// and traffic/log visibility, sitting between the UI and the
// kernel adapter. Step 10 (Android) reuses this layer unchanged;
// only the engine binding and the platform package differ.
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/plugins/vpngate"
)

// Sentinel service-level errors. The UI maps these (and kernel
// error kinds via kernel.KindOf) to localized strings; service
// code never produces display text.
var (
	ErrNoNodeSelected = errors.New("service: no node selected")
	ErrNoTestedNode   = errors.New("service: no successfully tested node available")
	ErrNoEngine       = errors.New("service: no kernel engine configured")
	// ErrNoNodeResponded reports a one-tap chain that tried
	// its bounded candidate set and every attempt failed in
	// the no-response class (timeout / silence from the
	// server). The UI maps it to its own localized line; the
	// per-attempt real reasons are in the log.
	ErrNoNodeResponded = errors.New("service: no candidate node responded")
)

// NodeView is one node as the UI presents it: the record plus its
// recomputed risk classification.
type NodeView struct {
	Record   NodeRecord
	Weak     bool
	Insecure bool
	VPNGate  bool // from the VPN Gate public pool
	// Admission is the recorded source admission level
	// ("tcp-connect" / "handshake-verified" / "none"); empty
	// for user-imported nodes.
	Admission string
	// Favorite mirrors NodeRecord.Favorite (the user's star).
	Favorite bool
	// SourcePingMs / SourceScore mirror the record's
	// source-reported list figures (ranking inputs for the
	// one-tap chain; never displayed as measured latency).
	SourcePingMs int64
	SourceScore  int64
	// Reach is the node's latest fast TCP reachability check
	// result from this process (nil when never fast-checked).
	// It is a latency/reachability signal only — never a
	// handshake claim (see fastcheck.go).
	Reach *ReachResult
}

// LogBuffer is a bounded in-memory ring of diagnostic log lines
// (kernel output plus service events). Local only, never leaves
// the device (book 8.1).
type LogBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	// foldSlots tracks the most recent foldable lines (see
	// AddFold) by their distance from the end of lines, so a
	// repeat can bump the counter on its first occurrence
	// instead of appending another copy.
	foldSlots []foldSlot
}

// foldSlot is one foldable line's bookkeeping: the line's key,
// its first-occurrence rendering (the repeat counter suffix is
// applied on top of it), how far it currently sits from the
// end of the buffer, and how many times it has occurred.
type foldSlot struct {
	key     string
	base    string
	fromEnd int
	count   int
}

// maxFoldSlots bounds how many distinct foldable lines are
// tracked at once (the kernel's retry chatter cycles through
// two or three messages; four leaves headroom).
const maxFoldSlots = 4

// maxFoldDistance forgets a foldable line once this many newer
// lines separate it from the end: a repeat after that is a new
// episode, not the same retry loop, and earns its own line.
const maxFoldDistance = 64

// NewLogBuffer creates a buffer holding at most max lines.
func NewLogBuffer(max int) *LogBuffer {
	if max <= 0 {
		max = 500
	}
	return &LogBuffer{max: max}
}

// appendLocked appends one line and applies the size bound.
// Caller holds mu.
func (b *LogBuffer) appendLocked(line string) {
	b.lines = append(b.lines, line)
	if len(b.lines) > b.max {
		b.lines = append([]string{}, b.lines[len(b.lines)-b.max:]...)
	}
}

// shiftSlotsLocked ages every fold slot by one appended line
// and forgets slots that fell out of the fold window or whose
// line was trimmed away. Caller holds mu.
func (b *LogBuffer) shiftSlotsLocked() {
	kept := b.foldSlots[:0]
	for _, s := range b.foldSlots {
		s.fromEnd++
		if s.fromEnd <= maxFoldDistance && s.fromEnd < len(b.lines) {
			kept = append(kept, s)
		}
	}
	b.foldSlots = kept
}

// Add appends one line (timestamped by the caller-facing format).
func (b *LogBuffer) Add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.appendLocked(line)
	b.shiftSlotsLocked()
}

// AddFold appends a foldable line: when the same key was seen
// recently — consecutively OR alternating with other foldable
// lines, the shape of the OpenVPN core's poll-retry chatter —
// the repeat only bumps a "(×N)" counter on the first
// occurrence instead of flooding the buffer with copies. Only
// high-volume informational chatter goes through here (the
// service routes kernel [info] lines); failures always use
// Add and land verbatim, one line each.
func (b *LogBuffer) AddFold(key, line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.foldSlots {
		if b.foldSlots[i].key != key {
			continue
		}
		s := &b.foldSlots[i]
		idx := len(b.lines) - 1 - s.fromEnd
		if idx < 0 || idx >= len(b.lines) {
			break // slot outlived its line; fall through to append
		}
		s.count++
		b.lines[idx] = fmt.Sprintf("%s (×%d)", s.base, s.count)
		return
	}
	b.appendLocked(line)
	b.shiftSlotsLocked()
	b.foldSlots = append(b.foldSlots, foldSlot{key: key, base: line, count: 1})
	if len(b.foldSlots) > maxFoldSlots {
		b.foldSlots = append([]foldSlot{}, b.foldSlots[len(b.foldSlots)-maxFoldSlots:]...)
	}
}

// Lines returns a copy of the buffered lines, oldest first.
func (b *LogBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.lines...)
}

// Clear empties the buffer (book 8.1: one-click clear).
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = nil
	b.foldSlots = nil
}

// Service wires the store, the kernel engine and the log buffer.
type Service struct {
	store      *Store
	engine     Engine
	logs       *LogBuffer
	httpClient *http.Client

	mu sync.Mutex // serializes engine lifecycle operations

	// lastAuto remembers the most recent auto-select outcome
	// for the settings fallback line (see AutoSelectAndConnect).
	// Guarded by mu.
	lastAuto autoSelectOutcome

	// The cancellable-operation registry (BeginOp /
	// CancelActiveOp): the UI registers its long-running
	// chains (one-tap connect, check-all, manual connect) so
	// Disconnect can stop EVERYTHING — the chain context and
	// with it every loop that could start another session —
	// not just the session that happens to be in flight. This
	// is the fix for the 2026-11-14 "turned it off and it
	// kept reconnecting itself" report: previously Disconnect
	// stopped only the current probe session and the chain
	// immediately started the next one.
	opMu     sync.Mutex
	opCancel context.CancelFunc
	opGen    uint64

	// Fast-check state (fastcheck.go): in-memory reachability
	// results of this process, plus the dialer and per-node
	// timeout the checks run with (fields so tests can
	// substitute deterministic dialers, like vgProber below).
	reachMu          sync.Mutex
	reach            map[string]*ReachResult
	tcpDial          func(ctx context.Context, network, address string) (net.Conn, error)
	fastCheckTimeout time.Duration

	// VPN Gate pool source (vpngate.go). vgProber is the TCP
	// admission prober used at refresh; nil means the plugin's
	// default prober. It is a field (not a local) so tests can
	// substitute a deterministic dialer.
	vgMu     sync.Mutex
	vg       *vpngate.Plugin
	vgProber *vpngate.Prober
}

// New builds a Service. engine may be nil (UI can still manage
// nodes; connection operations then return ErrNoEngine).
func New(store *Store, engine Engine) *Service {
	return &Service{
		store:      store,
		engine:     engine,
		logs:       NewLogBuffer(500),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		reach:      map[string]*ReachResult{},
	}
}

// Store exposes the underlying store (settings persistence).
func (s *Service) Store() *Store { return s.store }

// Logs returns the log buffer.
func (s *Service) Logs() *LogBuffer { return s.logs }

// OnKernelLog is the sink to hand to the engine (kernel log lines
// for the local log view).
func (s *Service) OnKernelLog(level, message string) {
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("15:04:05"), level, message)
	if level == "info" {
		// Kernel [info] chatter repeats the same lines while
		// a session retries (the OpenVPN core's poll-timeout
		// loop filled the device's whole log page in the
		// 2026-11-14 test): fold repeats into a counter on
		// the first occurrence. Every other level — warnings
		// and every failure — lands verbatim, one line each,
		// with its real reason.
		s.logs.AddFold("kernel|"+message, line)
		return
	}
	s.logs.Add(line)
}

// BeginOp registers a new cancellable operation (a one-tap
// chain, a group check, a manual connect) and returns its
// context. Registering supersedes any operation still
// registered: the previous one's context is canceled, because
// a new user action replaces the old chain, never runs beside
// it. The returned release function unregisters (and cancels)
// this operation when it ends; callers defer it.
func (s *Service) BeginOp() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	s.opMu.Lock()
	s.opGen++
	gen := s.opGen
	prev := s.opCancel
	s.opCancel = cancel
	s.opMu.Unlock()
	if prev != nil {
		prev()
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			s.opMu.Lock()
			if s.opGen == gen {
				s.opCancel = nil
			}
			s.opMu.Unlock()
			cancel()
		})
	}
	return ctx, release
}

// CancelActiveOp cancels the registered operation's context,
// if any. It is the chain half of Disconnect's "stop
// everything" semantics: canceling the context stops the
// chain's probe/attempt loops from starting any further
// session; the engine stop that follows ends the session in
// flight.
func (s *Service) CancelActiveOp() {
	s.opMu.Lock()
	c := s.opCancel
	s.opCancel = nil
	s.opGen++
	s.opMu.Unlock()
	if c != nil {
		c()
	}
}

func (s *Service) logf(format string, args ...any) {
	s.logs.Add(fmt.Sprintf("%s [service] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...)))
}

// --- node/group views -------------------------------------------------

// Groups returns group display names.
func (s *Service) Groups() []string { return s.store.GroupNames() }

// Nodes returns the records of one group ("" = ungrouped,
// AllGroups = every node) in display order, as UI views.
func (s *Service) Nodes(group string) []NodeView {
	doc := s.store.Snapshot()
	var out []NodeView
	for _, rec := range doc.Nodes {
		if group != AllGroups && rec.Node.Group != group {
			continue
		}
		out = append(out, s.nodeView(rec))
	}
	return out
}

// nodeView assembles the UI view of one record, including the
// session-local fast-check result when one exists.
func (s *Service) nodeView(rec NodeRecord) NodeView {
	return NodeView{
		Record:       rec,
		Weak:         WeakEncryption(rec.Node),
		Insecure:     InsecureSkipVerify(rec.Node),
		VPNGate:      IsVPNGateNode(rec.Node),
		Admission:    rec.Admission,
		Favorite:     rec.Favorite,
		SourcePingMs: rec.SourcePingMs,
		SourceScore:  rec.SourceScore,
		Reach:        s.reachResult(rec.Node.ID),
	}
}

// AllGroups is the pseudo-group key selecting every node.
const AllGroups = "\x00all"

// NodeByID returns one view by ID.
func (s *Service) NodeByID(id string) (NodeView, bool) {
	rec, ok := s.store.NodeByID(id)
	if !ok {
		return NodeView{}, false
	}
	return s.nodeView(rec), true
}

// SetNodeFavorite stars or unstars a node and persists the
// change immediately (the star must survive a restart).
func (s *Service) SetNodeFavorite(id string, fav bool) {
	if s.store.SetFavorite(id, fav) {
		_ = s.store.Save()
	}
}

// LogFailure records a user-visible failure in the local log
// with its stage and real reason. It exists for failures that
// originate OUTSIDE the service (file reads in the UI,
// subscription fetches, platform refusals surfaced by shells):
// the error-chain rule is that any failure the UI shows must
// also be findable on the log page, so the UI calls this for
// every error it displays.
func (s *Service) LogFailure(stage string, err error) {
	if err == nil {
		return
	}
	s.logf("%s failed: %v", stage, err)
}

// ProtocolPref returns the persisted auto-select protocol
// preference, normalized to a known value.
func (s *Service) ProtocolPref() string {
	switch s.store.Settings().ProtocolPref {
	case ProtocolPrefSpeed:
		return ProtocolPrefSpeed
	case ProtocolPrefCompat:
		return ProtocolPrefCompat
	default:
		return ProtocolPrefAuto
	}
}

// SetProtocolPref persists the auto-select protocol preference.
func (s *Service) SetProtocolPref(pref string) {
	s.store.UpdateSettings(func(st *Settings) { st.ProtocolPref = pref })
	_ = s.store.Save()
}

// Background theme choices (Settings.Theme), v3 design: four
// user-selectable backgrounds, persisted like every other
// preference. The zero value is the light background existing
// users already have.
const (
	ThemeLight  = "light"
	ThemeNavy   = "navy"
	ThemeInk    = "ink"
	ThemeSystem = "system"
)

// Theme returns the persisted background choice, normalized to
// a known value (unknown or empty reads as light).
func (s *Service) Theme() string {
	switch s.store.Settings().Theme {
	case ThemeNavy:
		return ThemeNavy
	case ThemeInk:
		return ThemeInk
	case ThemeSystem:
		return ThemeSystem
	default:
		return ThemeLight
	}
}

// SetTheme persists the background choice.
func (s *Service) SetTheme(theme string) {
	s.store.UpdateSettings(func(st *Settings) { st.Theme = theme })
	_ = s.store.Save()
}

// LastConnectedNodeID returns the node of the most recent
// successful connection ("" when never connected), for the
// home hero's "reconnect the last node" state.
func (s *Service) LastConnectedNodeID() string {
	return s.store.Settings().LastConnectedNodeID
}

// RunModeOption is one selectable run mode with its live
// availability on this platform/build.
type RunModeOption struct {
	Mode      kernel.RunMode
	Available bool
	// Reason classifies an unavailable mode for the settings
	// copy (teardown §4.3: the reason shown must be the real
	// one): ModeReasonPlatform when the device/platform cannot
	// do it, ModeReasonVersion when this build does not ship
	// it. Empty when Available.
	Reason string
}

// Run-mode unavailability reason kinds (internal identifiers,
// never display text).
const (
	ModeReasonPlatform = "platform"
	ModeReasonVersion  = "version"
)

// RunModeOptions lists the run modes the settings page may
// offer, with availability taken from the primary engine's live
// capabilities — a mode the platform cannot honor is listed as
// unavailable (with the reason shown by the UI), never hidden
// and never offered as a dead switch:
//   - TUN: the platform layer reports a TUN device;
//   - system proxy: the platform layer can set the OS proxy;
//   - manual (local listener): a local mixed listener address
//     exists (the Android TUN engine exposes none — its only
//     mode is TUN).
func (s *Service) RunModeOptions() []RunModeOption {
	caps := s.Capabilities()
	opt := func(m kernel.RunMode, ok bool, reason string) RunModeOption {
		o := RunModeOption{Mode: m, Available: ok}
		if !ok {
			o.Reason = reason
		}
		return o
	}
	return []RunModeOption{
		// TUN and system proxy are platform capabilities: a
		// device without them can never offer the mode.
		opt(kernel.ModeTUN, caps.Platform.TUN, ModeReasonPlatform),
		// Manual mode exists only when the build's engine
		// exposes a local listener; the Android TUN build ships
		// none, which is a property of this version, not of the
		// device.
		opt(kernel.ModeManual, s.MixedAddr() != "", ModeReasonVersion),
		opt(kernel.ModeSystemProxy, caps.Platform.SystemProxy, ModeReasonPlatform),
	}
}

// DeleteNode removes a node (and persists).
func (s *Service) DeleteNode(id string) bool {
	ok := s.store.DeleteNode(id)
	if ok {
		_ = s.store.Save()
		s.logf("node deleted: %s", id)
	}
	return ok
}

// MoveNode reorders a node in display order (and persists).
func (s *Service) MoveNode(id string, dir int) bool {
	ok := s.store.MoveNode(id, dir)
	if ok {
		_ = s.store.Save()
	}
	return ok
}

// AddGroup registers a group (and persists).
func (s *Service) AddGroup(name string) {
	s.store.AddGroup(name)
	_ = s.store.Save()
}

// DeleteGroup removes a group, ungrouping its nodes (and persists).
func (s *Service) DeleteGroup(name string) {
	s.store.DeleteGroup(name)
	_ = s.store.Save()
}

// --- handshake tests ----------------------------------------------------

// TestNode runs a REAL protocol handshake (book 5.3: no ping
// substitution) against one node and records the outcome on it.
func (s *Service) TestNode(ctx context.Context, id string) (*kernel.HandshakeResult, error) {
	if s.engine == nil {
		return nil, ErrNoEngine
	}
	rec, ok := s.store.NodeByID(id)
	if !ok {
		return nil, ErrNoNodeSelected
	}
	res, err := s.engine.TestHandshakeNode(ctx, rec.Node)
	if err != nil {
		return nil, err
	}
	if res.OK {
		s.recordHandshakeSuccess(rec, res.TestedAt, res.Latency)
	} else {
		lt := &specnode.LastTest{At: res.TestedAt.UTC().Format(time.RFC3339), OK: false}
		if res.Error != nil {
			lt.Error = string(res.Error.Kind)
		}
		s.store.SetLastTest(id, lt)
	}
	_ = s.store.Save()
	return res, nil
}

// recordHandshakeSuccess stores a successful REAL handshake
// outcome on a node: the LastTest latency record (the ranking
// input of auto-select and the "picked for you" shortlist) and,
// for VPN Gate OpenVPN nodes, the handshake-verified admission
// upgrade — a real OpenVPN handshake through the app's dispatch
// is exactly the plugin's handshake-verified admission evidence
// (refreshes never downgrade it). Callers: TestNode (a probe
// session) and the one-tap chain (a connect IS a handshake;
// its measured duration is the honest latency).
func (s *Service) recordHandshakeSuccess(rec NodeRecord, at time.Time, latency time.Duration) {
	ms := float64(latency.Microseconds()) / 1000.0
	s.store.SetLastTest(rec.Node.ID, &specnode.LastTest{
		At:        at.UTC().Format(time.RFC3339),
		OK:        true,
		LatencyMs: &ms,
	})
	if IsVPNGateNode(rec.Node) && rec.Node.Protocol == specnode.ProtocolOpenVPN {
		s.store.SetAdmission(rec.Node.ID, vpngate.ProbeLevelHandshakeVerified)
	}
}

// TestGroup tests every node of a group sequentially (group ""
// tests the ungrouped nodes; AllGroups tests everything). Results
// are recorded per node; the returned slice aligns with the
// group's display order and carries a nil result where the test
// itself could not run.
func (s *Service) TestGroup(ctx context.Context, group string) ([]*kernel.HandshakeResult, error) {
	views := s.Nodes(group)
	results := make([]*kernel.HandshakeResult, len(views))
	for i, v := range views {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		res, err := s.TestNode(ctx, v.Record.Node.ID)
		if err != nil {
			s.logf("test %s: %v", v.Record.Node.ID, err)
			continue
		}
		results[i] = res
	}
	return results, nil
}

// --- connection control -------------------------------------------------

// Mode returns the configured kernel run mode (default manual).
func (s *Service) Mode() kernel.RunMode {
	m := s.store.Settings().Mode
	if m == "" {
		return kernel.ModeManual
	}
	return kernel.RunMode(m)
}

// SetMode persists the run mode. Note the honesty contract: the
// mode is a REQUEST. The engine refuses modes its platform layer
// cannot honor (the current in-process integration honors only
// manual), and Connect surfaces that refusal instead of silently
// running another mode.
func (s *Service) SetMode(mode kernel.RunMode) {
	s.store.UpdateSettings(func(st *Settings) { st.Mode = string(mode) })
	_ = s.store.Save()
}

// Connect starts the kernel with the chosen node. Kernel errors
// keep their structured kind (kernel.KindOf) for the UI to map to
// localized text.
func (s *Service) Connect(ctx context.Context, id string) error {
	if s.engine == nil {
		return ErrNoEngine
	}
	rec, ok := s.store.NodeByID(id)
	if !ok {
		return ErrNoNodeSelected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.engine.StartNode(ctx, rec.Node, kernel.PlatformOptions{Mode: s.Mode()}); err != nil {
		s.logf("connect %s failed: %v", id, err)
		return err
	}
	s.store.UpdateSettings(func(st *Settings) {
		st.SelectedNodeID = id
		st.LastConnectedNodeID = id
	})
	_ = s.store.Save()
	s.logf("connected: %s (%s)", rec.Node.Name, id)
	return nil
}

// AutoSelectAndConnect picks the group's best node by the
// AutoSelect rule (lowest latency, weak-encryption nodes
// deprioritized) and connects to it.
func (s *Service) AutoSelectAndConnect(ctx context.Context, group string) (*specnode.Node, error) {
	views := s.Nodes(group)
	recs := make([]NodeRecord, 0, len(views))
	for _, v := range views {
		recs = append(recs, v.Record)
	}
	n, fellBack := AutoSelectExplain(recs, s.ProtocolPref())
	if n == nil {
		s.logf("autoselect: no tested node available in group %q", group)
		return nil, ErrNoTestedNode
	}
	s.mu.Lock()
	s.lastAuto = autoSelectOutcome{nodeName: n.Name, fellBack: fellBack, ok: true}
	s.mu.Unlock()
	if err := s.Connect(ctx, n.ID); err != nil {
		return nil, err
	}
	return n, nil
}

// autoSelectOutcome is the remembered result of the most recent
// AutoSelectAndConnect, for the settings page's post-hoc
// fallback line (teardown §4.2: the fallback note appears AFTER
// an auto-select actually ran, never as a pre-emptive warning).
type autoSelectOutcome struct {
	nodeName string
	fellBack bool
	ok       bool
}

// LastAutoSelect reports the last auto-select outcome: the
// picked node's display name and whether the protocol
// preference fell back to plain latency. ok is false until the
// first auto-select of this process.
func (s *Service) LastAutoSelect() (nodeName string, fellBack bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuto.nodeName, s.lastAuto.fellBack, s.lastAuto.ok
}

// Disconnect stops EVERYTHING (2026-11-14 fix batch): first
// the registered operation chain is canceled, so its probe /
// attempt loops cannot start another session behind this
// call; then the engine itself is stopped, ending the session
// in flight. Before this change Disconnect stopped only the
// in-flight session and a running one-tap chain immediately
// started the next node — the device report "I turned it off
// and it kept reconnecting by itself". Engine Stop is
// idempotent at the adapter.
func (s *Service) Disconnect(ctx context.Context) error {
	s.CancelActiveOp()
	if s.engine == nil {
		return ErrNoEngine
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.engine.Stop(ctx)
	if err == nil {
		s.logf("disconnected")
	}
	return err
}

// Status returns the engine status snapshot (idle when no engine).
func (s *Service) Status() kernel.Status {
	if s.engine == nil {
		return kernel.Status{State: kernel.StateIdle}
	}
	return s.engine.Status()
}

// Traffic returns current traffic counters.
func (s *Service) Traffic(ctx context.Context) (*kernel.TrafficStats, error) {
	if s.engine == nil {
		return nil, ErrNoEngine
	}
	return s.engine.QueryTraffic(ctx)
}

// MixedAddr returns the local listener address while running.
func (s *Service) MixedAddr() string {
	if s.engine == nil {
		return ""
	}
	return s.engine.MixedAddr()
}

// Capabilities returns the engine's capability self-report (zero
// value when no engine), for the UI's honest capability display.
func (s *Service) Capabilities() kernel.Capabilities {
	if s.engine == nil {
		return kernel.Capabilities{}
	}
	return s.engine.Capabilities()
}

// SelectedNodeID returns the persisted selection.
func (s *Service) SelectedNodeID() string { return s.store.Settings().SelectedNodeID }

// SelectNode persists the UI selection.
func (s *Service) SelectNode(id string) {
	s.store.UpdateSettings(func(st *Settings) { st.SelectedNodeID = id })
	_ = s.store.Save()
}
