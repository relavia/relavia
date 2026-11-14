package service

// Tests for the 2026-11-14 real-device fix batch: the
// cancellable one-tap chain, tiered probing, source-meta
// ranking inputs and kernel-log folding. Internal (package
// service) because several cases substitute the fast-check
// dialer / timeout fields, the same pattern as
// vpngate_internal_test.go.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// --- helpers -----------------------------------------------------------

func batchNode(id, server string) *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            id,
		Name:          id,
		Protocol:      specnode.ProtocolShadowsocks,
		Server:        server,
		Port:          8388,
		Source:        specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "user-provided"},
		Shadowsocks:   &specnode.CredShadowsocks{Method: "aes-256-gcm", Password: "pw"},
	}
}

func newBatchService(t *testing.T, eng Engine) *Service {
	t.Helper()
	store, err := OpenStore("") // in-memory
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return New(store, eng)
}

func addRanked(t *testing.T, svc *Service, id, server string, pingMs, score int64) {
	t.Helper()
	svc.store.AddNode(batchNode(id, server), nil)
	if pingMs > 0 || score > 0 {
		svc.store.SetSourceMeta(id, pingMs, score)
	}
}

// instantDialer succeeds immediately for every address.
func instantDialer(ctx context.Context, network, address string) (net.Conn, error) {
	c1, _ := net.Pipe()
	return c1, nil
}

// delayDialer succeeds after a per-address delay taken from
// the delays map (default: fail). Delays make the fast
// check's measured-latency ordering deterministic.
func delayDialer(delays map[string]time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		d, ok := delays[host]
		if !ok {
			return nil, errors.New("stub: unreachable")
		}
		select {
		case <-time.After(d):
			c1, _ := net.Pipe()
			return c1, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// scriptEngine succeeds or fails per node ID script.
type scriptEngine struct {
	mu      sync.Mutex
	starts  []string
	failErr map[string]error
	running *specnode.Node
}

func (e *scriptEngine) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{KernelID: "script", Platform: kernel.PlatformCapabilities{Platform: "test"}}
}
func (e *scriptEngine) ValidateSpec(_ context.Context, n *specnode.Node) error { return n.Validate() }
func (e *scriptEngine) StartNode(_ context.Context, n *specnode.Node, _ kernel.PlatformOptions) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.starts = append(e.starts, n.ID)
	if err := e.failErr[n.ID]; err != nil {
		return err
	}
	e.running = n
	return nil
}
func (e *scriptEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running = nil
	return nil
}
func (e *scriptEngine) Status() kernel.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running != nil {
		return kernel.Status{State: kernel.StateRunning, ActiveNodeID: e.running.ID}
	}
	return kernel.Status{State: kernel.StateIdle}
}
func (e *scriptEngine) TestHandshakeNode(_ context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return &kernel.HandshakeResult{NodeID: n.ID, TestedAt: time.Now(),
		Error: kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake", "script engine does not probe", nil)}, nil
}
func (e *scriptEngine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	return &kernel.TrafficStats{}, nil
}
func (e *scriptEngine) MixedAddr() string { return "" }
func (e *scriptEngine) startCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.starts)
}
func (e *scriptEngine) startedIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.starts...)
}

// blockEngine blocks inside StartNode until Stop releases it:
// the shape of an engine whose start does not unwind on
// context cancellation alone (the OpenVPN 3 consent-detached
// start), which is exactly what the chain watchdog and
// Disconnect exist to defeat.
type blockEngine struct {
	mu      sync.Mutex
	starts  int
	release chan struct{}
	entered chan struct{}
}

func newBlockEngine() *blockEngine {
	return &blockEngine{entered: make(chan struct{}, 32)}
}

func (e *blockEngine) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{KernelID: "block", Platform: kernel.PlatformCapabilities{Platform: "test"}}
}
func (e *blockEngine) ValidateSpec(_ context.Context, n *specnode.Node) error { return n.Validate() }
func (e *blockEngine) StartNode(_ context.Context, n *specnode.Node, _ kernel.PlatformOptions) error {
	e.mu.Lock()
	e.starts++
	ch := make(chan struct{})
	e.release = ch
	e.mu.Unlock()
	e.entered <- struct{}{}
	<-ch // deliberately ignores ctx: only Stop unwinds this
	return kernel.NewError(kernel.KindCanceled, "Start", "start stopped", nil)
}
func (e *blockEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.release != nil {
		close(e.release)
		e.release = nil
	}
	return nil
}
func (e *blockEngine) Status() kernel.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.release != nil {
		return kernel.Status{State: kernel.StateStarting}
	}
	return kernel.Status{State: kernel.StateIdle}
}
func (e *blockEngine) TestHandshakeNode(_ context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return &kernel.HandshakeResult{NodeID: n.ID, TestedAt: time.Now(),
		Error: kernel.NewError(kernel.KindHandshakeFailed, "TestHandshake", "block engine does not probe", nil)}, nil
}
func (e *blockEngine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	return &kernel.TrafficStats{}, nil
}
func (e *blockEngine) MixedAddr() string { return "" }
func (e *blockEngine) startCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.starts
}

// --- 1. chain cancellation ----------------------------------------------

// TestOneTapCancelStartsNoNewSessions is THE regression test
// for the device report "I turned it off and it kept
// reconnecting by itself": canceling mid-chain (via
// Disconnect, as the UI's button does) must unwind the
// in-flight start AND prevent every later session.
func TestOneTapCancelStartsNoNewSessions(t *testing.T) {
	eng := newBlockEngine()
	svc := newBatchService(t, eng)
	svc.tcpDial = instantDialer
	for i := 1; i <= 5; i++ {
		addRanked(t, svc, fmt.Sprintf("n%d", i), fmt.Sprintf("10.1.0.%d", i), int64(i*10), 100)
	}
	ctx, release := svc.BeginOp()
	defer release()
	done := make(chan error, 1)
	go func() {
		_, err := svc.OneTapConnect(ctx, AllGroups, nil)
		done <- err
	}()
	// Wait until the first session start is in flight.
	select {
	case <-eng.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("chain never started a session")
	}
	if err := svc.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("chain error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("chain did not stop after Disconnect")
	}
	// Give any rogue loop a chance to misbehave, then assert
	// the core promise: zero new sessions after the cancel.
	time.Sleep(300 * time.Millisecond)
	if got := eng.startCount(); got != 1 {
		t.Fatalf("engine starts after cancel = %d, want exactly 1", got)
	}
}

// TestBeginOpSupersedeAndCancel covers the registry itself: a
// new BeginOp cancels the previous op, CancelActiveOp cancels
// the current one, release unregisters without touching a
// successor.
func TestBeginOpSupersedeAndCancel(t *testing.T) {
	svc := newBatchService(t, nil)
	ctx1, release1 := svc.BeginOp()
	ctx2, release2 := svc.BeginOp()
	if ctx1.Err() == nil {
		t.Fatal("second BeginOp must cancel the first op")
	}
	if ctx2.Err() != nil {
		t.Fatal("second op must start live")
	}
	release1() // stale release: must not cancel op 2
	if ctx2.Err() != nil {
		t.Fatal("stale release canceled the successor op")
	}
	svc.CancelActiveOp()
	if ctx2.Err() == nil {
		t.Fatal("CancelActiveOp must cancel the registered op")
	}
	release2()
}

// --- 2. tiered probing + chain attempts ---------------------------------

// TestOneTapFirstSuccessStopsAndRecords: attempts follow the
// pre-check's measured latency, stop at the first success,
// and the successful connect is recorded as a real handshake
// (LastTest) — the evidence the next ranking runs on.
func TestOneTapFirstSuccessStopsAndRecords(t *testing.T) {
	timeoutErr := kernel.NewError(kernel.KindTimeout, "Start", "silence", nil)
	eng := &scriptEngine{failErr: map[string]error{"b": timeoutErr}}
	svc := newBatchService(t, eng)
	addRanked(t, svc, "a", "10.2.0.1", 30, 100)
	addRanked(t, svc, "b", "10.2.0.2", 10, 100)
	addRanked(t, svc, "c", "10.2.0.3", 20, 100)
	// Pre-check latencies: b fastest (attempted first, fails),
	// c next (succeeds), a slowest (must never be attempted).
	svc.tcpDial = delayDialer(map[string]time.Duration{
		"10.2.0.1": 30 * time.Millisecond,
		"10.2.0.2": 5 * time.Millisecond,
		"10.2.0.3": 15 * time.Millisecond,
	})
	node, err := svc.OneTapConnect(context.Background(), AllGroups, nil)
	if err != nil {
		t.Fatalf("OneTapConnect: %v", err)
	}
	if node == nil || node.ID != "c" {
		t.Fatalf("connected node = %v, want c", node)
	}
	if got := eng.startedIDs(); len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("attempts = %v, want [b c]", got)
	}
	rec, ok := svc.store.NodeByID("c")
	if !ok || rec.Node.LastTest == nil || !rec.Node.LastTest.OK || rec.Node.LastTest.LatencyMs == nil {
		t.Fatalf("successful connect not recorded as handshake: %+v", rec.Node.LastTest)
	}
}

// TestOneTapAllFailTaxonomy: every attempt timing out yields
// ErrNoNodeResponded with the attempt count capped at 5; a
// protocol-level failure (handshake refused) keeps its own
// classification instead.
func TestOneTapAllFailTaxonomy(t *testing.T) {
	timeoutErr := kernel.NewError(kernel.KindTimeout, "Start", "silence", nil)
	failAll := map[string]error{}
	eng := &scriptEngine{failErr: failAll}
	svc := newBatchService(t, eng)
	svc.tcpDial = instantDialer
	for i := 1; i <= 8; i++ {
		id := fmt.Sprintf("t%d", i)
		addRanked(t, svc, id, fmt.Sprintf("10.3.0.%d", i), int64(i*10), 100)
		failAll[id] = timeoutErr
	}
	if _, err := svc.OneTapConnect(context.Background(), AllGroups, nil); !errors.Is(err, ErrNoNodeResponded) {
		t.Fatalf("all-timeout chain error = %v, want ErrNoNodeResponded", err)
	}
	if got := eng.startCount(); got != oneTapMaxAttempts {
		t.Fatalf("attempts = %d, want the cap %d", got, oneTapMaxAttempts)
	}

	authErr := kernel.NewError(kernel.KindHandshakeFailed, "Start", "auth refused", nil)
	eng2 := &scriptEngine{failErr: map[string]error{"x": authErr, "y": authErr}}
	svc2 := newBatchService(t, eng2)
	svc2.tcpDial = instantDialer
	addRanked(t, svc2, "x", "10.3.1.1", 10, 100)
	addRanked(t, svc2, "y", "10.3.1.2", 20, 100)
	_, err := svc2.OneTapConnect(context.Background(), AllGroups, nil)
	if errors.Is(err, ErrNoNodeResponded) {
		t.Fatal("handshake-refused failures must not collapse into no-response")
	}
	if kernel.KindOf(err) != kernel.KindHandshakeFailed {
		t.Fatalf("chain error kind = %v, want handshake_failed (err %v)", kernel.KindOf(err), err)
	}
}

// TestOneTapPrecheckedDeadNotRetried: a candidate that just
// failed its fast pre-check is excluded from this chain's
// attempts even though the engine would have connected it.
func TestOneTapPrecheckedDeadNotRetried(t *testing.T) {
	eng := &scriptEngine{}
	svc := newBatchService(t, eng)
	addRanked(t, svc, "dead", "10.4.0.1", 5, 999) // best list figures
	addRanked(t, svc, "live", "10.4.0.2", 50, 100)
	svc.tcpDial = delayDialer(map[string]time.Duration{
		"10.4.0.2": 5 * time.Millisecond, // 10.4.0.1 absent: unreachable
	})
	node, err := svc.OneTapConnect(context.Background(), AllGroups, nil)
	if err != nil {
		t.Fatalf("OneTapConnect: %v", err)
	}
	if node.ID != "live" {
		t.Fatalf("connected = %s, want live", node.ID)
	}
	for _, id := range eng.startedIDs() {
		if id == "dead" {
			t.Fatal("pre-check-failed candidate was retried inside the same chain")
		}
	}
}

// TestOneTapNoNodes: an empty group is a selection problem,
// not a no-response one.
func TestOneTapNoNodes(t *testing.T) {
	svc := newBatchService(t, &scriptEngine{})
	if _, err := svc.OneTapConnect(context.Background(), AllGroups, nil); !errors.Is(err, ErrNoNodeSelected) {
		t.Fatalf("empty chain error = %v, want ErrNoNodeSelected", err)
	}
}

// TestRankOneTapCandidates pins the ranking tiers: measured
// handshakes (latency order, weak demoted) > source-reported
// ping/score > the rest in display order.
func TestRankOneTapCandidates(t *testing.T) {
	mk := func(id string, ping, score int64, ltMs *float64, method string) NodeRecord {
		n := batchNode(id, "10.5.0.1")
		if method != "" {
			n.Shadowsocks.Method = method
		}
		if ltMs != nil {
			n.LastTest = &specnode.LastTest{At: "2026-11-14T00:00:00Z", OK: true, LatencyMs: ltMs}
		}
		return NodeRecord{Node: n, SourcePingMs: ping, SourceScore: score}
	}
	f := func(v float64) *float64 { return &v }
	recs := []NodeRecord{
		mk("plain", 0, 0, nil, ""),                // tier 2
		mk("pingSlow", 90, 9999, nil, ""),         // tier 1, slower ping
		mk("testedSlow", 0, 0, f(300), ""),        // tier 0
		mk("pingFastLowScore", 20, 10, nil, ""),   // tier 1
		mk("testedFast", 0, 0, f(80), ""),         // tier 0, first
		mk("pingFastHighScore", 20, 500, nil, ""), // tier 1, score wins the ping tie
		mk("testedWeak", 0, 0, f(10), "rc4-md5"),  // tier 0 but weak: demoted within tier
	}
	got := rankOneTapCandidates(recs, ProtocolPrefAuto)
	want := []string{"testedFast", "testedSlow", "testedWeak", "pingFastHighScore", "pingFastLowScore", "pingSlow", "plain"}
	if len(got) != len(want) {
		t.Fatalf("ranked %d nodes, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].Node.ID != id {
			t.Fatalf("rank[%d] = %s, want %s (full order %v)", i, got[i].Node.ID, id, got)
		}
	}
}

// TestRankOneTapTier0Preference: inside tier 0 the settings
// protocol preference keeps its auto-select semantics — in
// the same latency bucket the preferred class wins; under
// "auto" plain latency decides.
func TestRankOneTapTier0Preference(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	trojan := batchNode("trojan", "10.5.1.1")
	trojan.Protocol = specnode.ProtocolTrojan
	trojan.Shadowsocks = nil
	trojan.Trojan = &specnode.CredTrojan{Password: "pw"}
	trojan.LastTest = &specnode.LastTest{At: "2026-11-14T00:00:00Z", OK: true, LatencyMs: f(100)}
	wg := batchNode("wg", "10.5.1.2")
	wg.Protocol = specnode.ProtocolWireGuard
	wg.Shadowsocks = nil
	wg.WireGuard = &specnode.CredWireGuard{PrivateKey: "k", PeerPublicKey: "p", Addresses: []string{"10.0.0.2/32"}}
	wg.LastTest = &specnode.LastTest{At: "2026-11-14T00:00:00Z", OK: true, LatencyMs: f(105)}
	recs := []NodeRecord{{Node: trojan}, {Node: wg}}
	if got := rankOneTapCandidates(recs, ProtocolPrefAuto); got[0].Node.ID != "trojan" {
		t.Fatalf("auto pref rank[0] = %s, want trojan (plain latency)", got[0].Node.ID)
	}
	if got := rankOneTapCandidates(recs, ProtocolPrefSpeed); got[0].Node.ID != "wg" {
		t.Fatalf("speed pref rank[0] = %s, want wg (fast class wins the bucket)", got[0].Node.ID)
	}
	if got := rankOneTapCandidates(recs, ProtocolPrefCompat); got[0].Node.ID != "trojan" {
		t.Fatalf("compat pref rank[0] = %s, want trojan (traditional class wins the bucket)", got[0].Node.ID)
	}
}

// --- 2b. fast checks ------------------------------------------------------

// TestCheckGroupFastBoundedAndProgressive: a 24-node sweep
// with 200 ms dials must finish far below the sequential
// bound (concurrency), record every result on the views, and
// report progress per node.
func TestCheckGroupFastBoundedAndProgressive(t *testing.T) {
	svc := newBatchService(t, &scriptEngine{})
	delays := map[string]time.Duration{}
	for i := 1; i <= 24; i++ {
		ip := fmt.Sprintf("10.6.0.%d", i)
		addRanked(t, svc, fmt.Sprintf("g%d", i), ip, 0, 0)
		if i%2 == 0 {
			delays[ip] = 200 * time.Millisecond
		}
	}
	svc.tcpDial = delayDialer(delays)
	progress := 0
	start := time.Now()
	checked, responded := svc.CheckGroupFast(context.Background(), AllGroups, func() { progress++ })
	elapsed := time.Since(start)
	if checked != 24 || responded != 12 {
		t.Fatalf("checked/responded = %d/%d, want 24/12", checked, responded)
	}
	if progress != 24 {
		t.Fatalf("progress callbacks = %d, want 24 (results land per node)", progress)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("group check took %v; sequential would be ~4.8s — concurrency missing?", elapsed)
	}
	views := svc.Nodes(AllGroups)
	seen := 0
	for _, v := range views {
		if v.Reach == nil {
			t.Fatalf("node %s has no recorded reach result", v.Record.Node.ID)
		}
		seen++
	}
	if seen != 24 {
		t.Fatalf("views with reach results = %d, want 24", seen)
	}
}

// TestCheckNodeFastUnprobableStaysUnknown: a UDP-native node
// cannot be TCP-probed; the honest outcome is "not checked",
// never "no response".
func TestCheckNodeFastUnprobableStaysUnknown(t *testing.T) {
	svc := newBatchService(t, &scriptEngine{})
	wg := batchNode("wg", "10.7.0.1")
	wg.Protocol = specnode.ProtocolWireGuard
	wg.Shadowsocks = nil
	wg.WireGuard = &specnode.CredWireGuard{PrivateKey: "k", PeerPublicKey: "p", Addresses: []string{"10.0.0.2/32"}}
	svc.store.AddNode(wg, nil)
	res, err := svc.CheckNodeFast(context.Background(), "wg")
	if err != nil {
		t.Fatalf("CheckNodeFast: %v", err)
	}
	if res.Checked || res.Reachable {
		t.Fatalf("UDP node fast check = %+v, want unchecked/unknown", res)
	}
	if got := svc.reachResult("wg"); got != nil {
		t.Fatalf("unprobable node recorded a reach result: %+v", got)
	}
}

// TestCheckNodeFastRecordsNoResponse: a failed dial is a
// recorded result with its reason, not an error return.
func TestCheckNodeFastRecordsNoResponse(t *testing.T) {
	svc := newBatchService(t, &scriptEngine{})
	svc.tcpDial = delayDialer(map[string]time.Duration{})
	addRanked(t, svc, "down", "10.8.0.1", 0, 0)
	res, err := svc.CheckNodeFast(context.Background(), "down")
	if err != nil {
		t.Fatalf("CheckNodeFast: %v", err)
	}
	if !res.Checked || res.Reachable || res.Err == "" {
		t.Fatalf("no-response result = %+v, want checked + unreachable + reason", res)
	}
	if got := svc.reachResult("down"); got == nil || got.Reachable {
		t.Fatalf("stored reach = %+v, want unreachable record", got)
	}
}

// --- 2c. source meta ------------------------------------------------------

// TestRefreshStampsSourceMeta runs the real pool refresh
// (the internal harness's sample CSV) and asserts the list's
// own Ping/Score figures land on the stored records — the
// ranking inputs the service used to drop.
func TestRefreshStampsSourceMeta(t *testing.T) {
	srv := serveSample(t)
	defer srv.Close()
	svc, _ := newPoolService(t, srv.URL, &scriptEngine{})
	ctx := context.Background()
	if err := svc.AcknowledgeVPNGateRisk(); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableVPNGate(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshVPNGate(ctx, true); err != nil {
		t.Fatal(err)
	}
	// public-vpn-192 / 219.100.37.209 in the frozen sample:
	// Score 2940710, Ping 18.
	var found *NodeView
	for _, v := range svc.Nodes(AllGroups) {
		vv := v
		if vv.Record.Node.Server == "219.100.37.209" {
			found = &vv
		}
		if vv.SourcePingMs <= 0 && vv.SourceScore <= 0 {
			t.Fatalf("pool node %s carries no source figures", vv.Record.Node.Name)
		}
	}
	if found == nil {
		t.Fatal("sample node 219.100.37.209 missing after refresh")
	}
	if found.SourcePingMs != 18 || found.SourceScore != 2940710 {
		t.Fatalf("source figures = ping %d score %d, want 18 / 2940710", found.SourcePingMs, found.SourceScore)
	}
}

// --- 4. log folding -------------------------------------------------------

// TestLogFoldAlternatingRepeats is the device case: the
// OpenVPN core alternates "Contacting …" / "Server poll
// timeout …" while it retries — the log must show each once
// with a counter, not dozens of copies.
func TestLogFoldAlternatingRepeats(t *testing.T) {
	svc := newBatchService(t, nil)
	for i := 0; i < 3; i++ {
		svc.OnKernelLog("info", "Contacting 203.0.113.7:443 via TCP")
		svc.OnKernelLog("info", "Server poll timeout, trying next remote entry...")
	}
	lines := svc.Logs().Lines()
	if len(lines) != 2 {
		t.Fatalf("folded log lines = %d, want 2: %v", len(lines), lines)
	}
	for _, want := range []string{"Contacting 203.0.113.7:443", "Server poll timeout"} {
		ok := false
		for _, l := range lines {
			if strings.Contains(l, want) && strings.Contains(l, "(×3)") {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("no folded (×3) line for %q: %v", want, lines)
		}
	}
}

// TestLogFoldKeepsFailuresVerbatim: folding applies to the
// core's [info] chatter only — repeated failures land one
// line each, with their reasons intact.
func TestLogFoldKeepsFailuresVerbatim(t *testing.T) {
	svc := newBatchService(t, nil)
	for i := 0; i < 3; i++ {
		svc.OnKernelLog("error", "AUTH_FAILED: credentials rejected")
	}
	lines := svc.Logs().Lines()
	if len(lines) != 3 {
		t.Fatalf("failure lines = %d, want 3 verbatim: %v", len(lines), lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "(×") {
			t.Fatalf("failure line was folded: %q", l)
		}
	}
	// And a burst of identical info lines folds consecutively too.
	svc.Logs().Clear()
	for i := 0; i < 5; i++ {
		svc.OnKernelLog("info", "same chatter")
	}
	if lines := svc.Logs().Lines(); len(lines) != 1 || !strings.Contains(lines[0], "(×5)") {
		t.Fatalf("consecutive fold = %v, want one line with (×5)", lines)
	}
}
