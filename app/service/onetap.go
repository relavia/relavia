package service

import (
	"context"
	"math"
	"sort"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// The one-tap connect chain (2026-11-14 fix batch; diagnosis
// §6 items 1–2). The old chain ran a FULL handshake probe of
// every node (TestGroup) before auto-selecting: for the ~99
// node pool that is up to 45 s per dead node against a 5
// minute chain budget — structurally unable to finish, and
// every "check" the user saw was that same broken sweep.
//
// The chain now works the way the diagnosis prescribes:
//
//  1. Rank ALL candidates by evidence, not display order:
//     nodes with a successful handshake on record first (by
//     measured latency), then pool nodes by the list's own
//     reported Ping / Score, then the rest in display order.
//     The frozen weak-encryption demotion applies inside
//     every tier (see autoselect.go).
//  2. Fast TCP pre-check (fastcheck.go) over the best-ranked
//     probable candidates only — concurrent, ≤3 s each.
//  3. Real connects, best first, at most oneTapMaxAttempts
//     of them, each bounded by oneTapAttemptBudget; the
//     first CONNECTED stops the chain. A candidate that just
//     failed its pre-check is not retried inside the same
//     chain. Total worst case ≈ pre-check ~6 s + 5 × 15 s.
//
// The chain runs on the caller's context: canceling it (the
// UI registers the chain via BeginOp, and Disconnect cancels
// it) stops every stage promptly and — via the attempt
// watchdog below — unwinds a session start already in
// flight, so no new session can start after the user said
// stop.

// OneTapStage identifies a chain phase for the UI's progress
// display. The node argument of the callback is the candidate
// being attempted (Connect stage only).
type OneTapStage int

const (
	OneTapStageCheck OneTapStage = iota + 1
	OneTapStageConnect
)

const (
	// oneTapPrecheckPool is how many top-ranked probable
	// candidates get the fast pre-check.
	oneTapPrecheckPool = 12
	// oneTapMaxAttempts caps real connection attempts.
	oneTapMaxAttempts = 5
	// oneTapAttemptBudget bounds one real connection
	// attempt inside the chain (a MANUAL single-node
	// connect keeps the engine's own 45 s bound instead —
	// only the chain's per-try budget is this short).
	oneTapAttemptBudget = 15 * time.Second
)

// rankOneTapCandidates orders records for the chain by the
// evidence tiers described above. Tier 0 orders exactly like
// AutoSelectExplain (the auto-select the chain replaces):
// weak demotion, then the protocol preference's near-tie
// buckets and class ranks, then exact latency — the settings
// preference keeps its meaning on the one-tap path. Input
// order (display order) breaks remaining ties; the sort is
// stable and the result deterministic.
func rankOneTapCandidates(recs []NodeRecord, pref string) []NodeRecord {
	type cand struct {
		rec     NodeRecord
		tier    int
		latency float64 // tier 0: measured handshake latency
		ping    int64   // tier 1: source-reported ping (MaxInt64 when unknown)
		score   int64   // tier 1: source-reported score
		weak    bool
		class   ProtocolClass
	}
	cands := make([]cand, 0, len(recs))
	for _, rec := range recs {
		c := cand{rec: rec, weak: WeakEncryption(rec.Node), ping: math.MaxInt64,
			class: ProtocolClassOf(rec.Node.Protocol)}
		switch {
		case rec.Node.LastTest != nil && rec.Node.LastTest.OK && rec.Node.LastTest.LatencyMs != nil:
			c.tier = 0
			c.latency = *rec.Node.LastTest.LatencyMs
		case rec.SourcePingMs > 0 || rec.SourceScore > 0:
			c.tier = 1
			if rec.SourcePingMs > 0 {
				c.ping = rec.SourcePingMs
			}
			c.score = rec.SourceScore
		default:
			c.tier = 2
		}
		cands = append(cands, c)
	}
	preference := pref == ProtocolPrefSpeed || pref == ProtocolPrefCompat
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.tier != b.tier {
			return a.tier < b.tier
		}
		if a.weak != b.weak {
			return !a.weak // non-weak first (frozen ruling)
		}
		switch a.tier {
		case 0:
			if preference {
				bi := int(a.latency / latencyBucketMs)
				bj := int(b.latency / latencyBucketMs)
				if bi != bj {
					return bi < bj
				}
				ri, rj := classRank(pref, a.class), classRank(pref, b.class)
				if ri != rj {
					return ri < rj
				}
			}
			return a.latency < b.latency
		case 1:
			if a.ping != b.ping {
				return a.ping < b.ping
			}
			return a.score > b.score
		}
		return false
	})
	out := make([]NodeRecord, len(cands))
	for i, c := range cands {
		out[i] = c.rec
	}
	return out
}

// OneTapConnect runs the chain over one group's nodes and
// returns the node it connected. onStage (may be nil) reports
// phase changes for the hero card. Failure taxonomy: the
// chain context's own error when canceled; ErrNoNodeResponded
// when every attempt failed in the no-response class
// (silence / timeout — the current network path simply does
// not answer); otherwise the last attempt's real error,
// classified exactly as a manual connect would be.
func (s *Service) OneTapConnect(ctx context.Context, group string, onStage func(OneTapStage, *specnode.Node)) (*specnode.Node, error) {
	if s.engine == nil {
		return nil, ErrNoEngine
	}
	views := s.Nodes(group)
	if len(views) == 0 {
		return nil, ErrNoNodeSelected
	}
	recs := make([]NodeRecord, 0, len(views))
	for _, v := range views {
		recs = append(recs, v.Record)
	}
	pref := s.ProtocolPref()
	ranked := rankOneTapCandidates(recs, pref)
	// The settings page's post-hoc preference line keys off
	// the plain auto-select outcome (as it did when the chain
	// ran AutoSelectAndConnect): compute it up front, and
	// record it only if the chain actually lands on that
	// pick — never claim a fallback story for a different
	// node than the one auto-select would have chosen.
	autoPick, autoFellBack := AutoSelectExplain(recs, pref)

	if onStage != nil {
		onStage(OneTapStageCheck, nil)
	}
	// Fast pre-check over the best-ranked probable
	// candidates (bounded set, concurrent, ≤3 s each).
	var preList []*specnode.Node
	for _, rec := range ranked {
		if len(preList) >= oneTapPrecheckPool {
			break
		}
		if tcpProbable(rec.Node) {
			preList = append(preList, rec.Node)
		}
	}
	prechecked := s.probeMany(ctx, preList, nil)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Attempt order: pre-checked responders by measured
	// latency first; then every candidate the pre-check did
	// not cover (UDP nodes, the ranking's tail) in rank
	// order. Pre-checked non-responders are excluded (see
	// the header: no same-chain retry of a just-failed node).
	var responders []NodeRecord
	for _, rec := range ranked {
		if r, ok := prechecked[rec.Node.ID]; ok && r.Reachable {
			responders = append(responders, rec)
		}
	}
	sort.SliceStable(responders, func(i, j int) bool {
		return prechecked[responders[i].Node.ID].LatencyMs < prechecked[responders[j].Node.ID].LatencyMs
	})
	attempts := append([]NodeRecord{}, responders...)
	for _, rec := range ranked {
		if _, covered := prechecked[rec.Node.ID]; !covered {
			attempts = append(attempts, rec)
		}
	}
	if len(attempts) > oneTapMaxAttempts {
		attempts = attempts[:oneTapMaxAttempts]
	}
	if len(attempts) == 0 {
		return nil, ErrNoNodeResponded
	}

	var lastErr error
	allNoResponse := true
	for _, rec := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if onStage != nil {
			onStage(OneTapStageConnect, rec.Node)
		}
		start := time.Now()
		err, timedOut := s.connectAttempt(ctx, rec.Node.ID)
		if err == nil {
			if autoPick != nil && autoPick.ID == rec.Node.ID {
				s.mu.Lock()
				s.lastAuto = autoSelectOutcome{nodeName: rec.Node.Name, fellBack: autoFellBack, ok: true}
				s.mu.Unlock()
			}
			// A connect IS a real handshake: record its
			// measured latency exactly like a probe's
			// (this is what lets the node rank by evidence
			// next time, and enter "picked for you").
			s.recordHandshakeSuccess(rec, time.Now(), time.Since(start))
			_ = s.store.Save()
			s.logf("one-tap: connected to %s (%s)", rec.Node.Name, rec.Node.ID)
			return rec.Node, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		s.logf("one-tap: %s (%s) failed: %v", rec.Node.Name, rec.Node.ID, err)
		if !timedOut && !attemptNoResponse(err) {
			allNoResponse = false
		}
		lastErr = err
	}
	if allNoResponse {
		return nil, ErrNoNodeResponded
	}
	return nil, lastErr
}

// attemptNoResponse classifies an attempt failure as the
// no-response class: the server (or the path to it) stayed
// silent — a timeout, or a transport-level failure with no
// protocol answer. Anything with a protocol-level answer
// (auth refused, config rejected, TLS failure) is NOT in
// this class: it carries information the user should see
// classified as itself.
func attemptNoResponse(err error) bool {
	switch kernel.KindOf(err) {
	case kernel.KindTimeout, kernel.KindNetwork:
		return true
	}
	return false
}

// connectAttempt runs one Connect under the chain's attempt
// budget. The budget is enforced by a stop-the-engine
// watchdog: an engine whose start wait does not unwind on
// context cancellation alone (the OpenVPN 3 start detaches
// its consent phase) is stopped outright when the budget or
// the chain dies, and the attempt collects the start's real
// outcome before returning. timedOut reports that the
// attempt consumed its budget (as opposed to failing fast or
// being canceled by the caller).
func (s *Service) connectAttempt(ctx context.Context, id string) (err error, timedOut bool) {
	actx, cancel := context.WithTimeout(ctx, oneTapAttemptBudget)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Connect(actx, id) }()
	select {
	case err := <-done:
		return err, false
	case <-actx.Done():
		// Budget exhausted or chain canceled while the
		// start is still in flight: force it to unwind
		// now, then report its real outcome.
		if s.engine != nil {
			_ = s.engine.Stop(context.Background())
		}
		err := <-done
		if err == nil && s.engine != nil && s.engine.Status().State != kernel.StateRunning {
			// The stop landed on a session that had just
			// connected: it is down now, so the attempt
			// honestly counts as a budget timeout.
			err = kernel.NewError(kernel.KindTimeout, "Connect",
				"the attempt was stopped at its budget", nil)
		}
		return err, ctx.Err() == nil
	}
}
