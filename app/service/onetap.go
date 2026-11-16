package service

import (
	"context"
	"math"
	"sort"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/openvpn"
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
//     candidates, each attempt bounded by
//     oneTapAttemptBudget; the first CONNECTED stops the
//     chain. A candidate that just failed its pre-check is
//     not retried inside the same chain. ONE exception: an
//     attempt refused with an auth rejection
//     (attemptAuthRejected) earns exactly one same-node
//     retry — the live-server evidence (diagnosis §11) is
//     that some SoftEther builds capture the client
//     certificate only intermittently, so a second draw
//     against the same node can connect where the first
//     was refused. The retry spends from the same start
//     budget as first attempts (oneTapMaxStarts), so the
//     total worst case stays ≈ pre-check ~6 s + 5 × 15 s
//     plus at most a few 1 s retry gaps.
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
	// oneTapMaxAttempts caps the candidates a chain will
	// try (distinct nodes).
	oneTapMaxAttempts = 5
	// oneTapMaxStarts caps the TOTAL real connection starts
	// one chain may make: first attempts and same-node auth
	// retries draw from this one budget, so a retry never
	// adds starts on top of the candidate cap — it spends
	// reach into later candidates instead. With at most
	// one retry per candidate the chain still makes at
	// most oneTapMaxStarts starts, each bounded by
	// oneTapAttemptBudget.
	oneTapMaxStarts = oneTapMaxAttempts
	// oneTapAttemptBudget bounds one real connection
	// attempt inside the chain (a MANUAL single-node
	// connect keeps the engine's own 45 s bound instead —
	// only the chain's per-try budget is this short).
	oneTapAttemptBudget = 15 * time.Second
)

// oneTapAuthRetryDelay is the short pause before the
// same-node auth retry: long enough for the server's
// per-connection state to settle, short enough to stay
// inside the chain's interactive feel. The wait dies with
// the chain context. A variable (not a constant) so
// internal tests can resize it.
var oneTapAuthRetryDelay = time.Second

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
	startsLeft := oneTapMaxStarts
	for _, rec := range attempts {
		if startsLeft <= 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if onStage != nil {
			onStage(OneTapStageConnect, rec.Node)
		}
		// One candidate may cost two starts: its first
		// attempt, plus — only after an auth rejection —
		// the single same-node retry. Both draws spend
		// from startsLeft, so the retry never extends the
		// chain past oneTapMaxStarts total starts.
		for draw := 0; ; draw++ {
			start := time.Now()
			err, timedOut := s.connectAttempt(ctx, rec.Node.ID)
			startsLeft--
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
			// The retry is narrow on purpose: first draw
			// only, a clean auth rejection only (an attempt
			// the watchdog had to stop at its budget is the
			// timeout class, not a fresh draw), and only
			// while the start budget lasts.
			if draw > 0 || timedOut || startsLeft <= 0 || !attemptAuthRejected(err) {
				break
			}
			s.logf("one-tap: %s (%s) auth rejected; retrying the same node once", rec.Node.Name, rec.Node.ID)
			timer := time.NewTimer(oneTapAuthRetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
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

// attemptAuthRejected classifies an attempt failure as the
// server-side credential rejection: the core reported
// AUTH_FAILED, which both production OpenVPN paths map to
// the stable code openvpn.CodeAuthFailed (the desktop
// process adapter from the child's AUTH_FAILED line, the
// Android OpenVPN 3 engine from the native event). This is
// the chain's ONLY retryable class, and deliberately
// narrower than kernel.KindHandshakeFailed: a TLS failure
// or a certificate-verify refusal is deterministic and a
// second draw would fail identically, while the
// AUTH_FAILED draws against SoftEther pool hosts are the
// documented intermittent-capture lottery (diagnosis §11:
// identical config, first attempt AUTH_FAILED, second
// CONNECTED). Keying on the code rather than the kind also
// keeps an unclassified handshake failure — one that never
// carried the core's AUTH_FAILED verdict — out of the
// retry.
func attemptAuthRejected(err error) bool {
	return openvpn.CodeOf(err) == openvpn.CodeAuthFailed
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
