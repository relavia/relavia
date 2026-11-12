package service

import (
	"sort"

	"openproxy/core/specnode"
)

// AutoSelect implements the book 8.1 "auto select (lowest latency
// in group)" rule WITH the Step 5 frozen ruling applied:
//
// A node that relies on weak encryption must never be the default
// recommendation. Concretely, candidates are ordered first by
// "not weak" and only then by measured latency, so a fast weak
// node is chosen ONLY when no non-weak node in the candidate set
// has a successful handshake on record. Nodes without a
// successful, latency-bearing LastTest are never chosen (there is
// nothing honest to rank them by).
//
// The input order is the display order; ties keep display order
// (stable sort), so the result is deterministic.
func AutoSelect(records []NodeRecord) *specnode.Node {
	type cand struct {
		node    *specnode.Node
		weak    bool
		latency float64
	}
	var cands []cand
	for _, rec := range records {
		lt := rec.Node.LastTest
		if lt == nil || !lt.OK || lt.LatencyMs == nil {
			continue
		}
		cands = append(cands, cand{
			node:    rec.Node,
			weak:    WeakEncryption(rec.Node),
			latency: *lt.LatencyMs,
		})
	}
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].weak != cands[j].weak {
			return !cands[i].weak // non-weak first
		}
		return cands[i].latency < cands[j].latency
	})
	return cands[0].node
}
