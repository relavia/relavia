package service

import (
	"sort"

	"openproxy/core/specnode"
)

// Protocol preference values (Settings.ProtocolPref), from the
// 2026-11-14 design ruling: the settings page offers real
// choices, and every choice is wired into the ranking below.
const (
	ProtocolPrefAuto   = "auto"   // by measured latency only
	ProtocolPrefSpeed  = "speed"  // fast protocols win near-ties
	ProtocolPrefCompat = "compat" // traditional protocols win near-ties
)

// ProtocolClass groups a protocol family for the preference
// ranking: fast modern UDP protocols, traditional protocols, and
// everything else (neutral). The classes are about handshake and
// transport overhead characteristics, not about quality claims
// for any single node.
type ProtocolClass int

const (
	ClassNeutral ProtocolClass = iota
	ClassFast
	ClassTraditional
)

// ProtocolClassOf classifies a unified-model protocol string.
func ProtocolClassOf(protocol string) ProtocolClass {
	switch protocol {
	case "wireguard", "hysteria2", "tuic":
		return ClassFast
	case "shadowsocks", "trojan", "vmess", "openvpn", "socks5", "http":
		return ClassTraditional
	default:
		return ClassNeutral
	}
}

// classRank orders classes for a preference: the preferred class
// first, neutral in the middle, the opposite class last.
func classRank(pref string, c ProtocolClass) int {
	switch pref {
	case ProtocolPrefSpeed:
		switch c {
		case ClassFast:
			return 0
		case ClassNeutral:
			return 1
		default:
			return 2
		}
	case ProtocolPrefCompat:
		switch c {
		case ClassTraditional:
			return 0
		case ClassNeutral:
			return 1
		default:
			return 2
		}
	}
	return 0
}

// latencyBucketMs is the near-tie window for the preference
// ranking: latencies within one bucket count as "the same
// latency" for preference purposes (the ruling's 同延迟）, so
// the protocol class decides inside a bucket while a clearly
// faster node (a full bucket or more) still wins on speed.
const latencyBucketMs = 25.0

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
	return AutoSelectWithPreference(records, ProtocolPrefAuto)
}

// AutoSelectWithPreference is AutoSelect plus the user's protocol
// preference. The frozen weak-encryption demotion always applies
// first (a preference never promotes a weak node over a non-weak
// one). Under "speed" / "compat", candidates whose latencies fall
// in the same near-tie bucket are ordered by protocol class
// before exact latency; under "auto" the ranking is exactly
// AutoSelect's. A preference whose class has no candidate in the
// set simply falls back to the remaining order — the caller can
// detect that case (no candidate of the preferred class) and say
// so in the UI.
func AutoSelectWithPreference(records []NodeRecord, pref string) *specnode.Node {
	type cand struct {
		node    *specnode.Node
		weak    bool
		latency float64
		class   ProtocolClass
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
			class:   ProtocolClassOf(rec.Node.Protocol),
		})
	}
	if len(cands) == 0 {
		return nil
	}
	preference := pref == ProtocolPrefSpeed || pref == ProtocolPrefCompat
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].weak != cands[j].weak {
			return !cands[i].weak // non-weak first
		}
		if preference {
			bi := int(cands[i].latency / latencyBucketMs)
			bj := int(cands[j].latency / latencyBucketMs)
			if bi != bj {
				return bi < bj
			}
			ri, rj := classRank(pref, cands[i].class), classRank(pref, cands[j].class)
			if ri != rj {
				return ri < rj
			}
		}
		return cands[i].latency < cands[j].latency
	})
	return cands[0].node
}
