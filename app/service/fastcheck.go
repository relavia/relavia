package service

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"openproxy/core/specnode"
)

// Fast reachability checks (2026-11-14 fix batch).
//
// What changed and why: the node page's "check latency" and
// the one-tap chain used to run a FULL protocol handshake per
// node (TestGroup). For OpenVPN pool nodes on Android that is
// a complete OpenVPN 3 session per node — up to 45 s each,
// sequentially — so checking ~99 pool nodes could never
// finish inside any sane budget, and the list sat at "not
// checked yet" forever (diagnosis §4②/§5.1).
//
// The fast check is deliberately a weaker, honestly-labelled
// signal: a plain TCP connect to the node's server:port,
// measuring reachability and connect latency. It is NOT a
// handshake and never feeds the handshake records (LastTest):
// a node that answers TCP has shown "network reachable +
// this fast", nothing more. Full-session probing remains
// available exactly where it belongs — a manual single-node
// connect (and TestNode for diagnostics).

// ReachResult is one node's fast-check outcome. Results live
// in the Service's memory only (a process restart forgets
// them; they are a "just measured" signal, not history).
type ReachResult struct {
	// Checked reports a probe actually ran (false for
	// transports a bare TCP connect cannot speak for, e.g.
	// UDP-only nodes: their reachability stays unknown,
	// never "down").
	Checked bool
	// Reachable reports the TCP connect succeeded.
	Reachable bool
	// LatencyMs is the measured TCP connect latency
	// (meaningful only when Reachable).
	LatencyMs float64
	// At is when the check ran.
	At time.Time
	// Err is the dial failure detail for the log (internal,
	// never display text).
	Err string
}

// defaultFastCheckTimeout bounds one node's fast check. The
// batch brief fixes ≤3 s per node: long enough for a real
// transcontinental SYN, short enough that a dead node costs
// almost nothing.
const defaultFastCheckTimeout = 3 * time.Second

// fastCheckConcurrency bounds simultaneous dials in a group
// check: the whole list must land in bounded time even when
// every node is dead (99 nodes × 3 s / 16 ≈ 19 s worst case).
const fastCheckConcurrency = 16

// fastCheckGroupBudget caps one whole group check regardless
// of list size.
const fastCheckGroupBudget = 45 * time.Second

func (s *Service) dialTCP(ctx context.Context, network, address string) (net.Conn, error) {
	if s.tcpDial != nil {
		return s.tcpDial(ctx, network, address)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, address)
}

func (s *Service) checkTimeout() time.Duration {
	if s.fastCheckTimeout > 0 {
		return s.fastCheckTimeout
	}
	return defaultFastCheckTimeout
}

// setReach records a node's fast-check result for this process.
func (s *Service) setReach(id string, r *ReachResult) {
	s.reachMu.Lock()
	defer s.reachMu.Unlock()
	if s.reach == nil {
		s.reach = map[string]*ReachResult{}
	}
	cp := *r
	s.reach[id] = &cp
}

// reachResult returns a copy of the node's fast-check result,
// or nil when the node was never fast-checked in this process.
func (s *Service) reachResult(id string) *ReachResult {
	s.reachMu.Lock()
	defer s.reachMu.Unlock()
	r, ok := s.reach[id]
	if !ok {
		return nil
	}
	cp := *r
	return &cp
}

// tcpProbable reports whether a bare TCP connect can say
// anything about this node's reachability: the node must have
// a server endpoint and a TCP-carried transport. UDP-native
// protocols (Hysteria2, TUIC, WireGuard, UDP OpenVPN) cannot
// be probed this way — probing them with TCP would report
// healthy nodes as dead, so they are honestly unprobable.
func tcpProbable(n *specnode.Node) bool {
	if n == nil || n.Server == "" || n.Port <= 0 {
		return false
	}
	if n.UDP {
		return false
	}
	switch n.Protocol {
	case specnode.ProtocolHysteria2, specnode.ProtocolTUIC, specnode.ProtocolWireGuard:
		return false
	case specnode.ProtocolOpenVPN:
		return openVPNProtoIsTCP(n)
	case specnode.ProtocolVMess, specnode.ProtocolVLESS:
		switch n.TransportType() {
		case "quic", "kcp":
			return false
		}
		return true
	default:
		// shadowsocks / trojan / socks5 / http are TCP-carried
		// in their native form.
		return true
	}
}

// openVPNProtoIsTCP reads the node's effective OpenVPN
// transport: the structured credential's proto field, or the
// first proto directive of a full-text body (OpenVPN's own
// default, when no directive exists, is UDP).
func openVPNProtoIsTCP(n *specnode.Node) bool {
	c := n.OpenVPN
	if c == nil {
		return false
	}
	if c.ConfigContent != "" {
		for _, line := range strings.Split(c.ConfigContent, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && strings.EqualFold(f[0], "proto") {
				return strings.HasPrefix(strings.ToLower(f[1]), "tcp")
			}
		}
		return false
	}
	return strings.HasPrefix(strings.ToLower(c.Proto), "tcp")
}

// probeTCP runs one fast check against a node and returns the
// outcome (not recorded; callers record). The result is data,
// not an error: an unreachable node is a normal outcome.
func (s *Service) probeTCP(ctx context.Context, n *specnode.Node) *ReachResult {
	res := &ReachResult{At: time.Now()}
	if !tcpProbable(n) {
		return res // Checked stays false: unknown, not down
	}
	res.Checked = true
	dctx, cancel := context.WithTimeout(ctx, s.checkTimeout())
	defer cancel()
	addr := net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
	start := time.Now()
	conn, err := s.dialTCP(dctx, "tcp", addr)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	_ = conn.Close()
	res.Reachable = true
	res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	return res
}

// CheckNodeFast runs the fast check for one node (the node
// row's "check latency" action), records the result on the
// node's view and returns it. A no-response outcome is a
// result, not an error; it is logged with its real reason
// like every user-visible failure. An error is returned only
// when the check itself could not be set up (no such node).
func (s *Service) CheckNodeFast(ctx context.Context, id string) (*ReachResult, error) {
	rec, ok := s.store.NodeByID(id)
	if !ok {
		return nil, ErrNoNodeSelected
	}
	res := s.probeTCP(ctx, rec.Node)
	if res.Checked {
		s.setReach(id, res)
		if !res.Reachable {
			s.logf("check %s (%s): no response: %s", rec.Node.Name, id, res.Err)
		}
	}
	return res, nil
}

// probeMany fast-checks a set of nodes concurrently and
// records every result. onEach (may be nil) fires per
// recorded result, in completion order, serialized under the
// same mutex that guards the result map — callbacks may
// safely accumulate counters. Returns the results by node ID
// (only nodes actually probed appear). Shared by the group
// check and the one-tap chain's pre-check.
func (s *Service) probeMany(ctx context.Context, nodes []*specnode.Node, onEach func(*specnode.Node, *ReachResult)) map[string]*ReachResult {
	out := map[string]*ReachResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, fastCheckConcurrency)
	for _, n := range nodes {
		wg.Add(1)
		go func(n *specnode.Node) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			res := s.probeTCP(ctx, n)
			if !res.Checked {
				return
			}
			s.setReach(n.ID, res)
			mu.Lock()
			out[n.ID] = res
			if onEach != nil {
				onEach(n, res)
			}
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}

// CheckGroupFast fast-checks every TCP-probable node of a
// group (the node page's check-all action). Results land per
// node as they complete — onProgress (may be nil) fires after
// each recorded result so the UI can redraw — and the whole
// run is bounded by fastCheckGroupBudget and the caller's
// context: canceling stops the sweep promptly and leaves the
// results gathered so far in place. Returns how many nodes
// were checked and how many responded.
func (s *Service) CheckGroupFast(ctx context.Context, group string, onProgress func()) (checked, responded int) {
	ctx, cancel := context.WithTimeout(ctx, fastCheckGroupBudget)
	defer cancel()
	views := s.Nodes(group)
	var nodes []*specnode.Node
	for _, v := range views {
		if tcpProbable(v.Record.Node) {
			nodes = append(nodes, v.Record.Node)
		}
	}
	s.probeMany(ctx, nodes, func(_ *specnode.Node, res *ReachResult) {
		checked++
		if res.Reachable {
			responded++
		}
		if onProgress != nil {
			onProgress()
		}
	})
	s.logf("check: %d nodes checked, %d responded", checked, responded)
	return checked, responded
}
