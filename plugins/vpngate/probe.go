package vpngate

import (
	"context"
	"fmt"
	"net"
	"time"

	"openproxy/core/parsers"
)

// Probe levels, named honestly (the kernel layer's rule
// applies project-wide: no ping or bare connect may masquerade
// as a protocol handshake).
const (
	// ProbeLevelTCPConnect means only transport reachability
	// was established: a TCP connection to server:port opened.
	// This is NOT an OpenVPN handshake.
	ProbeLevelTCPConnect = "tcp-connect"
	// ProbeLevelNone means no probe could be performed (e.g.
	// UDP-mode node): reachability is unknown, not "down".
	ProbeLevelNone = "none"
)

// ProbeResult is one node's probing outcome.
type ProbeResult struct {
	NodeID    string
	Level     string // ProbeLevelTCPConnect or ProbeLevelNone
	Probed    bool   // a probe was actually performed
	Reachable bool   // meaningful only when Probed is true
	Latency   time.Duration
	Detail    string
}

// Prober is the plugin's own reachability probe.
//
// Ruling (recorded as a deviation in the Step 14 doc): book 7.3
// asks for real-handshake admission. A real OpenVPN handshake
// requires the OpenVPN independent-process engine (Step 2
// license-audit ruling), which has not landed yet — the Step 7
// sing-box adapter explicitly reports OpenVPN as unsupported.
// Until that engine lands, admission to the *displayed* list is
// config validity (Step 8 parse) plus this reachability probe,
// always labelled with its level; a real handshake through the
// kernel adapter remains the admission test for *connecting*
// once the OpenVPN engine exists. The probe never claims to be
// a handshake.
type Prober struct {
	Timeout time.Duration // per node; default 5s
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 5 * time.Second
}

func (p *Prober) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial(ctx, network, address)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, address)
}

// Probe tests one node. UDP-mode OpenVPN nodes cannot be
// reachability-probed without speaking the protocol, so they
// are reported unprobed rather than unreachable.
func (p *Prober) Probe(ctx context.Context, node *parsers.Node) ProbeResult {
	res := ProbeResult{NodeID: node.ID, Level: ProbeLevelNone}
	if node.UDP != nil && *node.UDP {
		res.Detail = "UDP-mode node: transport reachability cannot be established without an OpenVPN handshake (pending the OpenVPN process engine); status unknown, not down"
		return res
	}
	addr := net.JoinHostPort(node.Server, fmt.Sprintf("%d", node.Port))
	dctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	start := time.Now()
	conn, err := p.dial(dctx, "tcp", addr)
	res.Level = ProbeLevelTCPConnect
	res.Probed = true
	if err != nil {
		res.Detail = "tcp connect failed: " + err.Error()
		return res
	}
	_ = conn.Close()
	res.Reachable = true
	res.Latency = time.Since(start)
	res.Detail = "tcp connect succeeded (transport reachability only, not an OpenVPN handshake)"
	return res
}

// ProbeAll probes nodes sequentially and returns results in
// input order. (The list is ~100 nodes; the app may call this
// per group. Concurrency policy belongs to the caller.)
func (p *Prober) ProbeAll(ctx context.Context, nodes []*parsers.Node) []ProbeResult {
	out := make([]ProbeResult, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, p.Probe(ctx, n))
	}
	return out
}
