package vpngate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/openvpn"
	"openproxy/core/parsers"
	"openproxy/core/specnode"
)

// Real-handshake admission (book 7.3), landed with the OpenVPN
// independent-process adapter (core/openvpn; see
// docs/openvpn进程适配.md).
//
// Step 14 shipped with a recorded deviation: admission was config
// validity plus the tcp-connect reachability probe below, because
// no OpenVPN engine existed. The engine now exists, so this file
// adds the handshake-verified level and the prober that reaches
// it. The levels stay strictly ordered and honestly labelled:
//
//	handshake-verified  a full OpenVPN session reached the
//	                    management CONNECTED state through the
//	                    process adapter (TLS handshake +
//	                    authentication + data-channel setup)
//	tcp-connect         transport reachability only (as before)
//	none                nothing could be established
const (
	// ProbeLevelHandshakeVerified means a real OpenVPN handshake
	// completed for this node via the process adapter.
	ProbeLevelHandshakeVerified = "handshake-verified"
)

// HandshakeTester is the slice of the OpenVPN process adapter the
// prober needs. *openvpn.Adapter satisfies it.
type HandshakeTester interface {
	TestHandshakeNode(ctx context.Context, n *specnode.Node) (*kernel.HandshakeResult, error)
}

// HandshakeProber performs real-handshake admission for OpenVPN
// nodes. A zero Tester is a configuration error reported per node
// (never silently downgraded to the TCP probe: a caller asking
// for handshake admission must learn that no engine was wired).
type HandshakeProber struct {
	Tester HandshakeTester
	// TCP, when set, runs the reachability probe first as a cheap
	// pre-filter for TCP-mode nodes: an unreachable endpoint
	// skips the (process-spawning) handshake attempt. UDP-mode
	// nodes always go straight to the handshake (there is no TCP
	// to pre-filter with).
	TCP *Prober
}

// toSpecNode converts a parser node into the unified model the
// adapter consumes, through the shared schema JSON form.
func toSpecNode(pn *parsers.Node) (*specnode.Node, error) {
	raw, err := json.Marshal(pn)
	if err != nil {
		return nil, err
	}
	var sn specnode.Node
	if err := json.Unmarshal(raw, &sn); err != nil {
		return nil, err
	}
	return &sn, nil
}

// ProbeHandshake runs handshake admission for one node and reports
// the highest level actually established.
func (h *HandshakeProber) ProbeHandshake(ctx context.Context, node *parsers.Node) ProbeResult {
	res := ProbeResult{NodeID: node.ID, Level: ProbeLevelNone}
	if node.Protocol != specnode.ProtocolOpenVPN {
		res.Detail = "handshake admission applies to OpenVPN nodes only"
		return res
	}
	if h.Tester == nil {
		res.Detail = "no OpenVPN engine wired for handshake admission (configuration error); NOT downgraded to a reachability claim"
		return res
	}
	isUDP := node.UDP != nil && *node.UDP
	if h.TCP != nil && !isUDP {
		pre := h.TCP.Probe(ctx, node)
		res = pre
		if !pre.Reachable {
			res.Detail = "tcp pre-filter: " + pre.Detail + "; handshake not attempted"
			return res
		}
	}
	sn, err := toSpecNode(node)
	if err != nil {
		res.Detail = "node conversion for handshake failed: " + err.Error()
		return res
	}
	start := time.Now()
	hr, err := h.Tester.TestHandshakeNode(ctx, sn)
	if err != nil {
		// Test-preventing problem (e.g. openvpn binary missing):
		// keep whatever level the pre-filter established and say
		// plainly that the handshake could not run.
		res.Detail = fmt.Sprintf("handshake could not run: %v (established level stays %s)", err, res.Level)
		return res
	}
	res.Probed = true
	if hr.OK {
		res.Level = ProbeLevelHandshakeVerified
		res.Reachable = true
		res.Latency = hr.Latency
		res.Detail = "real OpenVPN handshake completed through the process adapter (management CONNECTED)"
		return res
	}
	detail := "real OpenVPN handshake attempted and failed"
	if hr.Error != nil {
		// The adapter prefixes its stable classification code to
		// the message (see core/openvpn resultError).
		detail += ": " + hr.Error.Message
	}
	res.Detail = detail + fmt.Sprintf(" (attempt took %s; established level stays %s)", time.Since(start).Round(time.Millisecond), res.Level)
	return res
}

// NewHandshakeProber wires the production prober: the OpenVPN
// process adapter with default options plus the TCP pre-filter.
func NewHandshakeProber() *HandshakeProber {
	return &HandshakeProber{
		Tester: openvpn.New(openvpn.Options{}),
		TCP:    &Prober{},
	}
}
