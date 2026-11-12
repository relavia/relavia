package vpngate

import (
	"context"
	"errors"
	"net"
	"testing"

	"openproxy/core/parsers"
)

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func TestProbeTCPReachableAndNot(t *testing.T) {
	node := &parsers.Node{ID: "n1", Protocol: "openvpn", Server: "203.0.113.7", Port: 1194}
	p := &Prober{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "203.0.113.7:1194" {
			t.Fatalf("dial address = %q", address)
		}
		return fakeConn{}, nil
	}}
	res := p.Probe(context.Background(), node)
	if !res.Probed || !res.Reachable || res.Level != ProbeLevelTCPConnect {
		t.Fatalf("reachable case: %+v", res)
	}

	p.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	res = p.Probe(context.Background(), node)
	if !res.Probed || res.Reachable {
		t.Fatalf("refused case: %+v", res)
	}
}

func TestProbeUDPNodeIsUnprobedNotDown(t *testing.T) {
	udp := true
	node := &parsers.Node{ID: "n2", Protocol: "openvpn", Server: "203.0.113.8", Port: 1194, UDP: &udp}
	p := &Prober{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		t.Fatal("UDP node must not be dialled")
		return nil, nil
	}}
	res := p.Probe(context.Background(), node)
	if res.Probed || res.Reachable || res.Level != ProbeLevelNone {
		t.Fatalf("udp case: %+v, want unprobed/unknown", res)
	}
}
