package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/plugins/vpngate"
)

// sampleCSVPath is the plugin's frozen 2026-11-12 list snapshot
// (10 nodes, all Japan, TCP mode) reused as the refresh payload.
const sampleCSVPath = "../../plugins/vpngate/testdata/vpngate-sample-2026-11-12.csv"

// stubDialer makes exactly one pool server reachable.
func stubDialer(ctx context.Context, network, address string) (net.Conn, error) {
	if strings.HasPrefix(address, "219.100.37.209:") {
		c1, _ := net.Pipe()
		return c1, nil
	}
	return nil, errors.New("stub: unreachable")
}

func newPoolPlugin(t *testing.T, endpoint string) *vpngate.Plugin {
	t.Helper()
	dir := t.TempDir()
	consent, err := vpngate.NewConsent(&vpngate.FileConsentStore{Path: filepath.Join(dir, "consent.json")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := vpngate.New(&vpngate.Fetcher{
		Endpoints: []string{endpoint},
		Cache:     &vpngate.FileCache{Dir: dir},
	}, consent)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newPoolService(t *testing.T, endpoint string, eng Engine) (*Service, *vpngate.Plugin) {
	t.Helper()
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store, eng)
	p := newPoolPlugin(t, endpoint)
	svc.SetVPNGate(p)
	svc.vgProber = &vpngate.Prober{Dial: stubDialer}
	return svc, p
}

func serveSample(t *testing.T) *httptest.Server {
	t.Helper()
	payload, err := os.ReadFile(sampleCSVPath)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
}

func TestVPNGateConsentGateOnAppPath(t *testing.T) {
	srv := serveSample(t)
	defer srv.Close()
	svc, _ := newPoolService(t, srv.URL, nil)
	ctx := context.Background()

	// Nothing acknowledged: enable and refresh must refuse with
	// the plugin's sentinel — the app path adds no bypass.
	if err := svc.EnableVPNGate(); !errors.Is(err, vpngate.ErrConsentRequired) {
		t.Fatalf("EnableVPNGate before consent: %v", err)
	}
	if _, err := svc.RefreshVPNGate(ctx, true); !errors.Is(err, vpngate.ErrConsentRequired) {
		t.Fatalf("RefreshVPNGate before consent: %v", err)
	}
	st := svc.VPNGateStatus()
	if !st.Attached || st.Enabled || st.ConsentState != "none" || st.NodeCount != 0 {
		t.Fatalf("status before consent: %+v", st)
	}

	// Acknowledge -> enable -> refresh works end to end.
	if err := svc.AcknowledgeVPNGateRisk(); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableVPNGate(); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.RefreshVPNGate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.NodeCount != 10 || rep.GroupCount != 1 {
		t.Fatalf("refresh report: %+v", rep)
	}
	if rep.ProbedReachable != 1 {
		t.Fatalf("stub dialer makes exactly one node reachable, got %d", rep.ProbedReachable)
	}
	if rep.Stale || rep.FromCache {
		t.Fatalf("fresh fetch must not be stale/cache: %+v", rep)
	}

	// Nodes landed with source registration, country group and
	// factual admission levels.
	views := svc.Nodes(AllGroups)
	if len(views) != 10 {
		t.Fatalf("store holds %d nodes, want 10", len(views))
	}
	admissions := map[string]int{}
	for _, v := range views {
		if !v.VPNGate {
			t.Fatalf("pool node missing VPNGate flag: %+v", v.Record.Node.Source)
		}
		if v.Record.Node.Source.Kind != "plugin" || v.Record.Node.Source.Ref != VPNGateSourceRef {
			t.Fatalf("source registration: %+v", v.Record.Node.Source)
		}
		if v.Record.Node.Group != "Japan" {
			t.Fatalf("country group: %q", v.Record.Node.Group)
		}
		if v.Record.Node.Protocol != specnode.ProtocolOpenVPN {
			t.Fatalf("pool node protocol: %q", v.Record.Node.Protocol)
		}
		admissions[v.Admission]++
	}
	if admissions[vpngate.ProbeLevelTCPConnect] != 1 || admissions[vpngate.ProbeLevelNone] != 9 {
		t.Fatalf("admission levels: %v", admissions)
	}
	st = svc.VPNGateStatus()
	if !st.Enabled || st.NodeCount != 10 || st.Stale || st.LastRefresh.IsZero() {
		t.Fatalf("status after refresh: %+v", st)
	}
	if groups := svc.Groups(); len(groups) != 1 || groups[0] != "Japan" {
		t.Fatalf("groups: %v", groups)
	}
}

func TestVPNGateRefreshFailureKeepsStaleSnapshot(t *testing.T) {
	srv := serveSample(t)
	svc, p := newPoolService(t, srv.URL, nil)
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
	// Total failure with no cache to fall back on: endpoint
	// dead AND cache purged.
	srv.Close()
	if err := p.Fetcher.Cache.Purge(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshVPNGate(ctx, true); err == nil {
		t.Fatal("refresh against a dead endpoint with no cache must fail")
	}
	st := svc.VPNGateStatus()
	if !st.Stale || st.LastError == "" {
		t.Fatalf("failure must mark the snapshot stale with a reason: %+v", st)
	}
	if st.NodeCount != 10 {
		t.Fatalf("previous snapshot must be kept, got %d nodes", st.NodeCount)
	}
}

func TestVPNGateStaleCacheRefreshIsLabelled(t *testing.T) {
	srv := serveSample(t)
	svc, _ := newPoolService(t, srv.URL, nil)
	ctx := context.Background()
	_ = svc.AcknowledgeVPNGateRisk()
	_ = svc.EnableVPNGate()
	if _, err := svc.RefreshVPNGate(ctx, true); err != nil {
		t.Fatal(err)
	}
	srv.Close() // endpoint dead, cache intact -> stale-cache path
	rep, err := svc.RefreshVPNGate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Stale || !rep.FromCache || rep.LastError == "" {
		t.Fatalf("cache fallback must be labelled stale with the failure: %+v", rep)
	}
	if st := svc.VPNGateStatus(); !st.Stale {
		t.Fatalf("status must show stale: %+v", st)
	}
}

func TestVPNGateDisableRevokesAndPurges(t *testing.T) {
	srv := serveSample(t)
	defer srv.Close()
	svc, _ := newPoolService(t, srv.URL, nil)
	ctx := context.Background()
	_ = svc.AcknowledgeVPNGateRisk()
	_ = svc.EnableVPNGate()
	if _, err := svc.RefreshVPNGate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableVPNGate(); err != nil {
		t.Fatal(err)
	}
	st := svc.VPNGateStatus()
	if st.Enabled || st.ConsentState != "revoked" || st.NodeCount != 0 || !st.LastRefresh.IsZero() {
		t.Fatalf("status after disable: %+v", st)
	}
	// The gate is closed again: refresh refuses, enable refuses.
	if _, err := svc.RefreshVPNGate(ctx, true); !errors.Is(err, vpngate.ErrConsentRequired) {
		t.Fatalf("refresh after revoke: %v", err)
	}
	if err := svc.EnableVPNGate(); !errors.Is(err, vpngate.ErrConsentRequired) {
		t.Fatalf("enable after revoke: %v", err)
	}
}

// hsEngine is a minimal engine whose handshakes always succeed.
type hsEngine struct{}

func (hsEngine) Capabilities() kernel.Capabilities { return kernel.Capabilities{KernelID: "hs"} }
func (hsEngine) ValidateSpec(context.Context, *specnode.Node) error {
	return nil
}
func (hsEngine) StartNode(context.Context, *specnode.Node, kernel.PlatformOptions) error {
	return nil
}
func (hsEngine) Stop(context.Context) error { return nil }
func (hsEngine) Status() kernel.Status      { return kernel.Status{State: kernel.StateIdle} }
func (hsEngine) QueryTraffic(context.Context) (*kernel.TrafficStats, error) {
	return &kernel.TrafficStats{}, nil
}
func (hsEngine) MixedAddr() string { return "" }
func (hsEngine) TestHandshakeNode(_ context.Context, n *specnode.Node) (*kernel.HandshakeResult, error) {
	return &kernel.HandshakeResult{NodeID: n.ID, OK: true, Latency: time.Millisecond, TestedAt: time.Now()}, nil
}

func TestVPNGateHandshakeVerifiedSurvivesRefresh(t *testing.T) {
	srv := serveSample(t)
	defer srv.Close()
	svc, _ := newPoolService(t, srv.URL, hsEngine{})
	ctx := context.Background()
	_ = svc.AcknowledgeVPNGateRisk()
	_ = svc.EnableVPNGate()
	if _, err := svc.RefreshVPNGate(ctx, true); err != nil {
		t.Fatal(err)
	}
	views := svc.Nodes(AllGroups)
	target := views[0].Record.Node.ID
	if _, err := svc.TestNode(ctx, target); err != nil {
		t.Fatal(err)
	}
	v, ok := svc.NodeByID(target)
	if !ok || v.Admission != vpngate.ProbeLevelHandshakeVerified {
		t.Fatalf("successful engine handshake must upgrade admission: %+v", v)
	}
	// A later refresh re-probes TCP reachability but must not
	// downgrade the established handshake verification (the
	// stub dialer leaves this node unreachable, which would
	// otherwise reset it to "none").
	if _, err := svc.RefreshVPNGate(ctx, true); err != nil {
		t.Fatal(err)
	}
	v, ok = svc.NodeByID(target)
	if !ok || v.Admission != vpngate.ProbeLevelHandshakeVerified {
		t.Fatalf("refresh downgraded admission: %+v", v)
	}
}

// TestVPNGateLiveRefresh is the operator-run evidence test for
// the app-path wiring against the REAL official list. It is
// skipped unless RELAVIA_VG_LIVE=1 (CI must not depend on the
// public endpoint). It exercises the production plugin
// (NewDefault: real endpoints, file cache/consent) through the
// service exactly as the app does.
func TestVPNGateLiveRefresh(t *testing.T) {
	if os.Getenv("RELAVIA_VG_LIVE") != "1" {
		t.Skip("set RELAVIA_VG_LIVE=1 for the live-endpoint evidence run")
	}
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store, nil)
	p, err := NewVPNGatePlugin(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc.SetVPNGate(p)
	if err := svc.AcknowledgeVPNGateRisk(); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableVPNGate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	rep, err := svc.RefreshVPNGate(ctx, true)
	if err != nil {
		t.Fatalf("live refresh: %v", err)
	}
	t.Logf("live refresh: nodes=%d groups=%d rowErrors=%d fromCache=%v stale=%v tcpReachable=%d fetchedAt=%s",
		rep.NodeCount, rep.GroupCount, rep.RowErrors, rep.FromCache, rep.Stale, rep.ProbedReachable, rep.FetchedAt)
	t.Logf("groups: %v", svc.Groups())
	if rep.NodeCount < 50 {
		t.Fatalf("live list implausibly small: %d nodes", rep.NodeCount)
	}
}
