package service_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openproxy/core/specnode"

	"openproxy/app/service"
)

// tested builds a NodeRecord whose node passed a handshake with
// the given latency — the only candidates AutoSelect ranks.
func tested(id, protocol string, latencyMs float64) service.NodeRecord {
	n := &specnode.Node{
		SchemaVersion: "1.0",
		ID:            id,
		Name:          id,
		Protocol:      protocol,
		Server:        "127.0.0.1",
		Port:          443,
		Source:        specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "user-provided"},
	}
	if protocol == specnode.ProtocolShadowsocks {
		n.Shadowsocks = &specnode.CredShadowsocks{Method: "aes-256-gcm", Password: "pw"}
	}
	lat := latencyMs
	n.LastTest = &specnode.LastTest{OK: true, LatencyMs: &lat}
	return service.NodeRecord{Node: n}
}

func pickID(recs []service.NodeRecord, pref string) string {
	n := service.AutoSelectWithPreference(recs, pref)
	if n == nil {
		return ""
	}
	return n.ID
}

// The ruling, proven: at equal latency the preference decides;
// under "auto" the display order (stable latency order) is
// untouched.
func TestAutoSelectPreferenceDecidesNearTies(t *testing.T) {
	recs := []service.NodeRecord{
		tested("trojan-1", specnode.ProtocolTrojan, 100),
		tested("wg-1", specnode.ProtocolWireGuard, 100),
	}
	if got := pickID(recs, service.ProtocolPrefAuto); got != "trojan-1" {
		t.Errorf("auto: got %q, want trojan-1 (display order at equal latency)", got)
	}
	if got := pickID(recs, service.ProtocolPrefSpeed); got != "wg-1" {
		t.Errorf("speed: got %q, want wg-1 (fast class wins the tie)", got)
	}
	if got := pickID(recs, service.ProtocolPrefCompat); got != "trojan-1" {
		t.Errorf("compat: got %q, want trojan-1 (traditional class wins the tie)", got)
	}
}

// A clearly faster node still wins under a preference: the class
// only breaks near-ties (one 25 ms bucket), it does not override
// a full bucket of latency.
func TestAutoSelectPreferenceYieldsToClearLatency(t *testing.T) {
	recs := []service.NodeRecord{
		tested("wg-slow", specnode.ProtocolWireGuard, 200),
		tested("trojan-fast", specnode.ProtocolTrojan, 100),
	}
	if got := pickID(recs, service.ProtocolPrefSpeed); got != "trojan-fast" {
		t.Errorf("speed: got %q, want trojan-fast (100 ms beats 200 ms regardless of class)", got)
	}
	// Near-tie inside one bucket: 100 vs 115 — class decides.
	recs = []service.NodeRecord{
		tested("trojan-115", specnode.ProtocolTrojan, 115),
		tested("wg-100", specnode.ProtocolWireGuard, 100),
	}
	if got := pickID(recs, service.ProtocolPrefCompat); got != "trojan-115" {
		t.Errorf("compat near-tie: got %q, want trojan-115 (same bucket, traditional first)", got)
	}
}

// The frozen weak-encryption demotion outranks any preference: a
// fast weak node never beats a non-weak node.
func TestAutoSelectPreferenceNeverPromotesWeak(t *testing.T) {
	weak := tested("ss-weak", specnode.ProtocolShadowsocks, 50)
	weak.Node.Shadowsocks.Method = "rc4-md5"
	recs := []service.NodeRecord{
		weak,
		tested("wg-1", specnode.ProtocolWireGuard, 100),
	}
	if got := pickID(recs, service.ProtocolPrefSpeed); got != "wg-1" {
		t.Errorf("speed: got %q, want wg-1 (weak demotion beats preference)", got)
	}
	if got := pickID(recs, service.ProtocolPrefCompat); got != "wg-1" {
		t.Errorf("compat: got %q, want wg-1 (weak demotion beats preference)", got)
	}
}

// Preference fallback: with no candidate of the preferred class
// the ranking falls back to latency order (the UI notes this
// case; the selection itself must still work).
func TestAutoSelectPreferenceFallbackWithoutClass(t *testing.T) {
	recs := []service.NodeRecord{
		tested("trojan-150", specnode.ProtocolTrojan, 150),
		tested("trojan-120", specnode.ProtocolTrojan, 120),
	}
	if got := pickID(recs, service.ProtocolPrefSpeed); got != "trojan-120" {
		t.Errorf("speed fallback: got %q, want trojan-120 (lowest latency)", got)
	}
}

// The preference is persisted in Settings and read back by the
// service (the settings page writes exactly this).
func TestProtocolPrefPersistence(t *testing.T) {
	svc, store := newTestService(t, nil)
	if got := svc.ProtocolPref(); got != service.ProtocolPrefAuto {
		t.Errorf("default pref = %q, want auto", got)
	}
	svc.SetProtocolPref(service.ProtocolPrefSpeed)
	if got := svc.ProtocolPref(); got != service.ProtocolPrefSpeed {
		t.Errorf("after set: pref = %q, want speed", got)
	}
	if got := store.Settings().ProtocolPref; got != service.ProtocolPrefSpeed {
		t.Errorf("stored pref = %q, want speed", got)
	}
	svc.SetProtocolPref("bogus")
	if got := svc.ProtocolPref(); got != service.ProtocolPrefAuto {
		t.Errorf("bogus pref normalized to %q, want auto", got)
	}
}

// AutoSelectAndConnect honors the persisted preference: with the
// fake engine scripting equal latencies, "speed" connects the
// WireGuard node while "auto" connects the first-listed one.
func TestAutoSelectAndConnectUsesPreference(t *testing.T) {
	svc, store := newTestService(t, &fakeEngine{latency: map[string]time.Duration{
		"trojan-1": 100 * time.Millisecond,
		"wg-1":     100 * time.Millisecond,
	}})
	for _, rec := range []service.NodeRecord{
		tested("trojan-1", specnode.ProtocolTrojan, 100),
		tested("wg-1", specnode.ProtocolWireGuard, 100),
	} {
		store.AddNode(rec.Node, nil)
		lt := rec.Node.LastTest
		store.SetLastTest(rec.Node.ID, lt)
	}
	_ = store.Save()

	n, err := svc.AutoSelectAndConnect(context.Background(), service.AllGroups)
	if err != nil {
		t.Fatalf("auto connect: %v", err)
	}
	if n.ID != "trojan-1" {
		t.Errorf("auto pref connected %q, want trojan-1", n.ID)
	}
	_ = svc.Disconnect(context.Background())

	svc.SetProtocolPref(service.ProtocolPrefSpeed)
	n, err = svc.AutoSelectAndConnect(context.Background(), service.AllGroups)
	if err != nil {
		t.Fatalf("speed connect: %v", err)
	}
	if n.ID != "wg-1" {
		t.Errorf("speed pref connected %q, want wg-1", n.ID)
	}
}

// Favorites persist on the record and surface through NodeView.
func TestNodeFavoritePersists(t *testing.T) {
	svc, store := newTestService(t, nil)
	rec := tested("fav-1", specnode.ProtocolTrojan, 100)
	store.AddNode(rec.Node, nil)
	_ = store.Save()

	svc.SetNodeFavorite("fav-1", true)
	views := svc.Nodes(service.AllGroups)
	if len(views) != 1 || !views[0].Favorite {
		t.Fatalf("view favorite = %+v, want starred", views)
	}
	got, ok := store.NodeByID("fav-1")
	if !ok || !got.Favorite {
		t.Errorf("stored favorite = %v (ok=%v), want true", got.Favorite, ok)
	}
	svc.SetNodeFavorite("fav-1", false)
	got, _ = store.NodeByID("fav-1")
	if got.Favorite {
		t.Error("favorite still set after unstar")
	}
}

// Error chain: a failed subscription fetch returns an error AND
// leaves the reason in the local log (the banner tells the user
// to look there).
func TestSubscriptionFetchFailureIsLogged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	svc, _ := newTestService(t, nil)
	if _, err := svc.ImportSubscriptionURL(context.Background(), srv.URL, "x"); err == nil {
		t.Fatal("expected fetch error")
	}
	found := false
	for _, line := range svc.Logs().Lines() {
		if strings.Contains(line, "subscription") && strings.Contains(line, "500") {
			found = true
		}
	}
	if !found {
		t.Errorf("log lines = %v, want a subscription fetch failure with the HTTP status", svc.Logs().Lines())
	}
}

// Error chain: import failures keep their parser codes in the
// log, and LogFailure records UI-originated failures.
func TestImportFailureAndLogFailureAreLogged(t *testing.T) {
	svc, _ := newTestService(t, nil)
	rep := svc.ImportText("ss://not-a-valid-link")
	if len(rep.Failed) == 0 {
		t.Fatalf("expected a failed import, got %+v", rep)
	}
	code := rep.Failed[0].Code
	joined := strings.Join(svc.Logs().Lines(), "\n")
	if !strings.Contains(joined, code) {
		t.Errorf("log does not carry the failure code %q: %q", code, joined)
	}
	svc.LogFailure("import-file", context.DeadlineExceeded)
	joined = strings.Join(svc.Logs().Lines(), "\n")
	if !strings.Contains(joined, "import-file") {
		t.Errorf("LogFailure line missing: %q", joined)
	}
}
