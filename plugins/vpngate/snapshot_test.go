package vpngate

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

var snapshotTestDate = time.Date(2026, 11, 23, 5, 28, 48, 0, time.UTC)

func deadServer(t *testing.T) string {
	t.Helper()
	return server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }).URL
}

func TestFetchFallsBackToBundledSnapshot(t *testing.T) {
	payload := samplePayload(t)
	f := &Fetcher{
		Endpoints: []string{deadServer(t)},
		FallbackSnapshot: func() ([]byte, time.Time, error) {
			return payload, snapshotTestDate, nil
		},
	}
	body, info, err := f.Fetch(context.Background(), true)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	if !info.FromSnapshot {
		t.Fatalf("info = %+v, want FromSnapshot", info)
	}
	if !info.SnapshotAt.Equal(snapshotTestDate) || !info.FetchedAt.Equal(snapshotTestDate) {
		t.Fatalf("info times = %+v, want capture date %v", info, snapshotTestDate)
	}
	if !info.Stale || info.LastError == "" {
		t.Fatalf("snapshot must be labelled stale with the failure detail: %+v", info)
	}
	if info.FromCache {
		t.Fatalf("snapshot must not pose as cache: %+v", info)
	}
}

func TestFetchPrefersLiveOverSnapshot(t *testing.T) {
	payload := samplePayload(t)
	good := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	f := &Fetcher{
		Endpoints: []string{good.URL},
		FallbackSnapshot: func() ([]byte, time.Time, error) {
			return payload, snapshotTestDate, nil
		},
	}
	_, info, err := f.Fetch(context.Background(), true)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if info.FromSnapshot || info.Stale || info.Endpoint != good.URL {
		t.Fatalf("info = %+v, want fresh live fetch", info)
	}
}

func TestFetchPrefersStaleCacheOverSnapshot(t *testing.T) {
	payload := samplePayload(t)
	cache := &FileCache{Dir: t.TempDir()}
	old := time.Now().Add(-2 * DefaultCacheTTL)
	if err := cache.Save(payload, ListInfo{FetchedAt: old, Endpoint: "https://example.invalid/"}); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{
		Endpoints: []string{deadServer(t)},
		Cache:     cache,
		FallbackSnapshot: func() ([]byte, time.Time, error) {
			return payload, snapshotTestDate, nil
		},
	}
	body, info, err := f.Fetch(context.Background(), true)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	if info.FromSnapshot || !info.FromCache || !info.Stale {
		t.Fatalf("info = %+v, want the user's own stale cache, not the snapshot", info)
	}
}

func TestFetchInvalidSnapshotRejected(t *testing.T) {
	f := &Fetcher{
		Endpoints: []string{deadServer(t)},
		FallbackSnapshot: func() ([]byte, time.Time, error) {
			return []byte("<html>not a csv</html>"), snapshotTestDate, nil
		},
	}
	_, _, err := f.Fetch(context.Background(), true)
	var ferr *FetchError
	if !errors.As(err, &ferr) || !strings.Contains(ferr.Error(), "bundled snapshot") {
		t.Fatalf("err = %v, want FetchError naming the snapshot failure", err)
	}
}

func TestBundledSnapshotValid(t *testing.T) {
	payload, capturedAt, err := BundledSnapshot()
	if err != nil {
		t.Fatalf("BundledSnapshot: %v", err)
	}
	if capturedAt.Year() != 2026 || capturedAt.Month() != 11 || capturedAt.Day() != 23 {
		t.Fatalf("capture date = %v, want 2026-11-23", capturedAt)
	}
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	cat, err := BuildCatalog(payload, ListInfo{FromSnapshot: true, SnapshotAt: capturedAt}, m)
	if err != nil {
		t.Fatalf("BuildCatalog(snapshot): %v", err)
	}
	if len(cat.Nodes) < 50 {
		t.Fatalf("snapshot catalog has %d nodes, want a real full list (>= 50)", len(cat.Nodes))
	}
	if len(cat.Groups) < 3 {
		t.Fatalf("snapshot catalog has %d groups, want several countries", len(cat.Groups))
	}
}

func TestNewDefaultWiresSnapshotFallback(t *testing.T) {
	p, err := NewDefault(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if p.Fetcher.FallbackSnapshot == nil {
		t.Fatal("production wiring must arm the bundled snapshot fallback")
	}
}
