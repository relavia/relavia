package vpngate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func samplePayload(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/vpngate-sample-2026-11-12.csv")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	return data
}

func server(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestRotationSkipsBadEndpoints(t *testing.T) {
	payload := samplePayload(t)
	s500 := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	sGarbage := server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>portal</title></head><body>login</body></html>"))
	})
	sGood := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })

	f := &Fetcher{Endpoints: []string{s500.URL, sGarbage.URL, sGood.URL}}
	body, info, err := f.Fetch(context.Background(), false)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(payload) {
		t.Fatalf("payload mismatch")
	}
	if info.Endpoint != sGood.URL || info.Stale || info.FromCache {
		t.Fatalf("info = %+v, want fresh from good endpoint", info)
	}
}

func TestRotationAllFailNoCache(t *testing.T) {
	s500 := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	f := &Fetcher{Endpoints: []string{s500.URL}}
	_, _, err := f.Fetch(context.Background(), false)
	var ferr *FetchError
	if !errors.As(err, &ferr) {
		t.Fatalf("err = %v, want FetchError", err)
	}
	if len(ferr.Attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(ferr.Attempts))
	}
}

func TestOversizeResponseRejected(t *testing.T) {
	payload := samplePayload(t)
	sBig := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	f := &Fetcher{Endpoints: []string{sBig.URL}, MaxBytes: 1024}
	_, _, err := f.Fetch(context.Background(), false)
	var ferr *FetchError
	if !errors.As(err, &ferr) || !strings.Contains(ferr.Error(), "exceeds") {
		t.Fatalf("err = %v, want size-cap FetchError", err)
	}
}

func TestValidatePayloadRejectsPoison(t *testing.T) {
	if err := ValidatePayload([]byte("<html>definitely not a csv</html>")); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("html: err = %v", err)
	}
	// Right markers, but the embedded configs are undecodable:
	poison := "*vpn_servers\n#HostName,IP,CountryShort,OpenVPN_ConfigData_Base64\nhost1,1.2.3.4,JP,!!!not-base64!!!\n"
	if err := ValidatePayload([]byte(poison)); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("poison rows: err = %v", err)
	}
	if err := ValidatePayload(samplePayload(t)); err != nil {
		t.Fatalf("real sample must validate: %v", err)
	}
}

func TestCacheFreshnessSemantics(t *testing.T) {
	payload := samplePayload(t)
	dir := t.TempDir()
	cache := &FileCache{Dir: dir}
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	good := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	f := &Fetcher{
		Endpoints: []string{good.URL},
		Cache:     cache,
		TTL:       time.Hour,
		Now:       func() time.Time { return now },
	}
	// First fetch populates the cache.
	if _, info, err := f.Fetch(context.Background(), false); err != nil || info.FromCache {
		t.Fatalf("first fetch: info=%+v err=%v", info, err)
	}
	// Within TTL the cache is served without touching the network:
	// point the fetcher at a dead endpoint to prove it.
	f.Endpoints = []string{"http://127.0.0.1:1/dead"}
	body, info, err := f.Fetch(context.Background(), false)
	if err != nil || !info.FromCache || info.Stale || string(body) != string(payload) {
		t.Fatalf("fresh cache: info=%+v err=%v", info, err)
	}
	// Past TTL with the network down: stale cache, clearly labelled,
	// never presented as fresh.
	now = now.Add(2 * time.Hour)
	body, info, err = f.Fetch(context.Background(), false)
	if err != nil {
		t.Fatalf("stale fallback must not error: %v", err)
	}
	if !info.Stale || !info.FromCache || info.LastError == "" || string(body) != string(payload) {
		t.Fatalf("stale cache: info=%+v", info)
	}
	if !info.FetchedAt.Equal(now.Add(-2 * time.Hour)) {
		t.Fatalf("stale info must keep the original fetch time, got %v", info.FetchedAt)
	}
	// Purge removes everything (disable semantics).
	if err := cache.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, _, err := f.Fetch(context.Background(), false); err == nil {
		t.Fatalf("after purge with dead network the fetch must fail")
	}
}
