package vpngate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openproxy/core/parsers"
)

// Fetch-layer constants. The real official CSV is ~1.3 MB; the
// cap leaves generous headroom while bounding poisoned or
// runaway responses (book 7.2/9: bounded, validated intake).
const (
	DefaultMaxResponseBytes = 8 << 20 // 8 MiB
	DefaultAttemptTimeout   = 20 * time.Second
	DefaultCacheTTL         = time.Hour // mirrors manifest.updateIntervalMinutes
)

// ErrInvalidPayload marks a response that is not a plausible
// VPN Gate CSV (wrong shape, or parses to zero usable nodes).
// Such a response is never cached and never served: the fetcher
// rotates to the next endpoint instead (anti-poisoning).
var ErrInvalidPayload = errors.New("vpngate: response failed CSV validation")

// FetchError aggregates per-endpoint failures when every
// endpoint in the rotation failed.
type FetchError struct{ Attempts []error }

func (e *FetchError) Error() string {
	parts := make([]string, len(e.Attempts))
	for i, err := range e.Attempts {
		parts[i] = err.Error()
	}
	return "vpngate: all endpoints failed: " + strings.Join(parts, "; ")
}

// ListInfo is the freshness label every catalog carries to the
// upper layers (book 7.3 / task: freshness must be presented,
// stale cache must never masquerade as fresh data).
type ListInfo struct {
	FetchedAt time.Time // when the payload was fetched from the network
	Endpoint  string    // endpoint that produced the payload
	FromCache bool      // payload came from the local cache
	Stale     bool      // cache is past TTL or a refresh just failed
	LastError string    // refresh failure detail when Stale due to an error
}

// Cache stores the last validated payload plus its metadata.
type Cache interface {
	Load() (payload []byte, info ListInfo, err error) // (nil, _, nil) when empty
	Save(payload []byte, info ListInfo) error
	Purge() error
}

// ---------------------------------------------------------------------------
// File cache
// ---------------------------------------------------------------------------

type cacheMeta struct {
	FetchedAt time.Time `json:"fetchedAt"`
	Endpoint  string    `json:"endpoint"`
}

// FileCache keeps payload and metadata as two files in a
// directory. Disabling the plugin purges both (book 7.2
// self-check: disable means cache deleted).
type FileCache struct{ Dir string }

func (c *FileCache) payloadPath() string { return filepath.Join(c.Dir, "vpngate-list.csv") }
func (c *FileCache) metaPath() string    { return filepath.Join(c.Dir, "vpngate-list.meta.json") }

func (c *FileCache) Load() ([]byte, ListInfo, error) {
	metaBytes, err := os.ReadFile(c.metaPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ListInfo{}, nil
	}
	if err != nil {
		return nil, ListInfo{}, err
	}
	var meta cacheMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, ListInfo{}, fmt.Errorf("vpngate: cache meta corrupt: %w", err)
	}
	payload, err := os.ReadFile(c.payloadPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ListInfo{}, nil
	}
	if err != nil {
		return nil, ListInfo{}, err
	}
	return payload, ListInfo{FetchedAt: meta.FetchedAt, Endpoint: meta.Endpoint, FromCache: true}, nil
}

func (c *FileCache) Save(payload []byte, info ListInfo) error {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(c.payloadPath(), payload, 0o600); err != nil {
		return err
	}
	meta, _ := json.Marshal(cacheMeta{FetchedAt: info.FetchedAt, Endpoint: info.Endpoint})
	return os.WriteFile(c.metaPath(), meta, 0o600)
}

func (c *FileCache) Purge() error {
	var firstErr error
	for _, p := range []string{c.payloadPath(), c.metaPath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---------------------------------------------------------------------------
// Fetcher with mirror rotation
// ---------------------------------------------------------------------------

// Fetcher downloads the official CSV, rotating over the
// endpoint list (book 7.3: mirror rotation). Each endpoint gets
// exactly one attempt per refresh — rotation IS the retry
// strategy, so a dead mirror cannot stall the list for long.
type Fetcher struct {
	Endpoints      []string
	Client         *http.Client // nil means a default client
	AttemptTimeout time.Duration
	MaxBytes       int64
	Cache          Cache // nil disables caching
	TTL            time.Duration
	Now            func() time.Time // test seam; nil means time.Now
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Fetcher) httpClient() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{}
}

func (f *Fetcher) ttl() time.Duration {
	if f.TTL > 0 {
		return f.TTL
	}
	return DefaultCacheTTL
}

// Fetch returns a validated payload and its freshness label.
//
// Semantics:
//   - A fresh cache entry (age < TTL) is served without network
//     traffic unless force is set, labelled FromCache, not stale.
//   - Otherwise endpoints are tried in order; the first payload
//     passing validation wins, replaces the cache, and is
//     labelled fresh.
//   - If every endpoint fails, a cache entry (however old) is
//     served labelled Stale with LastError set — never as fresh.
//   - With no cache, the aggregated FetchError is returned.
func (f *Fetcher) Fetch(ctx context.Context, force bool) ([]byte, ListInfo, error) {
	var cached []byte
	var cachedInfo ListInfo
	if f.Cache != nil {
		payload, info, err := f.Cache.Load()
		if err != nil {
			return nil, ListInfo{}, err
		}
		cached, cachedInfo = payload, info
		if cached != nil && !force && f.now().Sub(cachedInfo.FetchedAt) < f.ttl() {
			return cached, cachedInfo, nil
		}
	}

	attempts := make([]error, 0, len(f.Endpoints))
	for _, ep := range f.Endpoints {
		payload, err := f.fetchOne(ctx, ep)
		if err != nil {
			attempts = append(attempts, fmt.Errorf("%s: %w", ep, err))
			continue
		}
		info := ListInfo{FetchedAt: f.now(), Endpoint: ep}
		if f.Cache != nil {
			if err := f.Cache.Save(payload, info); err != nil {
				return nil, ListInfo{}, fmt.Errorf("vpngate: cache save: %w", err)
			}
		}
		return payload, info, nil
	}

	ferr := &FetchError{Attempts: attempts}
	if cached != nil {
		cachedInfo.Stale = true
		cachedInfo.LastError = ferr.Error()
		return cached, cachedInfo, nil
	}
	return nil, ListInfo{}, ferr
}

func (f *Fetcher) fetchOne(ctx context.Context, endpoint string) ([]byte, error) {
	timeout := f.AttemptTimeout
	if timeout <= 0 {
		timeout = DefaultAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Relavia-VPNGate-Plugin/1.0 (+https://www.vpngate.net/en/)")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	max := f.MaxBytes
	if max <= 0 {
		max = DefaultMaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidPayload, max)
	}
	if err := ValidatePayload(body); err != nil {
		return nil, err
	}
	return body, nil
}

// ValidatePayload is the anti-poisoning gate every downloaded
// (and cached) payload must pass before it is parsed into
// nodes: shape markers of the official CSV, then a real parse
// via the Step 8 parser yielding at least one usable node and
// the grade-A source registration.
func ValidatePayload(body []byte) error {
	s := string(body)
	if !strings.Contains(s, "*vpn_servers") || !strings.Contains(s, "OpenVPN_ConfigData_Base64") {
		return fmt.Errorf("%w: missing VPN Gate CSV markers", ErrInvalidPayload)
	}
	res := parsers.ParseVPNGateCSV(s, parsers.Options{})
	if res.SourceRecord == nil {
		return fmt.Errorf("%w: no source registration produced", ErrInvalidPayload)
	}
	usable := 0
	for _, item := range res.Items {
		if item.Node != nil {
			usable++
		}
	}
	if usable == 0 {
		return fmt.Errorf("%w: parses to zero usable nodes", ErrInvalidPayload)
	}
	return nil
}
