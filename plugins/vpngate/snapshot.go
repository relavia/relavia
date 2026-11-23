package vpngate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"
)

// Bundled list snapshot (bootstrap fallback, 2026-11-23).
//
// The pool has a bootstrap problem in restricted networks: the
// list itself is fetched from vpngate.net, so a fresh install
// that cannot reach the official endpoints gets no list at all
// — it needs to be out to get the list to get out. The official
// CSV is public data the project is authorized to redistribute
// for client use (book 7.1 grade A), so a snapshot of it ships
// inside the app as the last-resort list source.
//
// Honesty rules for this fallback:
//   - it is served ONLY when every endpoint failed and no
//     cache exists (a user's own last fetch always wins);
//   - it is never written into the fetch cache — it is app
//     data, not user data, and Disable's cache purge neither
//     needs nor gets to delete it;
//   - every catalog built from it is labelled FromSnapshot
//     with the capture date, and Stale: it must never
//     masquerade as a live list;
//   - it passes the same anti-poisoning validation as any
//     downloaded payload, at load time, every time.
//
// Refresh procedure: snapshot/refresh-snapshot.sh, run before
// each release (see docs/step15 release checklist).

//go:embed snapshot/vpngate-list.csv
var bundledSnapshotCSV []byte

//go:embed snapshot/meta.json
var bundledSnapshotMetaJSON []byte

type snapshotMeta struct {
	CapturedAt time.Time `json:"capturedAt"`
	Source     string    `json:"source"`
}

// BundledSnapshot returns the build-time copy of the official
// list and the moment it was captured from the official
// endpoint. The payload is validated on every call: a corrupt
// embedded snapshot is an error, never a list.
func BundledSnapshot() ([]byte, time.Time, error) {
	var meta snapshotMeta
	if err := json.Unmarshal(bundledSnapshotMetaJSON, &meta); err != nil {
		return nil, time.Time{}, fmt.Errorf("vpngate: bundled snapshot meta corrupt: %w", err)
	}
	if meta.CapturedAt.IsZero() {
		return nil, time.Time{}, fmt.Errorf("vpngate: bundled snapshot meta has no capture date")
	}
	if err := ValidatePayload(bundledSnapshotCSV); err != nil {
		return nil, time.Time{}, fmt.Errorf("vpngate: bundled snapshot invalid: %w", err)
	}
	return bundledSnapshotCSV, meta.CapturedAt, nil
}
