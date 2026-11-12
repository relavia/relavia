package vpngate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type memStore struct{ rec *consentRecord }

func (s *memStore) Load() (*consentRecord, error) { return s.rec, nil }
func (s *memStore) Save(r *consentRecord) error   { s.rec = r; return nil }
func (s *memStore) Clear() error                  { s.rec = nil; return nil }

func TestConsentGateBlocksUntilAcknowledged(t *testing.T) {
	c, err := NewConsent(&memStore{})
	if err != nil {
		t.Fatal(err)
	}
	if c.State() != ConsentNone {
		t.Fatalf("initial state = %v, want None", c.State())
	}
	if err := c.Require(); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("Require before ack: %v", err)
	}
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	if err := c.Acknowledge(now); err != nil {
		t.Fatal(err)
	}
	if c.State() != ConsentAcknowledged || c.Require() != nil {
		t.Fatalf("after ack: state=%v require=%v", c.State(), c.Require())
	}
	if !c.AcknowledgedAt().Equal(now) {
		t.Fatalf("ack time = %v", c.AcknowledgedAt())
	}
	// Revocation closes the gate again.
	if err := c.Revoke(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c.State() != ConsentRevoked {
		t.Fatalf("after revoke: state=%v", c.State())
	}
	if err := c.Require(); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("Require after revoke: %v", err)
	}
	// A fresh acknowledgement after revocation re-opens the gate.
	if err := c.Acknowledge(now.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c.State() != ConsentAcknowledged {
		t.Fatalf("after re-ack: state=%v", c.State())
	}
}

func TestConsentStaleOnTextVersionBump(t *testing.T) {
	store := &memStore{rec: &consentRecord{
		Acknowledged: true, TextVersion: "vpngate-risk-v0-old", At: time.Now(),
	}}
	c, err := NewConsent(store)
	if err != nil {
		t.Fatal(err)
	}
	if c.State() != ConsentStale {
		t.Fatalf("state = %v, want Stale for old wording", c.State())
	}
	if err := c.Require(); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("stale consent must not open the gate: %v", err)
	}
}

func TestFileConsentStoreRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "consent.json")
	c1, err := NewConsent(&FileConsentStore{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Acknowledge(time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec consentRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.TextVersion != RiskTextVersion {
		t.Fatalf("persisted record: %+v err=%v", rec, err)
	}
	c2, err := NewConsent(&FileConsentStore{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if c2.State() != ConsentAcknowledged {
		t.Fatalf("reloaded state = %v", c2.State())
	}
}
