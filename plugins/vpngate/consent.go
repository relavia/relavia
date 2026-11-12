package vpngate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrConsentRequired is returned whenever an operation needs an
// active risk acknowledgement the user has not given (or has
// revoked, or given for an older risk text version).
var ErrConsentRequired = errors.New("vpngate: risk disclosure not acknowledged (book 7.3: unacknowledged means not enabled)")

// ConsentState is the acknowledgement state of the mandatory
// VPN Gate risk disclosure.
type ConsentState int

const (
	// ConsentNone: the disclosure was never acknowledged.
	ConsentNone ConsentState = iota
	// ConsentAcknowledged: acknowledged for the CURRENT risk
	// text version; the source may be enabled.
	ConsentAcknowledged
	// ConsentRevoked: previously acknowledged, then revoked by
	// the user; the source must be disabled and stays disabled
	// until a fresh acknowledgement.
	ConsentRevoked
	// ConsentStale: acknowledged, but for an older risk text
	// version; treated as not acknowledged until re-confirmed.
	ConsentStale
)

// consentRecord is the persisted form of the acknowledgement.
type consentRecord struct {
	Acknowledged bool      `json:"acknowledged"`
	Revoked      bool      `json:"revoked"`
	TextVersion  string    `json:"textVersion"`
	At           time.Time `json:"at"`
}

// ConsentStore persists the acknowledgement record. The plugin
// ships a file-backed implementation; the app may substitute
// its own storage without changing the state machine.
type ConsentStore interface {
	Load() (*consentRecord, error) // (nil, nil) when nothing stored
	Save(rec *consentRecord) error
	Clear() error
}

// Consent is the risk-acknowledgement state machine of book 7.3.
//
// Transitions:
//   - Acknowledge: None/Revoked/Stale -> Acknowledged(current
//     text version, timestamped).
//   - Revoke: any -> Revoked; revoking also disables the source
//     and purges the fetch cache (wired in Plugin.Disable).
//   - A risk text version bump turns Acknowledged into Stale on
//     read: old acknowledgements never carry over to new wording.
type Consent struct {
	mu    sync.Mutex
	store ConsentStore
	rec   *consentRecord
}

// NewConsent loads the persisted state (empty state when the
// store holds nothing).
func NewConsent(store ConsentStore) (*Consent, error) {
	rec, err := store.Load()
	if err != nil {
		return nil, err
	}
	return &Consent{store: store, rec: rec}, nil
}

// State reports the effective state, folding version staleness
// into the result.
func (c *Consent) State() ConsentState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateLocked()
}

func (c *Consent) stateLocked() ConsentState {
	if c.rec == nil || (!c.rec.Acknowledged && !c.rec.Revoked) {
		return ConsentNone
	}
	if c.rec.Revoked {
		return ConsentRevoked
	}
	if c.rec.TextVersion != RiskTextVersion {
		return ConsentStale
	}
	return ConsentAcknowledged
}

// AcknowledgedAt returns when the current acknowledgement was
// given (zero when not acknowledged).
func (c *Consent) AcknowledgedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stateLocked() != ConsentAcknowledged {
		return time.Time{}
	}
	return c.rec.At
}

// Acknowledge records that the user has read and accepted the
// current risk text.
func (c *Consent) Acknowledge(at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := &consentRecord{Acknowledged: true, TextVersion: RiskTextVersion, At: at}
	if err := c.store.Save(rec); err != nil {
		return err
	}
	c.rec = rec
	return nil
}

// Revoke withdraws the acknowledgement. The source must be
// disabled afterwards; Plugin.Disable performs the full
// revoke + cache purge sequence.
func (c *Consent) Revoke(at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := &consentRecord{Revoked: true, TextVersion: RiskTextVersion, At: at}
	if err := c.store.Save(rec); err != nil {
		return err
	}
	c.rec = rec
	return nil
}

// Require returns ErrConsentRequired unless the current state
// is ConsentAcknowledged. Every enabling operation calls it.
func (c *Consent) Require() error {
	if c.State() != ConsentAcknowledged {
		return ErrConsentRequired
	}
	return nil
}

// ---------------------------------------------------------------------------
// File-backed consent store
// ---------------------------------------------------------------------------

// FileConsentStore keeps the record as a small JSON file inside
// the plugin's state directory (local only, never synced:
// book 3.2 local-first).
type FileConsentStore struct{ Path string }

func (s *FileConsentStore) Load() (*consentRecord, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec consentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("vpngate: consent record corrupt: %w", err)
	}
	return &rec, nil
}

func (s *FileConsentStore) Save(rec *consentRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func (s *FileConsentStore) Clear() error {
	err := os.Remove(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
