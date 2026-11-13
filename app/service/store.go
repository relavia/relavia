package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"openproxy/core/specnode"
)

// Persistence for the service layer.
//
// STEP 13 SCOPE (landed): the on-disk codec for Store's Document
// is the versioned envelope in secure.go — Argon2id +
// XChaCha20-Poly1305 encrypted when the user sets a passphrase,
// plaintext with an explicit degraded marker when they choose
// not to (book 5.5). Pre-Step-13 bare JSON files are detected at
// open and migrated on the first encrypted save, with the
// plaintext overwritten only after the sealed replacement is
// durably written (a failed migration leaves the original file
// byte-identical). Callers (cmd, UI, Android shell) keep the
// exact Step 9 API; the lock lifecycle (Unlock / Lock /
// SetPassphrase / Protection) is additive. Node credentials are
// secrets (book 9.1); the file is written 0600 inside the user's
// config directory and never leaves the device except through
// the passphrase-encrypted backup export (book 3.2, local-first).

// NodeRecord is one stored node plus its import-time warning
// codes (parser warning codes from package parsers).
type NodeRecord struct {
	Node     *specnode.Node `json:"node"`
	Warnings []string       `json:"warnings,omitempty"`
	AddedAt  string         `json:"addedAt,omitempty"`
	// Admission is the source-plugin admission level recorded
	// for plugin-sourced nodes (plugins/vpngate levels:
	// "tcp-connect", "handshake-verified", "none"). It is the
	// level actually established for this node, never a claim:
	// a node whose reachability probe failed keeps "none".
	// Empty for user-imported nodes (no admission concept).
	Admission string `json:"admission,omitempty"`
	// Favorite is the user's star on the node row (2026-11-14
	// design ruling): a plain bookmark flag, persisted with the
	// record so it survives restarts. It carries no ranking or
	// selection semantics.
	Favorite bool `json:"favorite,omitempty"`
}

// SubscriptionRecord is the stored registration of one imported
// subscription (the subscription itself lives in the core model's
// terms; this is the client's local bookkeeping).
type SubscriptionRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Format        string `json:"format,omitempty"`
	GroupName     string `json:"groupName,omitempty"`
	LastUpdatedAt string `json:"lastUpdatedAt,omitempty"`
}

// Settings are the persisted client preferences.
type Settings struct {
	Language       string `json:"language,omitempty"`
	Mode           string `json:"mode,omitempty"` // kernel RunMode; default "manual"
	// ProtocolPref is the auto-select protocol preference
	// (2026-11-14 design ruling): "" / "auto" (by latency),
	// "speed" (fast protocols win near-ties), "compat"
	// (traditional protocols win near-ties). Consumed by
	// AutoSelectAndConnect; see autoselect.go.
	ProtocolPref string `json:"protocolPref,omitempty"`
	SelectedNodeID string `json:"selectedNodeId,omitempty"`
	SelectedGroup  string `json:"selectedGroup,omitempty"`

	// Update mechanism (Step 16, docs/relavia-update-v1.md).
	// UpdateChannel is "stable" (default) or "beta".
	// UpdateAutoCheck is the periodic-check opt-in (default
	// false: the client never fetches update metadata unless the
	// user asks or opts in). The Seen* maps are the anti-rollback
	// anchors per channel; UpdateLastCheck is RFC 3339. All of it
	// is local-only bookkeeping, never transmitted.
	UpdateChannel       string            `json:"updateChannel,omitempty"`
	UpdateAutoCheck     bool              `json:"updateAutoCheck,omitempty"`
	UpdateSeenSeq       map[string]int64  `json:"updateSeenSeq,omitempty"`
	UpdateSeenPublished map[string]string `json:"updateSeenPublished,omitempty"`
	UpdateLastCheck     string            `json:"updateLastCheck,omitempty"`

	// VPN Gate source bookkeeping (last refresh outcome, kept so
	// the sources view can label freshness honestly across
	// restarts; the plugin's own cache remains the data source).
	// VPNGateLastRefresh is RFC 3339; VPNGateStale marks that the
	// freshest refresh attempt failed and the nodes on display
	// are the previous snapshot.
	VPNGateLastRefresh string `json:"vpngateLastRefresh,omitempty"`
	VPNGateStale       bool   `json:"vpngateStale,omitempty"`
	VPNGateLastError   string `json:"vpngateLastError,omitempty"`
}

// Document is the on-disk store document.
type Document struct {
	Version       int                  `json:"version"`
	Nodes         []NodeRecord         `json:"nodes"`
	Groups        []string             `json:"groups"` // explicit group display order
	Subscriptions []SubscriptionRecord `json:"subscriptions"`
	Settings      Settings             `json:"settings"`
}

const storeVersion = 1

// Store is a concurrency-safe document store. In passphrase
// mode a locked Store holds an empty in-memory Document: data
// accessors return zero values and Save refuses with
// ErrStoreLocked until Unlock succeeds, so a locked store can
// neither leak nor overwrite the sealed data.
type Store struct {
	mu   sync.Mutex
	path string
	doc  Document
	sec  secState
}

// DefaultStorePath returns <UserConfigDir>/Relavia/store.json.
func DefaultStorePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Relavia", "store.json"), nil
}

// OpenStore loads the store at path, creating an empty document
// when the file does not exist yet. Three on-disk shapes are
// recognised: the Step 13 envelope (encrypted or degraded
// plaintext), a legacy pre-Step-13 bare JSON document (loaded
// and flagged for migration), and — as a crash-recovery fallback
// when the main file is unreadable — the atomic-write temp file
// next to it. A passphrase-mode file opens Locked: the document
// stays sealed until Unlock.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	s.sec.mode = ModeNone
	s.sec.nowFn = time.Now
	s.sec.lastActivity = time.Now()

	data, err := readStoreBytes(path)
	switch {
	case err == nil:
		if err := s.loadBytesLocked(data); err != nil {
			return nil, err
		}
	case os.IsNotExist(err):
		// Fresh store.
	default:
		return nil, err
	}
	if s.doc.Version == 0 {
		s.doc.Version = storeVersion
	}
	return s, nil
}

// readStoreBytes reads the store file, falling back to the
// atomic-write temp file when the main file is missing or
// unreadable (the crash window of writeFileAtomic, and of the
// migration overwrite protocol). If both exist and the main file
// parses, the temp file is ignored.
func readStoreBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		if probeStoreBytes(data) == nil {
			return data, nil
		}
	}
	tmpData, tmpErr := os.ReadFile(path + ".tmp")
	if tmpErr == nil && len(tmpData) > 0 && probeStoreBytes(tmpData) == nil {
		return tmpData, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return data, nil
	}
	return nil, fmt.Errorf("%w: %s does not parse as a store file", ErrCorruptStore, path)
}

// probeStoreBytes reports whether data is a recognisable store
// file (envelope or legacy document) without decrypting it.
func probeStoreBytes(data []byte) error {
	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if probe.Format == storeFormat {
		var env storeEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return err
		}
		if env.Version > storeEnvVer {
			return fmt.Errorf("%w: store envelope version %d", ErrCorruptStore, env.Version)
		}
		return nil
	}
	var doc Document
	return json.Unmarshal(data, &doc)
}

// loadBytesLocked installs parsed file content into the store.
func (s *Store) loadBytesLocked(data []byte) error {
	var probe struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCorruptStore, s.path, err)
	}
	if probe.Format == storeFormat {
		var env storeEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrCorruptStore, s.path, err)
		}
		s.sec.env = &env
		s.sec.envKDF = env.KDF
		s.sec.envWrapped = env.WrappedKey
		s.sec.envPlatWrapped = env.PlatformWrappedKey
		switch env.Mode {
		case ModePassphrase:
			s.sec.mode = ModePassphrase
			s.sec.locked = true
			s.sec.plainOnDisk = false
			s.doc = Document{}
		case ModeNone:
			s.sec.mode = ModeNone
			s.sec.plainOnDisk = true
			if env.Document != nil {
				s.doc = *env.Document
			}
		default:
			return fmt.Errorf("%w: %s: unknown mode %q", ErrCorruptStore, s.path, env.Mode)
		}
		return nil
	}
	// Legacy bare JSON document (pre-Step-13).
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCorruptStore, s.path, err)
	}
	s.doc = doc
	s.sec.mode = ModeNone
	s.sec.legacy = true
	s.sec.plainOnDisk = true
	return nil
}

// Save persists the document atomically (write temp + fsync +
// rename), with owner-only permissions because it contains
// credentials. A locked store refuses: persisting the empty
// locked-state document would destroy the sealed data.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeAutoLockLocked()
	if s.sec.locked {
		return ErrStoreLocked
	}
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.sec.locked {
		return ErrStoreLocked
	}
	if s.path == "" {
		return nil // in-memory store (tests)
	}
	env, err := s.buildEnvelopeLocked()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	// When this write replaces plaintext credentials with
	// ciphertext (legacy migration / passphrase enablement), the
	// old plaintext bytes are zero-filled before the rename so
	// they do not linger in the freed inode.
	overwrite := s.sec.plainOnDisk && env.Mode == ModePassphrase
	if err := writeFileAtomic(s.path, data, overwrite); err != nil {
		return err
	}
	s.sec.env = env
	s.sec.legacy = false
	s.sec.plainOnDisk = env.Mode == ModeNone
	s.sec.touchLocked()
	return nil
}

// writeFileAtomic writes data to path via temp file + fsync +
// rename, so a crash or concurrent reader never sees a partial
// file and the previous content survives a failed write. With
// overwriteOld, the previous file's bytes are zero-filled and
// fsynced before the rename (best-effort secure erase: SSD wear
// levelling and copy-on-write filesystems can retain blocks
// below the filesystem layer — documented in the Step 13 report,
// not silently promised away).
func writeFileAtomic(path string, data []byte, overwriteOld bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if overwriteOld {
		if old, err := os.OpenFile(path, os.O_WRONLY, 0o600); err == nil {
			if info, err := old.Stat(); err == nil && info.Size() > 0 {
				zeros := make([]byte, 32*1024)
				remaining := info.Size()
				for remaining > 0 {
					n := int64(len(zeros))
					if remaining < n {
						n = remaining
					}
					if _, err := old.Write(zeros[:n]); err != nil {
						break
					}
					remaining -= n
				}
				_ = old.Sync()
			}
			_ = old.Close()
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Snapshot returns a copy of the document for read paths. On a
// locked store this is the empty document — credentials are
// never exposed before Unlock (Step 13 lock semantics).
func (s *Store) Snapshot() Document {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeAutoLockLocked()
	if !s.sec.locked {
		s.sec.touchLocked()
	}
	return s.doc
}

// --- node operations -------------------------------------------------

// AddNode inserts or replaces (by node ID) a record, merging the
// parser-emitted warning codes with the recomputed floor.
func (s *Store) AddNode(n *specnode.Node, warnings []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := NodeRecord{
		Node:     n,
		Warnings: mergeWarnings(warnings, n),
		AddedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.ID == n.ID {
			rec.AddedAt = s.doc.Nodes[i].AddedAt
			// Preserve the recorded admission level across
			// re-import; re-establishing it is the source
			// layer's job (probes / handshake tests).
			rec.Admission = s.doc.Nodes[i].Admission
			// Preserve the freshest handshake result across re-import.
			if rec.Node.LastTest == nil {
				rec.Node.LastTest = s.doc.Nodes[i].Node.LastTest
			}
			s.doc.Nodes[i] = rec
			return
		}
	}
	s.doc.Nodes = append(s.doc.Nodes, rec)
}

// DeleteNode removes a node by ID; reports whether it existed.
func (s *Store) DeleteNode(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.ID == id {
			s.doc.Nodes = append(s.doc.Nodes[:i], s.doc.Nodes[i+1:]...)
			return true
		}
	}
	return false
}

// MoveNode swaps a node with its neighbour (dir -1 = up/display
// earlier, +1 = down) in the global display order.
func (s *Store) MoveNode(id string, dir int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.ID != id {
			continue
		}
		j := i + dir
		if j < 0 || j >= len(s.doc.Nodes) {
			return false
		}
		s.doc.Nodes[i], s.doc.Nodes[j] = s.doc.Nodes[j], s.doc.Nodes[i]
		return true
	}
	return false
}

// NodeByID returns the record for an ID.
func (s *Store) NodeByID(id string) (NodeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.doc.Nodes {
		if rec.Node.ID == id {
			return rec, true
		}
	}
	return NodeRecord{}, false
}

// SetAdmission records the source-plugin admission level
// established for a node (see NodeRecord.Admission).
func (s *Store) SetAdmission(id string, level string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.ID == id {
			s.doc.Nodes[i].Admission = level
			return true
		}
	}
	return false
}

// SetFavorite records the user's star on a node (persisted by
// the caller's Save).
func (s *Store) SetFavorite(id string, fav bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.ID == id {
			s.doc.Nodes[i].Favorite = fav
			return true
		}
	}
	return false
}

// SetLastTest records a handshake outcome on the node (book 5.2
// LastTest) so latency history survives restarts.
func (s *Store) SetLastTest(id string, lt *specnode.LastTest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.ID == id {
			s.doc.Nodes[i].Node.LastTest = lt
			return true
		}
	}
	return false
}

// --- group operations ------------------------------------------------

// GroupNames returns group display order: explicit order first,
// then any group referenced by nodes in first-seen order.
func (s *Store) GroupNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, g := range s.doc.Groups {
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, rec := range s.doc.Nodes {
		g := rec.Node.Group
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// AddGroup registers a group name (idempotent).
func (s *Store) AddGroup(name string) {
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.doc.Groups {
		if g == name {
			return
		}
	}
	s.doc.Groups = append(s.doc.Groups, name)
}

// DeleteGroup unregisters a group and ungroups its nodes.
func (s *Store) DeleteGroup(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.doc.Groups[:0]
	for _, g := range s.doc.Groups {
		if g != name {
			out = append(out, g)
		}
	}
	s.doc.Groups = out
	for i := range s.doc.Nodes {
		if s.doc.Nodes[i].Node.Group == name {
			s.doc.Nodes[i].Node.Group = ""
		}
	}
}

// --- subscriptions & settings -----------------------------------------

// UpsertSubscription inserts or replaces a subscription record.
func (s *Store) UpsertSubscription(rec SubscriptionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.doc.Subscriptions {
		if s.doc.Subscriptions[i].ID == rec.ID {
			s.doc.Subscriptions[i] = rec
			return
		}
	}
	s.doc.Subscriptions = append(s.doc.Subscriptions, rec)
}

// Settings returns the persisted settings (zero value while
// the store is locked).
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeAutoLockLocked()
	return s.doc.Settings
}

// UpdateSettings mutates the settings under lock.
func (s *Store) UpdateSettings(fn func(*Settings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.doc.Settings)
}
