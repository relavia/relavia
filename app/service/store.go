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
// STEP 9 SCOPE: the store is a single PLAIN JSON file. This is a
// deliberate interim step, flagged here and in the Step 9 report:
// proposal book Step 13 replaces this with encrypted storage
// (config encryption, export confirmation). The replacement point
// is exactly this file — Store's on-disk Document — so Step 13
// can swap the codec without touching callers. Node credentials
// are secrets (book 9.1); until Step 13 lands, the file is
// written with 0600 permissions inside the user's config
// directory and never leaves the device (book 3.2, local-first).

// NodeRecord is one stored node plus its import-time warning
// codes (parser warning codes from package parsers).
type NodeRecord struct {
	Node     *specnode.Node `json:"node"`
	Warnings []string       `json:"warnings,omitempty"`
	AddedAt  string         `json:"addedAt,omitempty"`
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
	SelectedNodeID string `json:"selectedNodeId,omitempty"`
	SelectedGroup  string `json:"selectedGroup,omitempty"`
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

// Store is a concurrency-safe JSON document store.
type Store struct {
	mu   sync.Mutex
	path string
	doc  Document
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
// when the file does not exist yet.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) > 0 {
			if err := json.Unmarshal(data, &s.doc); err != nil {
				return nil, fmt.Errorf("service: parse store %s: %w", path, err)
			}
		}
	case os.IsNotExist(err):
		// Fresh store.
	default:
		return nil, fmt.Errorf("service: read store %s: %w", path, err)
	}
	if s.doc.Version == 0 {
		s.doc.Version = storeVersion
	}
	return s, nil
}

// Save persists the document atomically (write temp + rename),
// with owner-only permissions because it contains credentials.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil // in-memory store (tests)
	}
	data, err := json.MarshalIndent(&s.doc, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Snapshot returns a copy of the document for read paths.
func (s *Store) Snapshot() Document {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// Settings returns the persisted settings.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.Settings
}

// UpdateSettings mutates the settings under lock.
func (s *Store) UpdateSettings(fn func(*Settings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.doc.Settings)
}
