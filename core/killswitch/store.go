package killswitch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Record is the persisted kill-switch intent. It records what
// the state machine INTENDED, so a process that is killed (or
// a machine that loses power) reboots into the same intent —
// for a blocking intent, into the block (invariant I3).
type Record struct {
	Mode          Mode      `json:"mode"`
	State         State     `json:"state"`
	SessionActive bool      `json:"session_active"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Store persists Records. Implementations must make Save
// atomic enough that a kill mid-write cannot corrupt the last
// good record into an unreadable one that Restore would have
// to guess at (FileStore writes via rename).
type Store interface {
	Load() (*Record, error) // (nil, nil) when nothing was ever saved
	Save(Record) error
	Clear() error
}

// MemoryStore is an in-memory Store for tests.
type MemoryStore struct {
	rec   *Record
	Saved []Record // full history, for assertions
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (m *MemoryStore) Load() (*Record, error) {
	if m.rec == nil {
		return nil, nil
	}
	cp := *m.rec
	return &cp, nil
}

func (m *MemoryStore) Save(r Record) error {
	cp := r
	m.rec = &cp
	m.Saved = append(m.Saved, r)
	return nil
}

func (m *MemoryStore) Clear() error { m.rec = nil; return nil }

// FileStore persists the Record as JSON at a path, written via
// a temporary file + rename so a kill mid-save leaves either
// the old or the new record, never a torn one.
type FileStore struct {
	Path string
}

func NewFileStore(path string) *FileStore { return &FileStore{Path: path} }

func (s *FileStore) Load() (*Record, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("killswitch: persisted state at %s is corrupt: %w", s.Path, err)
	}
	return &rec, nil
}

func (s *FileStore) Save(r Record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".killswitch-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.Path)
}

func (s *FileStore) Clear() error {
	if err := os.Remove(s.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
