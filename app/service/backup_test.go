package service_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openproxy/app/service"
)

// normalizedJSON round-trips a document through JSON so deep
// comparisons are insensitive to nil-vs-empty slice provenance.
func normalizedJSON(t *testing.T, doc service.Document) string {
	t.Helper()
	raw, err := json.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	var back service.Document
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&back)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestBackupRoundTrip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "store.json")
	src := seedStore(t, srcPath)
	src.AddNode(markerNode("n2"), nil)
	if err := src.Save(); err != nil {
		t.Fatal(err)
	}
	want := normalizedJSON(t, src.Snapshot())

	backupPath := filepath.Join(dir, "backup.relavibak")
	if err := src.ExportBackup(backupPath, "bak-pw", false); !errors.Is(err, service.ErrExportNotConfirmed) {
		t.Fatalf("unconfirmed export = %v, want ErrExportNotConfirmed (book 5.5 second confirmation)", err)
	}
	if err := src.ExportBackup(backupPath, "", true); !errors.Is(err, service.ErrBackupPassphraseNeeded) {
		t.Fatalf("passphrase-less export = %v, want ErrBackupPassphraseNeeded", err)
	}
	if err := src.ExportBackup(backupPath, "bak-pw", true); err != nil {
		t.Fatalf("ExportBackup: %v", err)
	}

	raw, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), credMarker) {
		t.Fatal("credential marker found in backup file (plaintext leak)")
	}

	if _, err := service.ReadBackup(backupPath, "wrong"); !errors.Is(err, service.ErrWrongPassphrase) {
		t.Fatalf("ReadBackup(wrong pw) = %v, want ErrWrongPassphrase", err)
	}
	doc, err := service.ReadBackup(backupPath, "bak-pw")
	if err != nil {
		t.Fatalf("ReadBackup: %v", err)
	}
	if got := normalizedJSON(t, doc); got != want {
		t.Fatalf("backup document mismatch:\n got %s\nwant %s", got, want)
	}

	dst := openStoreAt(t, filepath.Join(dir, "restored.json"))
	if err := dst.RestoreBackup(backupPath, "bak-pw"); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if got := normalizedJSON(t, dst.Snapshot()); got != want {
		t.Fatalf("restored document mismatch:\n got %s\nwant %s", got, want)
	}
	// And the restore must be durable across a reopen.
	dst2 := openStoreAt(t, filepath.Join(dir, "restored.json"))
	if got := normalizedJSON(t, dst2.Snapshot()); got != want {
		t.Fatal("restored document did not survive reopen")
	}
}

func TestBackupTamperAndVersionRefusals(t *testing.T) {
	dir := t.TempDir()
	src := seedStore(t, filepath.Join(dir, "store.json"))
	backupPath := filepath.Join(dir, "backup.relavibak")
	if err := src.ExportBackup(backupPath, "bak-pw", true); err != nil {
		t.Fatal(err)
	}
	flipEnvelopeField(t, backupPath, "ciphertext")
	if _, err := service.ReadBackup(backupPath, "bak-pw"); err == nil {
		t.Fatal("tampered backup was accepted")
	}

	future := filepath.Join(dir, "future.relavibak")
	content := `{"format":"relavia-backup","version":99,"kdf":{"time":3,"memoryKiB":65536,"threads":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAA"}`
	if err := os.WriteFile(future, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadBackup(future, "bak-pw"); !errors.Is(err, service.ErrUnsupportedBackupVer) {
		t.Fatalf("future-version backup = %v, want ErrUnsupportedBackupVer", err)
	}

	notBackup := filepath.Join(dir, "other.json")
	if err := os.WriteFile(notBackup, []byte(`{"format":"something-else","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadBackup(notBackup, "bak-pw"); !errors.Is(err, service.ErrCorruptStore) {
		t.Fatalf("non-backup file = %v, want ErrCorruptStore", err)
	}
}

func TestBackupLockedStoreRefusals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	st := seedStore(t, path)
	backupPath := filepath.Join(dir, "backup.relavibak")
	if err := st.ExportBackup(backupPath, "bak-pw", true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassphrase("pw"); err != nil {
		t.Fatal(err)
	}
	// Reopen so the store starts locked.
	st2 := openStoreAt(t, path)
	if !st2.Locked() {
		t.Fatal("precondition: store must be locked")
	}
	if err := st2.ExportBackup(filepath.Join(dir, "x.relavibak"), "bak-pw", true); !errors.Is(err, service.ErrStoreLocked) {
		t.Fatalf("export from locked store = %v, want ErrStoreLocked", err)
	}
	if err := st2.RestoreBackup(backupPath, "bak-pw"); !errors.Is(err, service.ErrStoreLocked) {
		t.Fatalf("restore into locked store = %v, want ErrStoreLocked", err)
	}
}

// A backup made from a no-passphrase (degraded) store is still
// encrypted: leaving the device is exactly when plaintext is not
// acceptable.
func TestBackupFromDegradedStoreIsEncrypted(t *testing.T) {
	dir := t.TempDir()
	st := seedStore(t, filepath.Join(dir, "store.json"))
	if p := st.Protection(); p.Mode != service.ModeNone {
		t.Fatalf("precondition: store should be in none mode, got %+v", p)
	}
	backupPath := filepath.Join(dir, "backup.relavibak")
	if err := st.ExportBackup(backupPath, "bak-pw", true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), credMarker) {
		t.Fatal("backup from degraded store leaked plaintext credentials")
	}
	doc, err := service.ReadBackup(backupPath, "bak-pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Nodes) != 1 {
		t.Fatalf("backup from degraded store has %d nodes, want 1", len(doc.Nodes))
	}
}
