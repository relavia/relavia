package service_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openproxy/core/specnode"

	"openproxy/app/service"
)

// credMarker is a distinctive credential string: its presence in
// a file on disk proves plaintext leakage, its absence is the
// encryption-at-rest assertion.
const credMarker = "CRED-MARKER-pw-9f3a7c"

func markerNode(id string) *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            id,
		Name:          id,
		Protocol:      specnode.ProtocolShadowsocks,
		Server:        "192.0.2.10",
		Port:          8388,
		Group:         "g1",
		Source:        specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "user-provided"},
		Shadowsocks:   &specnode.CredShadowsocks{Method: "aes-256-gcm", Password: credMarker},
	}
}

func openStoreAt(t *testing.T, path string) *service.Store {
	t.Helper()
	st, err := service.OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return st
}

func seedStore(t *testing.T, path string) *service.Store {
	t.Helper()
	st := openStoreAt(t, path)
	st.AddNode(markerNode("n1"), nil)
	st.AddGroup("g1")
	st.UpsertSubscription(service.SubscriptionRecord{ID: "s1", Name: "sub", URL: "https://example.invalid/sub?token=" + credMarker})
	st.UpdateSettings(func(s *service.Settings) { s.Language = "en" })
	if err := st.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return st
}

func fileContains(t *testing.T, path, needle string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Contains(string(data), needle)
}

// flipEnvelopeField decodes one base64 field of the on-disk
// envelope, flips a byte and writes the file back: the tamper
// oracle for the AEAD assertions.
func flipEnvelopeField(t *testing.T, path, field string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	raw, ok := env[field].(string)
	if !ok || raw == "" {
		t.Fatalf("envelope field %q missing", field)
	}
	buf, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	buf[len(buf)/2] ^= 0xFF
	env[field] = base64.StdEncoding.EncodeToString(buf)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPassphraseEncryptsAtRestAndLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	if !fileContains(t, path, credMarker) {
		t.Fatal("precondition: no-passphrase store should hold plaintext (degraded mode)")
	}
	if err := st.SetPassphrase("correct horse battery"); err != nil {
		t.Fatalf("SetPassphrase: %v", err)
	}
	if fileContains(t, path, credMarker) {
		t.Fatal("credential marker found in encrypted store file")
	}
	if p := st.Protection(); p.Mode != service.ModePassphrase || p.Degraded || p.Locked {
		t.Fatalf("Protection after SetPassphrase = %+v", p)
	}

	st2 := openStoreAt(t, path)
	if !st2.Locked() {
		t.Fatal("reopened encrypted store must start locked")
	}
	if snap := st2.Snapshot(); len(snap.Nodes) != 0 {
		t.Fatalf("locked store exposed %d nodes", len(snap.Nodes))
	}
	if _, ok := st2.NodeByID("n1"); ok {
		t.Fatal("locked store exposed a node record")
	}
	if err := st2.Save(); !errors.Is(err, service.ErrStoreLocked) {
		t.Fatalf("Save on locked store = %v, want ErrStoreLocked", err)
	}
	if err := st2.Unlock("wrong"); !errors.Is(err, service.ErrWrongPassphrase) {
		t.Fatalf("Unlock(wrong) = %v, want ErrWrongPassphrase", err)
	}
	if !st2.Locked() {
		t.Fatal("wrong passphrase must leave the store locked")
	}
	if err := st2.Unlock("correct horse battery"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	rec, ok := st2.NodeByID("n1")
	if !ok || rec.Node.Shadowsocks.Password != credMarker {
		t.Fatalf("unlocked node credential mismatch: %+v", rec)
	}
	if st2.Settings().Language != "en" {
		t.Fatal("settings lost across encrypt/reopen")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	for _, field := range []string{"ciphertext", "wrappedKey"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			st := seedStore(t, path)
			if err := st.SetPassphrase("pw-123"); err != nil {
				t.Fatal(err)
			}
			flipEnvelopeField(t, path, field)
			st2 := openStoreAt(t, path)
			err := st2.Unlock("pw-123")
			if err == nil {
				t.Fatalf("tampered %s: unlock succeeded, want rejection", field)
			}
			if !errors.Is(err, service.ErrWrongPassphrase) && !errors.Is(err, service.ErrCorruptStore) {
				t.Fatalf("tampered %s: unlock error = %v, want wrong-passphrase or corrupt", field, err)
			}
			if snap := st2.Snapshot(); len(snap.Nodes) != 0 {
				t.Fatal("tampered store exposed nodes")
			}
		})
	}
}

func TestLegacyPlaintextMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	legacy := service.Document{
		Version: 1,
		Nodes:   []service.NodeRecord{{Node: markerNode("n1")}},
		Groups:  []string{"g1"},
	}
	raw, err := json.Marshal(&legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	st := openStoreAt(t, path)
	if _, ok := st.NodeByID("n1"); !ok {
		t.Fatal("legacy document did not load")
	}
	if p := st.Protection(); p.Mode != service.ModeNone || !p.Degraded {
		t.Fatalf("legacy store Protection = %+v, want none+degraded", p)
	}
	if err := st.SetPassphrase("migrate-pw"); err != nil {
		t.Fatalf("SetPassphrase (migration): %v", err)
	}
	if fileContains(t, path, credMarker) {
		t.Fatal("plaintext credential survived migration")
	}
	st2 := openStoreAt(t, path)
	if err := st2.Unlock("migrate-pw"); err != nil {
		t.Fatalf("Unlock after migration: %v", err)
	}
	snap := st2.Snapshot()
	if len(snap.Nodes) != 1 || snap.Nodes[0].Node.ID != "n1" ||
		snap.Nodes[0].Node.Shadowsocks.Password != credMarker ||
		len(snap.Groups) != 1 || snap.Groups[0] != "g1" {
		t.Fatalf("migrated document mismatch: %+v", snap)
	}
}

func TestMigrationFailureKeepsOriginalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Block the atomic-write temp path with a directory: the
	// migration's write must fail before touching the original.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassphrase("pw"); err == nil {
		t.Fatal("SetPassphrase succeeded despite blocked temp path")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed migration modified the original store file")
	}
	if _, ok := st.NodeByID("n1"); !ok {
		t.Fatal("failed migration lost in-memory data")
	}
	if p := st.Protection(); p.Mode != service.ModeNone {
		t.Fatalf("failed migration changed protection mode: %+v", p)
	}
}

func TestNoPassphraseModeIsMarkedDegraded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	if p := st.Protection(); p.Mode != service.ModeNone || !p.Degraded || p.Locked {
		t.Fatalf("Protection = %+v, want none+degraded+unlocked", p)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Format   string `json:"format"`
		Mode     string `json:"mode"`
		Degraded bool   `json:"degraded"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.Format != "relavia-store" || env.Mode != "none" || !env.Degraded {
		t.Fatalf("on-disk degraded marker missing: %+v", env)
	}
	if err := st.Unlock("anything"); !errors.Is(err, service.ErrNoPassphraseSet) {
		t.Fatalf("Unlock on no-passphrase store = %v, want ErrNoPassphraseSet", err)
	}
}

func TestChangeAndRemovePassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	if err := st.SetPassphrase("pw-one"); err != nil {
		t.Fatal(err)
	}
	if err := st.ChangePassphrase("nope", "pw-two"); !errors.Is(err, service.ErrWrongPassphrase) {
		t.Fatalf("ChangePassphrase(wrong old) = %v", err)
	}
	if err := st.ChangePassphrase("pw-one", "pw-two"); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	st.Lock()
	if err := st.Unlock("pw-one"); !errors.Is(err, service.ErrWrongPassphrase) {
		t.Fatalf("old passphrase still works after change: %v", err)
	}
	if err := st.Unlock("pw-two"); err != nil {
		t.Fatalf("new passphrase rejected: %v", err)
	}
	if err := st.RemovePassphrase("nope"); !errors.Is(err, service.ErrWrongPassphrase) {
		t.Fatalf("RemovePassphrase(wrong) = %v", err)
	}
	if err := st.RemovePassphrase("pw-two"); err != nil {
		t.Fatalf("RemovePassphrase: %v", err)
	}
	if p := st.Protection(); p.Mode != service.ModeNone || !p.Degraded {
		t.Fatalf("after removal Protection = %+v, want none+degraded", p)
	}
	st2 := openStoreAt(t, path)
	if st2.Locked() {
		t.Fatal("downgraded store must reopen unlocked")
	}
	if _, ok := st2.NodeByID("n1"); !ok {
		t.Fatal("data lost across passphrase removal")
	}
}

func TestManualLockUnlockCycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	if err := st.SetPassphrase("pw"); err != nil {
		t.Fatal(err)
	}
	st.Lock()
	if !st.Locked() {
		t.Fatal("Lock() did not lock")
	}
	if snap := st.Snapshot(); len(snap.Nodes) != 0 {
		t.Fatal("locked snapshot exposed nodes")
	}
	if err := st.Unlock("pw"); err != nil {
		t.Fatalf("Unlock after Lock: %v", err)
	}
	if _, ok := st.NodeByID("n1"); !ok {
		t.Fatal("node missing after lock/unlock cycle (unsaved state must survive via re-seal)")
	}
}

func TestAutoLockExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	if err := st.SetPassphrase("pw"); err != nil {
		t.Fatal(err)
	}
	st.SetAutoLock(60 * time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if !st.CheckAutoLock() {
		t.Fatal("CheckAutoLock did not fire after the inactivity timeout")
	}
	if !st.Locked() {
		t.Fatal("store not locked after auto-lock")
	}
	if err := st.Unlock("pw"); err != nil {
		t.Fatalf("Unlock after auto-lock: %v", err)
	}
}

func TestCrashRecoveryFromTempFile(t *testing.T) {
	t.Run("none mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "store.json")
		seedStore(t, path)
		good, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{corrupted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".tmp", good, 0o600); err != nil {
			t.Fatal(err)
		}
		st := openStoreAt(t, path)
		if _, ok := st.NodeByID("n1"); !ok {
			t.Fatal("recovery from temp file lost the node")
		}
	})
	t.Run("passphrase mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "store.json")
		st := seedStore(t, path)
		if err := st.SetPassphrase("pw"); err != nil {
			t.Fatal(err)
		}
		good, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, len(good)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".tmp", good, 0o600); err != nil {
			t.Fatal(err)
		}
		st2 := openStoreAt(t, path)
		if !st2.Locked() {
			t.Fatal("recovered encrypted store must be locked")
		}
		if err := st2.Unlock("pw"); err != nil {
			t.Fatalf("Unlock after temp recovery: %v", err)
		}
		if _, ok := st2.NodeByID("n1"); !ok {
			t.Fatal("recovery from temp file lost the node")
		}
	})
}

// xorWrapper is a TEST-ONLY KeyWrapper fake. It is not a real
// platform key store and ships only in this test file.
type xorWrapper struct{ key byte }

func (w xorWrapper) WrapKey(dek []byte) ([]byte, error) {
	out := make([]byte, len(dek))
	for i, b := range dek {
		out[i] = b ^ w.key
	}
	return out, nil
}
func (w xorWrapper) UnwrapKey(blob []byte) ([]byte, error) { return w.WrapKey(blob) }

func TestPlatformWrapperUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st := seedStore(t, path)
	st.SetKeyWrapper(xorWrapper{key: 0x5A})
	if err := st.SetPassphrase("pw"); err != nil {
		t.Fatal(err)
	}
	if err := st.UnlockWithPlatform(); err != nil {
		// Not locked yet (same session): UnlockWithPlatform is a no-op success path.
		t.Fatalf("UnlockWithPlatform while unlocked: %v", err)
	}
	st.Lock()
	if err := st.UnlockWithPlatform(); !errors.Is(err, service.ErrNoPlatformKey) {
		t.Fatalf("UnlockWithPlatform before Enable = %v, want ErrNoPlatformKey", err)
	}
	if err := st.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnablePlatformUnlock(); err != nil {
		t.Fatalf("EnablePlatformUnlock: %v", err)
	}
	st.Lock()
	if err := st.UnlockWithPlatform(); err != nil {
		t.Fatalf("UnlockWithPlatform: %v", err)
	}
	if _, ok := st.NodeByID("n1"); !ok {
		t.Fatal("node missing after platform unlock")
	}
	// The blob must also survive a reopen.
	st2 := openStoreAt(t, path)
	st2.SetKeyWrapper(xorWrapper{key: 0x5A})
	if err := st2.UnlockWithPlatform(); err != nil {
		t.Fatalf("UnlockWithPlatform after reopen: %v", err)
	}
}
