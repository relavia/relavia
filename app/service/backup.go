package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Encrypted configuration backup (book 5.5, 8.1; Step 13).
//
// Rulings, all deliberate and documented in the Step 13 report:
//
//   - Backups are ALWAYS passphrase-encrypted, even when the
//     live store runs in no-passphrase mode: a backup file is
//     made to leave the app directory (user-carried copy), so it
//     never travels as plaintext credentials. The backup
//     passphrase is independent of the store passphrase.
//   - Export requires an explicit confirmation flag because the
//     book mandates a second confirmation with the warning that
//     the export contains credentials equivalent to passwords
//     (5.5: 导出配置须二次确认并提示「配置含凭据，等同密码」). The
//     service layer cannot show UI, so the caller's confirmation
//     is a required parameter; confirmed=false is refused with
//     ErrExportNotConfirmed. The warning text itself ships in
//     the trilingual string table (security.export_warning).
//   - No cloud account is involved anywhere (book 3.2): export
//     writes one local file; import reads one local file.
//   - Integrity is two-layer: the AEAD tag authenticates the
//     ciphertext, and the payload carries a SHA-256 of the
//     canonical document JSON plus the node count, both
//     re-verified on import.

const (
	backupFormat  = "relavia-backup"
	backupVersion = 1
	backupAAD     = "relavia-backup/v1"
)

// backupEnvelope is the on-disk backup file format (version 1).
type backupEnvelope struct {
	Format     string     `json:"format"`
	Version    int        `json:"version"`
	KDF        *kdfParams `json:"kdf"`
	Nonce      []byte     `json:"nonce"`
	Ciphertext []byte     `json:"ciphertext"`
}

// backupPayload is the encrypted content of a backup file.
type backupPayload struct {
	Document     Document `json:"document"`
	ExportedAt   string   `json:"exportedAt"`
	StoreVersion int      `json:"storeVersion"`
	NodeCount    int      `json:"nodeCount"`
	SHA256       string   `json:"sha256"` // hex SHA-256 of the canonical document JSON
}

func canonicalDocJSON(doc Document) ([]byte, error) {
	if doc.Version == 0 {
		doc.Version = storeVersion
	}
	return json.Marshal(&doc)
}

// ExportBackup writes the store's full document (nodes, groups,
// subscriptions, settings) as a passphrase-encrypted backup file
// at path. It refuses, in order: a locked store
// (ErrStoreLocked), a missing confirmation
// (ErrExportNotConfirmed) and an empty passphrase
// (ErrBackupPassphraseNeeded).
func (s *Store) ExportBackup(path, passphrase string, confirmed bool) error {
	if !confirmed {
		return ErrExportNotConfirmed
	}
	if passphrase == "" {
		return ErrBackupPassphraseNeeded
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeAutoLockLocked()
	if s.sec.locked {
		return ErrStoreLocked
	}
	doc := s.doc
	canon, err := canonicalDocJSON(doc)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	payload := backupPayload{
		Document:     doc,
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		StoreVersion: storeVersion,
		NodeCount:    len(doc.Nodes),
		SHA256:       hex.EncodeToString(sum[:]),
	}
	plain, err := json.Marshal(&payload)
	if err != nil {
		return err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	kdf := defaultKDFParams(salt)
	key := kdf.derive(passphrase)
	nonce, ct, err := sealWith(key, []byte(backupAAD), plain)
	zero(key)
	if err != nil {
		return err
	}
	env := backupEnvelope{
		Format:     backupFormat,
		Version:    backupVersion,
		KDF:        &kdf,
		Nonce:      nonce,
		Ciphertext: ct,
	}
	data, err := json.MarshalIndent(&env, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write, owner-only: the file is encrypted, but it is
	// still a credential container and gets credential handling.
	return writeFileAtomic(path, data, false)
}

// ReadBackup decrypts and verifies a backup file, returning the
// contained document. A wrong passphrase fails the AEAD open and
// is reported as ErrWrongPassphrase; a file from a newer backup
// format — or holding a document newer than this client's store
// version — is refused with ErrUnsupportedBackupVer; a payload
// whose internal hash or node count does not match is
// ErrCorruptStore.
func ReadBackup(path, passphrase string) (Document, error) {
	if passphrase == "" {
		return Document{}, ErrBackupPassphraseNeeded
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	var env backupEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Document{}, fmt.Errorf("%w: backup does not parse", ErrCorruptStore)
	}
	if env.Format != backupFormat {
		return Document{}, fmt.Errorf("%w: not a relavia backup (format %q)", ErrCorruptStore, env.Format)
	}
	if env.Version > backupVersion {
		return Document{}, fmt.Errorf("%w: backup format version %d > %d", ErrUnsupportedBackupVer, env.Version, backupVersion)
	}
	if env.KDF == nil {
		return Document{}, fmt.Errorf("%w: backup has no KDF header", ErrCorruptStore)
	}
	key := env.KDF.derive(passphrase)
	plain, err := openWith(key, []byte(backupAAD), env.Nonce, env.Ciphertext)
	zero(key)
	if err != nil {
		return Document{}, ErrWrongPassphrase
	}
	var payload backupPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return Document{}, fmt.Errorf("%w: backup payload does not parse", ErrCorruptStore)
	}
	if payload.Document.Version > storeVersion {
		return Document{}, fmt.Errorf("%w: backup document version %d > store version %d",
			ErrUnsupportedBackupVer, payload.Document.Version, storeVersion)
	}
	canon, err := canonicalDocJSON(payload.Document)
	if err != nil {
		return Document{}, err
	}
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(sum[:]) != payload.SHA256 {
		return Document{}, fmt.Errorf("%w: backup integrity hash mismatch", ErrCorruptStore)
	}
	if len(payload.Document.Nodes) != payload.NodeCount {
		return Document{}, fmt.Errorf("%w: backup node count mismatch", ErrCorruptStore)
	}
	return payload.Document, nil
}

// RestoreBackup replaces the store's whole document with the
// backup's content and persists it in the store's current
// protection mode. Replacement is total (documented semantics:
// a restore is a rollback to the backup point, not a merge).
// A locked store refuses with ErrStoreLocked.
func (s *Store) RestoreBackup(path, passphrase string) error {
	doc, err := ReadBackup(path, passphrase)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeAutoLockLocked()
	if s.sec.locked {
		return ErrStoreLocked
	}
	prev := s.doc
	s.doc = doc
	if err := s.saveLocked(); err != nil {
		s.doc = prev
		return err
	}
	return nil
}
