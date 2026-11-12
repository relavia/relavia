package service

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypted-at-rest storage (proposal book 5.5, Step 13).
//
// Design ruling (full rationale in docs/step13-本地安全存储与备份.md):
//
//   - KDF: Argon2id (golang.org/x/crypto/argon2, BSD-3-Clause)
//     derives a 32-byte key-encryption key (KEK) from the user's
//     passphrase. Parameters are stored in the file header so they
//     can be raised later without a format break.
//   - AEAD: XChaCha20-Poly1305 (golang.org/x/crypto/chacha20poly1305)
//     encrypts the document under a random 32-byte data-encryption
//     key (DEK); the DEK is itself sealed under the KEK, so a
//     passphrase change re-wraps the DEK instead of re-encrypting
//     the whole document. Random 24-byte nonces are safe with
//     XChaCha's large nonce space, and the construction needs no
//     AES hardware — relevant for low-end Android devices.
//   - No-passphrase mode is a user choice the book explicitly
//     allows (5.5: "用户可选择不设口令并承担相应风险，界面明示").
//     It is persisted with an explicit degraded marker and is
//     NEVER presented as equivalent to encrypted mode:
//     Protection() reports Mode "none" with Degraded true.
//   - Platform key stores (Windows DPAPI, Android Keystore) plug
//     in through the KeyWrapper interface: a platform wrapper may
//     hold an opaque blob that unwraps the DEK so the user can
//     unlock without typing the passphrase. The interface and the
//     envelope field are implemented and tested here with a fake;
//     the real DPAPI/Keystore bindings are platform work graded
//     in the Step 13 report (not claimed as done).

// Protection modes for the on-disk store.
const (
	ModeNone       = "none"       // no passphrase: plaintext document, degraded
	ModePassphrase = "passphrase" // Argon2id + XChaCha20-Poly1305 encrypted
)

const (
	storeFormat   = "relavia-store"
	storeEnvVer   = 1
	docAAD        = "relavia-store/v1"
	keyAAD        = "relavia-store-key/v1"
	dekLen        = 32
	saltLen       = 16
	minPassphrase = 1 // non-empty; strength guidance is a UI concern
)

// Security-state errors. Callers compare with errors.Is.
var (
	ErrStoreLocked            = errors.New("service: store is locked")
	ErrWrongPassphrase        = errors.New("service: wrong passphrase")
	ErrNoPassphraseSet        = errors.New("service: no passphrase set on this store")
	ErrPassphraseAlreadySet   = errors.New("service: passphrase already set; use ChangePassphrase")
	ErrEmptyPassphrase        = errors.New("service: passphrase must not be empty")
	ErrCorruptStore           = errors.New("service: store file is corrupt or tampered")
	ErrExportNotConfirmed     = errors.New("service: export requires explicit user confirmation (book 5.5)")
	ErrBackupPassphraseNeeded = errors.New("service: backup requires a passphrase")
	ErrUnsupportedBackupVer   = errors.New("service: backup version is newer than this client supports")
	ErrNoPlatformKey          = errors.New("service: no platform-wrapped key on this store")
)

// kdfParams are the Argon2id parameters persisted in the header.
type kdfParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memoryKiB"`
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`
}

// defaultKDFParams follows the OWASP baseline for Argon2id on
// interactive logins, raised for a single-user local vault:
// 64 MiB / 3 iterations / 4 lanes derives in well under a second
// on desktop and acceptably on mid-range phones; the stored
// parameters let future builds raise them per device class.
func defaultKDFParams(salt []byte) kdfParams {
	return kdfParams{Time: 3, Memory: 64 * 1024, Threads: 4, Salt: salt}
}

func (p kdfParams) derive(passphrase string) []byte {
	return argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Threads, dekLen)
}

// storeEnvelope is the on-disk file format (version 1). Binary
// fields are base64 in JSON (encoding/json default for []byte).
// In ModeNone the document sits in Document as plaintext and
// Degraded is true; in ModePassphrase only ciphertext fields are
// present and no plaintext credential ever touches the disk.
type storeEnvelope struct {
	Format             string     `json:"format"`
	Version            int        `json:"version"`
	Mode               string     `json:"mode"`
	Degraded           bool       `json:"degraded,omitempty"`
	KDF                *kdfParams `json:"kdf,omitempty"`
	WrappedKey         []byte     `json:"wrappedKey,omitempty"`         // nonce||ct of DEK under KEK
	PlatformWrappedKey []byte     `json:"platformWrappedKey,omitempty"` // opaque blob from a KeyWrapper
	Nonce              []byte     `json:"nonce,omitempty"`
	Ciphertext         []byte     `json:"ciphertext,omitempty"`
	Document           *Document  `json:"document,omitempty"`
}

// ProtectionInfo is the data-layer protection marker the UI
// renders (book 5.5: the no-passphrase risk must be 明示 — shown,
// not implied).
type ProtectionInfo struct {
	Mode     string // ModeNone or ModePassphrase
	Locked   bool   // passphrase mode and not yet unlocked
	Degraded bool   // true exactly when Mode == ModeNone
}

// KeyWrapper abstracts platform secret storage (Windows DPAPI,
// Android Keystore). WrapKey returns an opaque blob that only
// the same platform context can unwrap; UnwrapKey reverses it.
// Security note: a platform-wrapped key trades "something you
// know" for "something you have" (this device + OS user), which
// is weaker against a local attacker with device access; the UI
// must present it as a convenience unlock, not as passphrase
// equivalence. That trade-off is the platform steps' to surface.
type KeyWrapper interface {
	WrapKey(dek []byte) ([]byte, error)
	UnwrapKey(blob []byte) ([]byte, error)
}

// secState is the Store's security state (guarded by Store.mu).
type secState struct {
	mode           string
	locked         bool
	legacy         bool           // file at Open was a pre-Step-13 bare JSON document
	plainOnDisk    bool           // current on-disk content contains plaintext credentials
	env            *storeEnvelope // last known envelope (locked passphrase mode: the unlock candidates source)
	envKDF         *kdfParams     // header material mirrored from env for re-sealing
	envWrapped     []byte         // DEK wrapped under the passphrase KEK
	envPlatWrapped []byte         // DEK wrapped by the platform KeyWrapper, if enabled
	dek            []byte         // present only while unlocked in passphrase mode
	wrapper        KeyWrapper

	autoLock     time.Duration
	lastActivity time.Time
	nowFn        func() time.Time
}

func (sec *secState) now() time.Time {
	if sec.nowFn != nil {
		return sec.nowFn()
	}
	return time.Now()
}

func (sec *secState) touchLocked() { sec.lastActivity = sec.now() }

// normalizedMode maps the zero value to ModeNone (in-memory and
// freshly created stores start unencrypted until a passphrase is
// set — the degraded marker says so).
func (sec *secState) normalizedMode() string {
	if sec.mode == ModePassphrase {
		return ModePassphrase
	}
	return ModeNone
}

// Protection reports the store's current protection marker.
func (s *Store) Protection() ProtectionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeAutoLockLocked()
	return ProtectionInfo{
		Mode:     s.sec.normalizedMode(),
		Locked:   s.sec.locked,
		Degraded: s.sec.normalizedMode() == ModeNone,
	}
}

// Locked reports whether the store is in locked passphrase mode.
func (s *Store) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sec.locked
}

// --- envelope codec ---------------------------------------------------

func sealWith(key, aad, plaintext []byte) (nonce, ct []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, []byte(aad)), nil
}

func openWith(key, aad, nonce, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, []byte(aad))
}

// wrapDEK seals the DEK under the KEK, returned as nonce||ct.
func wrapDEK(kek, dek []byte) ([]byte, error) {
	nonce, ct, err := sealWith(kek, []byte(keyAAD), dek)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func unwrapDEK(kek, blob []byte) ([]byte, error) {
	ns := chacha20poly1305.NonceSizeX
	if len(blob) <= ns {
		return nil, ErrWrongPassphrase
	}
	dek, err := openWith(kek, []byte(keyAAD), blob[:ns], blob[ns:])
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return dek, nil
}

// buildEnvelopeLocked renders the current document into the
// on-disk envelope for the store's mode. Passphrase mode requires
// an unlocked DEK in memory.
func (s *Store) buildEnvelopeLocked() (*storeEnvelope, error) {
	doc := s.doc
	if doc.Version == 0 {
		doc.Version = storeVersion
	}
	if s.sec.normalizedMode() == ModeNone {
		d := doc
		return &storeEnvelope{
			Format:   storeFormat,
			Version:  storeEnvVer,
			Mode:     ModeNone,
			Degraded: true,
			Document: &d,
		}, nil
	}
	if s.sec.dek == nil {
		return nil, ErrStoreLocked
	}
	plain, err := json.Marshal(&doc)
	if err != nil {
		return nil, err
	}
	nonce, ct, err := sealWith(s.sec.dek, []byte(docAAD), plain)
	if err != nil {
		return nil, err
	}
	env := &storeEnvelope{
		Format:     storeFormat,
		Version:    storeEnvVer,
		Mode:       ModePassphrase,
		Nonce:      nonce,
		Ciphertext: ct,
	}
	env.KDF = s.sec.envKDF
	env.WrappedKey = s.sec.envWrapped
	env.PlatformWrappedKey = s.sec.envPlatWrapped
	return env, nil
}

// decryptEnvelopeDoc decrypts an envelope's document under dek.
// The DEK reaching this point is already authenticated (it came
// out of an AEAD unwrap), so an AEAD failure here means the
// ciphertext itself was tampered with or corrupted — reported as
// ErrCorruptStore, distinct from a wrong passphrase, which fails
// earlier at the unwrap.
func decryptEnvelopeDoc(env *storeEnvelope, dek []byte) (Document, error) {
	plain, err := openWith(dek, []byte(docAAD), env.Nonce, env.Ciphertext)
	if err != nil {
		return Document{}, fmt.Errorf("%w: document decryption failed (tampered or corrupt)", ErrCorruptStore)
	}
	var doc Document
	if err := json.Unmarshal(plain, &doc); err != nil {
		return Document{}, fmt.Errorf("%w: decrypted payload is not a document", ErrCorruptStore)
	}
	return doc, nil
}

// --- lock state machine ----------------------------------------------
//
// States (passphrase mode): Locked --Unlock(ok)--> Unlocked;
// Unlocked --Lock() / auto-lock timeout--> Locked. A wrong
// passphrase is not a transition: the store stays Locked and no
// part of the document is exposed. In ModeNone the store is
// always "unlocked" and Lock() is a no-op.

// Unlock decrypts the store with the user's passphrase. A wrong
// passphrase yields ErrWrongPassphrase and leaves the store
// locked with an empty in-memory document.
func (s *Store) Unlock(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec.normalizedMode() != ModePassphrase {
		return ErrNoPassphraseSet
	}
	if !s.sec.locked {
		return nil
	}
	env := s.sec.env
	if env == nil || env.KDF == nil {
		return ErrCorruptStore
	}
	kek := env.KDF.derive(passphrase)
	dek, err := unwrapDEK(kek, env.WrappedKey)
	zero(kek)
	if err != nil {
		return err
	}
	doc, err := decryptEnvelopeDoc(env, dek)
	if err != nil {
		zero(dek)
		return err
	}
	s.doc = doc
	s.sec.dek = dek
	s.sec.locked = false
	s.sec.touchLocked()
	return nil
}

// UnlockWithPlatform unlocks via the registered KeyWrapper's
// blob (DPAPI/Keystore convenience unlock). It fails with
// ErrNoPlatformKey when no wrapper or blob is present.
func (s *Store) UnlockWithPlatform() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec.normalizedMode() != ModePassphrase {
		return ErrNoPassphraseSet
	}
	if !s.sec.locked {
		return nil
	}
	env := s.sec.env
	if env == nil || len(env.PlatformWrappedKey) == 0 || s.sec.wrapper == nil {
		return ErrNoPlatformKey
	}
	dek, err := s.sec.wrapper.UnwrapKey(env.PlatformWrappedKey)
	if err != nil {
		return fmt.Errorf("service: platform unwrap: %w", err)
	}
	doc, err := decryptEnvelopeDoc(env, dek)
	if err != nil {
		zero(dek)
		return err
	}
	s.doc = doc
	s.sec.dek = dek
	s.sec.locked = false
	s.sec.touchLocked()
	return nil
}

// Lock re-seals the in-memory document, zeroes the DEK and drops
// the plaintext document from memory. No-op in ModeNone.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
}

func (s *Store) lockLocked() {
	if s.sec.normalizedMode() != ModePassphrase || s.sec.locked {
		return
	}
	// Re-seal under the still-resident DEK so Unlock can recover
	// exactly this state even if the process exits before a Save.
	if env, err := s.buildEnvelopeLocked(); err == nil {
		s.sec.env = env
	}
	zero(s.sec.dek)
	s.sec.dek = nil
	s.doc = Document{}
	s.sec.locked = true
}

// SetAutoLock arms the inactivity auto-lock (0 disables). The
// check is lazy — evaluated at the entry of read/save paths and
// by CheckAutoLock, which a UI timer may call — so behaviour is
// deterministic and testable without background goroutines.
func (s *Store) SetAutoLock(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sec.autoLock = d
	s.sec.touchLocked()
}

// CheckAutoLock locks the store if the auto-lock timeout has
// elapsed since the last activity; reports whether it locked.
func (s *Store) CheckAutoLock() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maybeAutoLockLocked()
}

func (s *Store) maybeAutoLockLocked() bool {
	if s.sec.normalizedMode() != ModePassphrase || s.sec.locked || s.sec.autoLock <= 0 {
		return false
	}
	if s.sec.now().Sub(s.sec.lastActivity) >= s.sec.autoLock {
		s.lockLocked()
		return true
	}
	return false
}

// SetKeyWrapper registers the platform key wrapper used by
// EnablePlatformUnlock / UnlockWithPlatform.
func (s *Store) SetKeyWrapper(w KeyWrapper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sec.wrapper = w
}

// --- passphrase lifecycle ----------------------------------------------

// SetPassphrase enables encrypted mode on an unlocked
// no-passphrase store (including migrating a legacy plaintext
// file). All cryptography happens in memory first; the on-disk
// plaintext is overwritten only after the sealed replacement is
// fully written and fsynced, so a failure leaves the original
// file byte-identical and the data intact.
func (s *Store) SetPassphrase(passphrase string) error {
	if len(passphrase) < minPassphrase {
		return ErrEmptyPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec.locked {
		return ErrStoreLocked
	}
	if s.sec.normalizedMode() == ModePassphrase {
		return ErrPassphraseAlreadySet
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	kdf := defaultKDFParams(salt)
	kek := kdf.derive(passphrase)
	wrapped, err := wrapDEK(kek, dek)
	zero(kek)
	if err != nil {
		zero(dek)
		return err
	}
	// Commit key material in memory, persist, roll back on error.
	prev := s.sec
	s.sec.mode = ModePassphrase
	s.sec.dek = dek
	s.sec.envKDF = &kdf
	s.sec.envWrapped = wrapped
	s.sec.envPlatWrapped = nil
	if err := s.saveLocked(); err != nil {
		zero(dek)
		s.sec = prev
		return err
	}
	return nil
}

// ChangePassphrase re-wraps the DEK under a new passphrase. The
// old passphrase is verified against the wrapped DEK first; a
// mismatch yields ErrWrongPassphrase and changes nothing.
func (s *Store) ChangePassphrase(oldPassphrase, newPassphrase string) error {
	if len(newPassphrase) < minPassphrase {
		return ErrEmptyPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec.normalizedMode() != ModePassphrase {
		return ErrNoPassphraseSet
	}
	if s.sec.locked {
		return ErrStoreLocked
	}
	env := s.sec.env
	if env == nil || env.KDF == nil {
		return ErrCorruptStore
	}
	oldKEK := env.KDF.derive(oldPassphrase)
	dek, err := unwrapDEK(oldKEK, env.WrappedKey)
	zero(oldKEK)
	if err != nil {
		return err
	}
	zero(dek) // the live DEK in s.sec.dek is authoritative; this copy only proved knowledge
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	kdf := defaultKDFParams(salt)
	newKEK := kdf.derive(newPassphrase)
	wrapped, err := wrapDEK(newKEK, s.sec.dek)
	zero(newKEK)
	if err != nil {
		return err
	}
	prevKDF, prevWrapped := s.sec.envKDF, s.sec.envWrapped
	s.sec.envKDF, s.sec.envWrapped = &kdf, wrapped
	if err := s.saveLocked(); err != nil {
		s.sec.envKDF, s.sec.envWrapped = prevKDF, prevWrapped
		return err
	}
	return nil
}

// RemovePassphrase downgrades the store to no-passphrase mode
// after verifying the current passphrase. The store is from then
// on persistently marked degraded (book 5.5: the risk is the
// user's explicit choice, shown — never silently equated with
// encrypted storage).
func (s *Store) RemovePassphrase(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec.normalizedMode() != ModePassphrase {
		return ErrNoPassphraseSet
	}
	if s.sec.locked {
		return ErrStoreLocked
	}
	env := s.sec.env
	if env == nil || env.KDF == nil {
		return ErrCorruptStore
	}
	kek := env.KDF.derive(passphrase)
	dek, err := unwrapDEK(kek, env.WrappedKey)
	zero(kek)
	if err != nil {
		return err
	}
	zero(dek)
	prev := s.sec
	s.sec.mode = ModeNone
	s.sec.dek = nil
	s.sec.envKDF, s.sec.envWrapped, s.sec.envPlatWrapped = nil, nil, nil
	if err := s.saveLocked(); err != nil {
		s.sec = prev
		return err
	}
	return nil
}

// EnablePlatformUnlock wraps the live DEK with the registered
// platform KeyWrapper and persists the blob, enabling
// UnlockWithPlatform on later runs. Requires an unlocked
// passphrase-mode store.
func (s *Store) EnablePlatformUnlock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec.normalizedMode() != ModePassphrase {
		return ErrNoPassphraseSet
	}
	if s.sec.locked || s.sec.dek == nil {
		return ErrStoreLocked
	}
	if s.sec.wrapper == nil {
		return ErrNoPlatformKey
	}
	blob, err := s.sec.wrapper.WrapKey(s.sec.dek)
	if err != nil {
		return fmt.Errorf("service: platform wrap: %w", err)
	}
	prev := s.sec.envPlatWrapped
	s.sec.envPlatWrapped = blob
	if err := s.saveLocked(); err != nil {
		s.sec.envPlatWrapped = prev
		return err
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
