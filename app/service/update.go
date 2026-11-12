package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Update mechanism (Step 16; format spec: docs/relavia-update-v1.md).
//
// Privacy posture (book 3.7, 5.5, 9.2): the checker fetches ONE
// static JSON manifest from the official release channel. It sends
// no device information — the only identifying header is
// "User-Agent: Relavia/<version>". Nothing is ever downloaded or
// installed without an explicit user action in the UI: Check only
// reports, Download only runs after the user confirms, and Install
// is a separate platform hand-off. There is no silent-update path
// in this API by construction.

// Update channels.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// UpdateManifestFormat is the only manifest format this client
// accepts (docs/relavia-update-v1.md).
const UpdateManifestFormat = "relavia-update/v1"

// Client build identity. The release pipeline (Step 15) stamps
// these via -ldflags -X; the values here are the development
// defaults. ClientVersionCode follows the manifest spec encoding:
// MAJOR*10000 + MINOR*100 + PATCH.
var (
	ClientVersion     = "0.1.0"
	ClientVersionCode = 100
)

// VersionCodeOf encodes a semantic version triple the way the
// manifest spec defines versionCode.
func VersionCodeOf(major, minor, patch int) int {
	return major*10000 + minor*100 + patch
}

// ---------------------------------------------------------------------------
// Semantic versions
// ---------------------------------------------------------------------------

// Semver is a parsed semantic version.
type Semver struct {
	Major, Minor, Patch int
	Pre                 string // dot-separated prerelease, "" for a release
}

// ParseSemver parses MAJOR.MINOR.PATCH with an optional
// "-prerelease" suffix and an optional leading "v".
func ParseSemver(s string) (Semver, error) {
	var v Semver
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if s == "" {
		return v, errors.New("empty version")
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.Pre = s[i+1:]
		s = s[:i]
		if v.Pre == "" {
			return v, errors.New("empty prerelease")
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
	}
	nums := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("version %q has a non-numeric component", s)
		}
		*nums[i] = n
	}
	return v, nil
}

// CompareSemver returns -1, 0 or +1. A release outranks any of its
// prereleases; prerelease identifiers compare per semver rules
// (numeric identifiers compare numerically and rank below
// alphanumeric ones; a shorter list ranks below a longer one when
// all shared identifiers are equal).
func CompareSemver(a, b Semver) int {
	if c := cmpInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpInt(a.Patch, b.Patch); c != 0 {
		return c
	}
	if a.Pre == b.Pre {
		return 0
	}
	if a.Pre == "" {
		return 1
	}
	if b.Pre == "" {
		return -1
	}
	as, bs := strings.Split(a.Pre, "."), strings.Split(b.Pre, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			return cmpInt(an, bn)
		case aerr == nil: // numeric < alphanumeric
			return -1
		case berr == nil:
			return 1
		default:
			return strings.Compare(as[i], bs[i])
		}
	}
	return cmpInt(len(as), len(bs))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// NewerRelease reports whether the manifest version is strictly
// newer than the current build, per the spec's comparison rule:
// semver first, versionCode as the tiebreak.
func NewerRelease(manifestVersion string, manifestCode int, currentVersion string, currentCode int) (bool, error) {
	mv, err := ParseSemver(manifestVersion)
	if err != nil {
		return false, err
	}
	cv, err := ParseSemver(currentVersion)
	if err != nil {
		return false, err
	}
	switch c := CompareSemver(mv, cv); {
	case c > 0:
		return true, nil
	case c < 0:
		return false, nil
	default:
		return manifestCode > currentCode, nil
	}
}

// ---------------------------------------------------------------------------
// Manifest (relavia-update/v1)
// ---------------------------------------------------------------------------

// UpdateArtifact is one platform's entry in the manifest.
type UpdateArtifact struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Sig      string `json:"sig"`
}

// UpdateManifest is a parsed relavia-update/v1 document.
type UpdateManifest struct {
	Format      string            `json:"format"`
	Version     string            `json:"version"`
	VersionCode int               `json:"versionCode"`
	Channel     string            `json:"channel"`
	Seq         int64             `json:"seq"`
	PublishedAt time.Time         `json:"publishedAt"`
	Notes       map[string]string `json:"notes"`
	Artifacts   []UpdateArtifact  `json:"artifacts"`
}

// Validate checks the structural rules of the format spec. Any
// violation makes the whole manifest unacceptable.
func (m *UpdateManifest) Validate() error {
	if m.Format != UpdateManifestFormat {
		return fmt.Errorf("format %q is not %q", m.Format, UpdateManifestFormat)
	}
	if m.Channel != ChannelStable && m.Channel != ChannelBeta {
		return fmt.Errorf("unknown channel %q", m.Channel)
	}
	if _, err := ParseSemver(m.Version); err != nil {
		return fmt.Errorf("version: %w", err)
	}
	if m.VersionCode < 0 {
		return errors.New("versionCode is negative")
	}
	if m.Seq < 1 {
		return errors.New("seq must be >= 1")
	}
	if m.PublishedAt.IsZero() {
		return errors.New("publishedAt is missing")
	}
	if len(m.Artifacts) == 0 {
		return errors.New("artifacts is empty")
	}
	for i := range m.Artifacts {
		if err := m.Artifacts[i].validate(); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", i, err)
		}
	}
	return nil
}

func (a *UpdateArtifact) validate() error {
	if a.Platform == "" {
		return errors.New("platform is empty")
	}
	if !strings.HasPrefix(a.URL, "https://") {
		return errors.New("url is not https")
	}
	if a.Size <= 0 {
		return errors.New("size must be > 0")
	}
	digest, err := hex.DecodeString(a.SHA256)
	if err != nil || len(digest) != sha256.Size || a.SHA256 != strings.ToLower(a.SHA256) {
		return errors.New("sha256 is not 64 lowercase hex characters")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("sig is not a base64 Ed25519 signature")
	}
	return nil
}

// ArtifactFor returns the artifact for a platform id, if present.
func (m *UpdateManifest) ArtifactFor(platform string) (UpdateArtifact, bool) {
	for _, a := range m.Artifacts {
		if a.Platform == platform {
			return a, true
		}
	}
	return UpdateArtifact{}, false
}

// Note returns the release note for a language, falling back to
// English and then to any available language.
func (m *UpdateManifest) Note(lang string) string {
	if n, ok := m.Notes[lang]; ok && n != "" {
		return n
	}
	if n, ok := m.Notes["en"]; ok {
		return n
	}
	for _, n := range m.Notes {
		return n
	}
	return ""
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Update error codes (docs/relavia-update-v1.md §6). The UI maps
// codes to localized strings via the update.* i18n keys.
const (
	CodeManifestFetch      = "update.manifest_fetch"
	CodeManifestInvalid    = "update.manifest_invalid"
	CodeRollbackDetected   = "update.rollback_detected"
	CodeNoArtifact         = "update.no_artifact"
	CodeDownloadFailed     = "update.download_failed"
	CodeDownloadCanceled   = "update.download_canceled"
	CodeHashMismatch       = "update.hash_mismatch"
	CodeSignatureInvalid   = "update.signature_invalid"
	CodeInstallUnavailable = "update.install_unavailable"
	CodeInstallFailed      = "update.install_failed"
)

// UpdateError is a typed update failure carrying a stable code.
type UpdateError struct {
	Code string
	Err  error
}

func (e *UpdateError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}

func (e *UpdateError) Unwrap() error { return e.Err }

func updateErr(code string, err error) *UpdateError { return &UpdateError{Code: code, Err: err} }

// UpdateCodeOf extracts the stable code from an error, or "".
func UpdateCodeOf(err error) string {
	var ue *UpdateError
	if errors.As(err, &ue) {
		return ue.Code
	}
	return ""
}

// ---------------------------------------------------------------------------
// Installer seam
// ---------------------------------------------------------------------------

// UpdateInstaller is the platform hand-off for a downloaded and
// verified artifact. The app/platform package provides the real
// implementations; the UI wires one into UpdaterConfig. Install
// must never leave the current version damaged: either the
// platform installer takes over completely, or it returns an
// error and the running version stays as it was.
type UpdateInstaller interface {
	Available() bool
	Install(path string) error
}

// UnavailableInstaller is the honest default: no in-app install
// on this platform/build yet.
type UnavailableInstaller struct{}

func (UnavailableInstaller) Available() bool { return false }
func (UnavailableInstaller) Install(string) error {
	return updateErr(CodeInstallUnavailable, errors.New("no update installer is wired on this platform"))
}

// ---------------------------------------------------------------------------
// Updater
// ---------------------------------------------------------------------------

// UpdaterConfig configures an Updater. Zero values fall back to
// the documented defaults (store settings, official URLs, the
// embedded release key).
type UpdaterConfig struct {
	Store      *Store // may be nil: anchors and prefs stay in memory
	HTTPClient *http.Client
	// ManifestURL overrides the per-channel default URL.
	ManifestURL string
	// Channel overrides the store's updateChannel setting.
	Channel string
	// Platform is the artifact platform id ("windows-amd64", ...).
	Platform string
	// CurrentVersion / CurrentVersionCode describe this build.
	CurrentVersion     string
	CurrentVersionCode int
	// PublicKey overrides the embedded release key (tests).
	PublicKey ed25519.PublicKey
	// Installer is the platform install hand-off.
	Installer UpdateInstaller
	// DownloadDir receives verified artifacts.
	DownloadDir string
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Updater is the update service. It is safe for concurrent use.
type Updater struct {
	cfg UpdaterConfig

	mu           sync.Mutex
	memSeenSeq   map[string]int64
	memSeenPub   map[string]time.Time
	memLastCheck time.Time
	memChannel   string
	memAutoCheck bool
	memHasPrefs  bool
}

// NewUpdater builds an Updater with defaults applied lazily.
func NewUpdater(cfg UpdaterConfig) *Updater {
	return &Updater{
		cfg:        cfg,
		memSeenSeq: make(map[string]int64),
		memSeenPub: make(map[string]time.Time),
	}
}

func (u *Updater) now() time.Time {
	if u.cfg.Now != nil {
		return u.cfg.Now()
	}
	return time.Now()
}

func (u *Updater) httpClient() *http.Client {
	if u.cfg.HTTPClient != nil {
		return u.cfg.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (u *Updater) currentVersion() string {
	if u.cfg.CurrentVersion != "" {
		return u.cfg.CurrentVersion
	}
	return ClientVersion
}

func (u *Updater) currentCode() int {
	if u.cfg.CurrentVersionCode != 0 {
		return u.cfg.CurrentVersionCode
	}
	return ClientVersionCode
}

func (u *Updater) publicKey() ed25519.PublicKey {
	if u.cfg.PublicKey != nil {
		return u.cfg.PublicKey
	}
	return ReleasePublicKey()
}

// DefaultUpdatePlatform is this build's artifact platform id.
func DefaultUpdatePlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

func (u *Updater) platform() string {
	if u.cfg.Platform != "" {
		return u.cfg.Platform
	}
	return DefaultUpdatePlatform()
}

// DefaultManifestURL is the official static manifest location for
// a channel (docs/relavia-update-v1.md §7).
func DefaultManifestURL(channel string) string {
	return "https://github.com/relavia/relavia/releases/latest/download/update-" + channel + ".json"
}

func (u *Updater) manifestURL(channel string) string {
	if u.cfg.ManifestURL != "" {
		return u.cfg.ManifestURL
	}
	return DefaultManifestURL(channel)
}

// Channel resolves the subscribed channel: explicit config, then
// the store setting, then stable.
func (u *Updater) Channel() string {
	if u.cfg.Channel != "" {
		return u.cfg.Channel
	}
	if u.cfg.Store != nil {
		if ch := u.cfg.Store.Settings().UpdateChannel; ch == ChannelBeta {
			return ChannelBeta
		}
		return ChannelStable
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.memHasPrefs && u.memChannel == ChannelBeta {
		return ChannelBeta
	}
	return ChannelStable
}

// SetChannel persists the subscribed channel.
func (u *Updater) SetChannel(channel string) error {
	if channel != ChannelStable && channel != ChannelBeta {
		return fmt.Errorf("unknown update channel %q", channel)
	}
	if u.cfg.Store != nil {
		u.cfg.Store.UpdateSettings(func(s *Settings) { s.UpdateChannel = channel })
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.memChannel, u.memHasPrefs = channel, true
	return nil
}

// AutoCheckEnabled reports the periodic-check opt-in (default off).
func (u *Updater) AutoCheckEnabled() bool {
	if u.cfg.Store != nil {
		return u.cfg.Store.Settings().UpdateAutoCheck
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.memHasPrefs && u.memAutoCheck
}

// SetAutoCheck persists the periodic-check opt-in.
func (u *Updater) SetAutoCheck(on bool) error {
	if u.cfg.Store != nil {
		u.cfg.Store.UpdateSettings(func(s *Settings) { s.UpdateAutoCheck = on })
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.memAutoCheck, u.memHasPrefs = on, true
	return nil
}

const autoCheckInterval = 24 * time.Hour

// AutoCheckDue reports whether a periodic check is due: the user
// opted in AND at least 24h passed since the last check. With the
// opt-in off (the default) this is always false — the client
// never fetches on its own initiative.
func (u *Updater) AutoCheckDue() bool {
	if !u.AutoCheckEnabled() {
		return false
	}
	return u.now().Sub(u.lastCheck()) >= autoCheckInterval
}

func (u *Updater) lastCheck() time.Time {
	if u.cfg.Store != nil {
		s := u.cfg.Store.Settings().UpdateLastCheck
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t
		}
		return time.Time{}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.memLastCheck
}

// seenAnchors returns the persisted rollback anchors for a channel.
func (u *Updater) seenAnchors(channel string) (seq int64, published time.Time) {
	if u.cfg.Store != nil {
		st := u.cfg.Store.Settings()
		seq = st.UpdateSeenSeq[channel]
		if s := st.UpdateSeenPublished[channel]; s != "" {
			published, _ = time.Parse(time.RFC3339, s)
		}
		return seq, published
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.memSeenSeq[channel], u.memSeenPub[channel]
}

// recordSeen advances the rollback anchors and the last-check
// timestamp after a manifest passed validation.
func (u *Updater) recordSeen(m *UpdateManifest) {
	if u.cfg.Store != nil {
		now := u.now().UTC().Format(time.RFC3339)
		u.cfg.Store.UpdateSettings(func(s *Settings) {
			if s.UpdateSeenSeq == nil {
				s.UpdateSeenSeq = make(map[string]int64)
			}
			if s.UpdateSeenPublished == nil {
				s.UpdateSeenPublished = make(map[string]string)
			}
			if m.Seq > s.UpdateSeenSeq[m.Channel] {
				s.UpdateSeenSeq[m.Channel] = m.Seq
			}
			if cur := s.UpdateSeenPublished[m.Channel]; cur == "" ||
				m.PublishedAt.UTC().Format(time.RFC3339) > cur {
				s.UpdateSeenPublished[m.Channel] = m.PublishedAt.UTC().Format(time.RFC3339)
			}
			s.UpdateLastCheck = now
		})
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if m.Seq > u.memSeenSeq[m.Channel] {
		u.memSeenSeq[m.Channel] = m.Seq
	}
	if m.PublishedAt.After(u.memSeenPub[m.Channel]) {
		u.memSeenPub[m.Channel] = m.PublishedAt
	}
	u.memLastCheck = u.now()
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

// UpdateInfo is what Check hands to the UI layer. Available means
// a newer release exists on the subscribed channel; NoArtifact
// means it exists but ships nothing for this platform.
type UpdateInfo struct {
	Available   bool
	NoArtifact  bool
	Version     string
	VersionCode int
	Channel     string
	Seq         int64
	PublishedAt time.Time
	Notes       map[string]string

	// Artifact details (empty when NoArtifact).
	Platform string
	URL      string
	Size     int64
	SHA256   string
	Sig      string
}

// Note returns the localized release note for the UI.
func (i *UpdateInfo) Note(lang string) string {
	if i == nil {
		return ""
	}
	m := &UpdateManifest{Notes: i.Notes}
	return m.Note(lang)
}

const maxManifestBytes = 1 << 20 // 1 MiB is generous for a manifest

// Check fetches and validates the channel manifest and reports
// whether an update is available. It downloads nothing else and
// installs nothing.
func (u *Updater) Check(ctx context.Context) (*UpdateInfo, error) {
	channel := u.Channel()
	raw, err := u.fetch(ctx, u.manifestURL(channel), maxManifestBytes)
	if err != nil {
		return nil, updateErr(CodeManifestFetch, err)
	}
	var m UpdateManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, updateErr(CodeManifestInvalid, fmt.Errorf("parse manifest: %w", err))
	}
	if err := m.Validate(); err != nil {
		return nil, updateErr(CodeManifestInvalid, err)
	}
	if m.Channel != channel {
		return nil, updateErr(CodeManifestInvalid,
			fmt.Errorf("manifest channel %q does not match subscribed channel %q", m.Channel, channel))
	}
	if m.PublishedAt.After(u.now().Add(7 * 24 * time.Hour)) {
		return nil, updateErr(CodeManifestInvalid, errors.New("publishedAt is implausibly far in the future"))
	}
	// Rollback guard (spec §5): a manifest older than one we have
	// already accepted must never win, even if it is well-formed
	// and validly signed.
	seenSeq, seenPub := u.seenAnchors(channel)
	if m.Seq < seenSeq {
		return nil, updateErr(CodeRollbackDetected,
			fmt.Errorf("manifest seq %d is below the accepted seq %d", m.Seq, seenSeq))
	}
	if m.Seq == seenSeq && !seenPub.IsZero() && m.PublishedAt.Before(seenPub) {
		return nil, updateErr(CodeRollbackDetected,
			errors.New("manifest publishedAt moved backwards at the same seq"))
	}
	u.recordSeen(&m)

	newer, err := NewerRelease(m.Version, m.VersionCode, u.currentVersion(), u.currentCode())
	if err != nil {
		return nil, updateErr(CodeManifestInvalid, err)
	}
	info := &UpdateInfo{
		Available:   newer,
		Version:     m.Version,
		VersionCode: m.VersionCode,
		Channel:     m.Channel,
		Seq:         m.Seq,
		PublishedAt: m.PublishedAt,
		Notes:       m.Notes,
		Platform:    u.platform(),
	}
	if !newer {
		return info, nil
	}
	art, ok := m.ArtifactFor(u.platform())
	if !ok {
		info.NoArtifact = true
		return info, nil
	}
	info.URL, info.Size, info.SHA256, info.Sig = art.URL, art.Size, art.SHA256, art.Sig
	return info, nil
}

// fetch GETs a URL with the privacy-minimal request shape: the
// only identifying header is "User-Agent: Relavia/<version>".
func (u *Updater) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Relavia/"+u.currentVersion())
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", url, limit)
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// Download + verify + install
// ---------------------------------------------------------------------------

// DownloadProgress receives (downloaded, total) byte counts while
// an artifact downloads. total is the manifest-declared size.
type DownloadProgress func(downloaded, total int64)

func (u *Updater) downloadDir() (string, error) {
	if u.cfg.DownloadDir != "" {
		return u.cfg.DownloadDir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Relavia", "updates"), nil
}

func artifactFileName(info *UpdateInfo) string {
	ext := filepath.Ext(strings.SplitN(info.URL, "?", 2)[0])
	name := "relavia-" + info.Version + "-" + info.Platform + ext
	return strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(name)
}

// Download fetches the artifact for an UpdateInfo previously
// returned by Check, verifies size, SHA-256 and the Ed25519
// release signature — in that order — and only then moves it into
// place. Any failure deletes the download; a canceled context
// leaves nothing behind. Call this ONLY after the user confirmed
// the update in the UI.
func (u *Updater) Download(ctx context.Context, info *UpdateInfo, progress DownloadProgress) (string, error) {
	if info == nil || !info.Available {
		return "", updateErr(CodeNoArtifact, errors.New("no update is available to download"))
	}
	if info.NoArtifact || info.URL == "" {
		return "", updateErr(CodeNoArtifact, fmt.Errorf("release %s ships no artifact for %s", info.Version, info.Platform))
	}
	dir, err := u.downloadDir()
	if err != nil {
		return "", updateErr(CodeDownloadFailed, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", updateErr(CodeDownloadFailed, err)
	}
	finalPath := filepath.Join(dir, artifactFileName(info))
	partPath := finalPath + ".part"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.URL, nil)
	if err != nil {
		return "", updateErr(CodeDownloadFailed, err)
	}
	req.Header.Set("User-Agent", "Relavia/"+u.currentVersion())
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return "", u.downloadErr(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", updateErr(CodeDownloadFailed, fmt.Errorf("GET %s: HTTP %d", info.URL, resp.StatusCode))
	}

	f, err := os.Create(partPath)
	if err != nil {
		return "", updateErr(CodeDownloadFailed, err)
	}
	hasher := sha256.New()
	var written int64
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, werr := f.Write(chunk); werr != nil {
				f.Close()
				os.Remove(partPath)
				return "", updateErr(CodeDownloadFailed, werr)
			}
			hasher.Write(chunk)
			written += int64(n)
			if progress != nil {
				progress(written, info.Size)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(partPath)
			return "", u.downloadErr(ctx, rerr)
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(partPath)
		return "", updateErr(CodeDownloadFailed, err)
	}

	// Verification chain (spec §4): size, then SHA-256 against the
	// manifest, then the Ed25519 signature over the ACTUAL digest.
	digest := hasher.Sum(nil)
	if written != info.Size || !strings.EqualFold(hex.EncodeToString(digest), info.SHA256) {
		os.Remove(partPath)
		return "", updateErr(CodeHashMismatch,
			fmt.Errorf("artifact hash/size does not match the manifest (got sha256 %s, %d bytes)", hex.EncodeToString(digest), written))
	}
	sig, err := base64.StdEncoding.DecodeString(info.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(u.publicKey(), digest, sig) {
		os.Remove(partPath)
		return "", updateErr(CodeSignatureInvalid, errors.New("release signature does not verify for the downloaded artifact"))
	}
	if err := os.Rename(partPath, finalPath); err != nil {
		os.Remove(partPath)
		return "", updateErr(CodeDownloadFailed, err)
	}
	return finalPath, nil
}

func (u *Updater) downloadErr(ctx context.Context, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return updateErr(CodeDownloadCanceled, err)
	}
	return updateErr(CodeDownloadFailed, err)
}

// Apply runs the post-confirmation flow: Download (with full
// verification) and then the platform install hand-off. It
// returns the verified artifact path even when the install step
// is unavailable or fails, so the UI can offer a manual path;
// the running version is never modified by a failed Apply.
func (u *Updater) Apply(ctx context.Context, info *UpdateInfo, progress DownloadProgress) (string, error) {
	path, err := u.Download(ctx, info, progress)
	if err != nil {
		return "", err
	}
	installer := u.cfg.Installer
	if installer == nil {
		installer = UnavailableInstaller{}
	}
	if !installer.Available() {
		return path, updateErr(CodeInstallUnavailable,
			errors.New("in-app install is not available on this platform yet; the verified package was kept for manual installation"))
	}
	if err := installer.Install(path); err != nil {
		if UpdateCodeOf(err) != "" {
			return path, err
		}
		return path, updateErr(CodeInstallFailed, err)
	}
	return path, nil
}
