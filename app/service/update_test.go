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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// TEST-ONLY release keypair. The private key below signs ONLY the
// fixtures in this file; the matching public key is the TEST key
// embedded in releasekey.go. The second keypair is the "attacker"
// key for the forgery cases. Neither must ever sign a real
// release (see releasekey.go).
// ============================================================================

const (
	testReleasePrivB64 = "UQJS7eVZe3mJDK7cJ2t4zOzjlWsZNE0cxRFz8Ht2Nv2IvuNWNoWcQEk/M1YrXCB0ur2Qw6QVTEOw1l+tbEm9Og=="
	forgePrivB64       = "HHmj596H7WACAitNytrbw8i41XZK9RhQXa84mhl/E/rulavgm70evzW3P/EPLsLJjaaz7FeLTQputCZ7NeLODQ=="
)

func mustPriv(t *testing.T, b64 string) ed25519.PrivateKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		t.Fatalf("bad test key: %v", err)
	}
	return ed25519.PrivateKey(raw)
}

func signDigest(priv ed25519.PrivateKey, artifact []byte) (shaHex, sigB64 string) {
	digest := sha256.Sum256(artifact)
	return hex.EncodeToString(digest[:]),
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))
}

// manifestFixture builds a valid relavia-update/v1 manifest for
// the given artifact, signed with priv. mutate may adjust fields
// after signing-relevant values are computed (hash/sig stay as
// computed unless mutate changes them — that is the point of the
// tamper cases).
func manifestFixture(t *testing.T, priv ed25519.PrivateKey, artifact []byte, artifactURL string, mutate func(*UpdateManifest)) []byte {
	t.Helper()
	shaHex, sigB64 := signDigest(priv, artifact)
	m := &UpdateManifest{
		Format:      UpdateManifestFormat,
		Version:     "0.2.0",
		VersionCode: 200,
		Channel:     ChannelStable,
		Seq:         7,
		PublishedAt: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		Notes:       map[string]string{"en": "Bug fixes.", "zh-Hans": "修复问题。"},
		Artifacts: []UpdateArtifact{{
			Platform: "linux-amd64",
			URL:      artifactURL,
			Size:     int64(len(artifact)),
			SHA256:   shaHex,
			Sig:      sigB64,
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// updateRig is an httptest TLS server (the manifest validator
// requires https artifact URLs) serving a swappable manifest and
// artifact, recording request shapes for the privacy assertions.
type updateRig struct {
	srv *httptest.Server

	mu           sync.Mutex
	manifest     []byte
	artifact     []byte
	artifactHook func(w http.ResponseWriter, r *http.Request)
	userAgents   []string
	headerSets   []http.Header
}

func newUpdateRig(t *testing.T) *updateRig {
	t.Helper()
	rig := &updateRig{}
	mux := http.NewServeMux()
	mux.HandleFunc("/update-stable.json", func(w http.ResponseWriter, r *http.Request) {
		rig.record(r)
		rig.mu.Lock()
		body := rig.manifest
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/artifact.bin", func(w http.ResponseWriter, r *http.Request) {
		rig.record(r)
		rig.mu.Lock()
		hook, body := rig.artifactHook, rig.artifact
		rig.mu.Unlock()
		if hook != nil {
			hook(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	rig.srv = httptest.NewTLSServer(mux)
	t.Cleanup(rig.srv.Close)
	return rig
}

func (r *updateRig) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.userAgents = append(r.userAgents, req.UserAgent())
	r.headerSets = append(r.headerSets, req.Header.Clone())
}

func (r *updateRig) set(manifest, artifact []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifest, r.artifact = manifest, artifact
}

func (r *updateRig) artifactURL() string { return r.srv.URL + "/artifact.bin" }
func (r *updateRig) manifestURL() string { return r.srv.URL + "/update-stable.json" }

func (r *updateRig) newUpdater(t *testing.T, store *Store, extra func(*UpdaterConfig)) *Updater {
	t.Helper()
	cfg := UpdaterConfig{
		Store:       store,
		HTTPClient:  r.srv.Client(),
		ManifestURL: r.manifestURL(),
		Platform:    "linux-amd64",
		DownloadDir: t.TempDir(),
		Now:         func() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) },
	}
	if extra != nil {
		extra(&cfg)
	}
	return NewUpdater(cfg)
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testArtifact() []byte {
	return []byte("relavia-fake-installer-payload\x00\x01\x02" + strings.Repeat("x", 4096))
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.1.0", 0},
		{"0.2.0", "0.1.0", 1},
		{"0.1.0", "0.2.0", -1},
		{"1.0.0", "0.9.9", 1},
		{"0.1.1", "0.1.0", 1},
		{"v0.2.0", "0.2.0", 0},
		{"0.2.0-beta.1", "0.2.0", -1},             // prerelease < release
		{"0.2.0", "0.2.0-beta.1", 1},              //
		{"0.2.0-beta.2", "0.2.0-beta.1", 1},       // numeric identifiers compare numerically
		{"0.2.0-beta.10", "0.2.0-beta.9", 1},      //
		{"0.2.0-alpha", "0.2.0-alpha.1", -1},      // shorter list < longer
		{"0.2.0-alpha.1", "0.2.0-alpha.beta", -1}, // numeric < alphanumeric
		{"0.2.0-rc.1", "0.2.0-beta.2", 1},         // lexical for alphanumeric
	}
	for _, c := range cases {
		a, err := ParseSemver(c.a)
		if err != nil {
			t.Fatalf("ParseSemver(%q): %v", c.a, err)
		}
		b, err := ParseSemver(c.b)
		if err != nil {
			t.Fatalf("ParseSemver(%q): %v", c.b, err)
		}
		if got := CompareSemver(a, b); got != c.want {
			t.Errorf("CompareSemver(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"", "1.0", "1.0.x", "1..0", "0.1.0-", "a.b.c"} {
		if _, err := ParseSemver(bad); err == nil {
			t.Errorf("ParseSemver(%q) succeeded, want error", bad)
		}
	}
}

func TestNewerRelease(t *testing.T) {
	cases := []struct {
		mv   string
		mc   int
		cv   string
		cc   int
		want bool
	}{
		{"0.2.0", 200, "0.1.0", 100, true},
		{"0.1.0", 100, "0.1.0", 100, false},
		{"0.0.9", 9, "0.1.0", 100, false},
		{"0.1.0", 101, "0.1.0", 100, true}, // same semver, higher code
		{"0.1.0", 99, "0.1.0", 100, false}, // same semver, lower code
		{"0.2.0-beta.1", 200, "0.1.0", 100, true},
		{"0.2.0-beta.1", 200, "0.2.0", 200, false}, // prerelease of current release
	}
	for _, c := range cases {
		got, err := NewerRelease(c.mv, c.mc, c.cv, c.cc)
		if err != nil {
			t.Fatalf("NewerRelease(%v): %v", c, err)
		}
		if got != c.want {
			t.Errorf("NewerRelease(%s/%d vs %s/%d) = %v, want %v", c.mv, c.mc, c.cv, c.cc, got, c.want)
		}
	}
	if got := VersionCodeOf(0, 2, 0); got != 200 {
		t.Errorf("VersionCodeOf(0,2,0) = %d, want 200", got)
	}
	if got := VersionCodeOf(1, 0, 0); got != 10000 {
		t.Errorf("VersionCodeOf(1,0,0) = %d, want 10000", got)
	}
}

// ---------------------------------------------------------------------------
// Check flow
// ---------------------------------------------------------------------------

func TestCheckFindsUpdate(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	u := rig.newUpdater(t, newTestStore(t), nil)
	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || info.NoArtifact {
		t.Fatalf("info = %+v, want available with artifact", info)
	}
	if info.Version != "0.2.0" || info.VersionCode != 200 || info.Seq != 7 {
		t.Errorf("info version/code/seq = %s/%d/%d", info.Version, info.VersionCode, info.Seq)
	}
	if info.Size != int64(len(artifact)) || info.URL != rig.artifactURL() {
		t.Errorf("info artifact = %s (%d bytes)", info.URL, info.Size)
	}
	if got := info.Note("zh-Hans"); got != "修复问题。" {
		t.Errorf("Note(zh-Hans) = %q", got)
	}
	if got := info.Note("fr"); got != "Bug fixes." { // unknown language falls back to en
		t.Errorf("Note(fr) = %q, want en fallback", got)
	}
}

func TestCheckUpToDateAndOlder(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	u := rig.newUpdater(t, newTestStore(t), nil)

	// Same version as the build: no update.
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) {
		m.Version, m.VersionCode = "0.1.0", 100
	}), artifact)
	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Available {
		t.Errorf("same-version manifest reported available: %+v", info)
	}

	// Older version: still no update, and NOT an error.
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) {
		m.Version, m.VersionCode, m.Seq = "0.0.9", 9, 8
	}), artifact)
	info, err = u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Available {
		t.Errorf("older manifest reported available: %+v", info)
	}
}

func TestCheckNoArtifactForPlatform(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	u := rig.newUpdater(t, newTestStore(t), func(c *UpdaterConfig) { c.Platform = "windows-amd64" })
	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || !info.NoArtifact {
		t.Fatalf("info = %+v, want Available && NoArtifact", info)
	}
	if _, err := u.Download(context.Background(), info, nil); UpdateCodeOf(err) != CodeNoArtifact {
		t.Errorf("Download err code = %q, want %q", UpdateCodeOf(err), CodeNoArtifact)
	}
}

func TestCheckInvalidManifests(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	u := rig.newUpdater(t, newTestStore(t), nil)
	valid := manifestFixture(t, priv, artifact, rig.artifactURL(), nil)

	cases := map[string][]byte{
		"not json at all":   []byte("{nope"),
		"wrong format tag":  manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Format = "relavia-update/v99" }),
		"channel mismatch":  manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Channel = ChannelBeta }),
		"seq zero":          manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Seq = 0 }),
		"bad sha256 field":  manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Artifacts[0].SHA256 = "xyz" }),
		"bad sig field":     manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Artifacts[0].Sig = "!!!" }),
		"http artifact url": manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Artifacts[0].URL = "http://example.com/x.exe" }),
		"publishedAt too far in the future": manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) {
			m.PublishedAt = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		}),
		"no artifacts": manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) { m.Artifacts = nil }),
	}
	for name, body := range cases {
		rig.set(body, artifact)
		if _, err := u.Check(context.Background()); UpdateCodeOf(err) != CodeManifestInvalid {
			t.Errorf("%s: code = %q (err %v), want %q", name, UpdateCodeOf(err), err, CodeManifestInvalid)
		}
	}
	// The valid manifest still passes after all the garbage.
	rig.set(valid, artifact)
	if _, err := u.Check(context.Background()); err != nil {
		t.Errorf("valid manifest after invalid ones: %v", err)
	}
}

func TestCheckManifestFetchFailure(t *testing.T) {
	u := NewUpdater(UpdaterConfig{
		ManifestURL: "https://127.0.0.1:1/update-stable.json",
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
	})
	if _, err := u.Check(context.Background()); UpdateCodeOf(err) != CodeManifestFetch {
		t.Errorf("code = %q, want %q", UpdateCodeOf(err), CodeManifestFetch)
	}
}

// ---------------------------------------------------------------------------
// Rollback protection
// ---------------------------------------------------------------------------

func TestCheckRollbackBySeq(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	store := newTestStore(t)
	u := rig.newUpdater(t, store, nil)

	// Accept seq 7 first.
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A fresh Updater over the same store (anchors are persisted,
	// not in-memory) is served an older manifest — validly signed,
	// advertising an even NEWER version. The seq guard must fire.
	u2 := rig.newUpdater(t, store, nil)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) {
		m.Seq = 6
		m.Version, m.VersionCode = "0.3.0", 300
	}), artifact)
	if _, err := u2.Check(context.Background()); UpdateCodeOf(err) != CodeRollbackDetected {
		t.Errorf("code = %q (err %v), want %q", UpdateCodeOf(err), err, CodeRollbackDetected)
	}
	// The rejected manifest must not have moved the anchor.
	if seq, _ := u2.seenAnchors(ChannelStable); seq != 7 {
		t.Errorf("anchor seq = %d after rollback attempt, want 7", seq)
	}
}

func TestCheckRollbackSameSeqOlderPublished(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	u := rig.newUpdater(t, newTestStore(t), nil)

	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) {
		m.PublishedAt = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC) // same seq 7, earlier
	}), artifact)
	if _, err := u.Check(context.Background()); UpdateCodeOf(err) != CodeRollbackDetected {
		t.Errorf("code = %q, want %q", UpdateCodeOf(err), CodeRollbackDetected)
	}
}

// ---------------------------------------------------------------------------
// Download + verification chain (incl. the Step 16 acceptance negatives)
// ---------------------------------------------------------------------------

func rigInfo(t *testing.T, rig *updateRig, u *Updater) *UpdateInfo {
	t.Helper()
	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Available || info.NoArtifact {
		t.Fatalf("info = %+v", info)
	}
	return info
}

func assertNoArtifactFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".part") || strings.HasPrefix(e.Name(), "relavia-") {
			t.Errorf("leftover file after rejected download: %s", e.Name())
		}
	}
}

func TestDownloadAndVerifyHappyPath(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	u := rig.newUpdater(t, newTestStore(t), nil)
	info := rigInfo(t, rig, u)

	var lastDone, lastTotal int64
	path, err := u.Download(context.Background(), info, func(done, total int64) {
		lastDone, lastTotal = done, total
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(artifact) {
		t.Errorf("downloaded bytes differ from the artifact")
	}
	if lastDone != int64(len(artifact)) || lastTotal != int64(len(artifact)) {
		t.Errorf("final progress = %d/%d, want %d/%d", lastDone, lastTotal, len(artifact), len(artifact))
	}
	if strings.HasSuffix(path, ".part") {
		t.Errorf("final path still has .part suffix: %s", path)
	}
}

// ACCEPTANCE NEGATIVE (Step 16): one flipped byte in the served
// artifact must be rejected and deleted.
func TestDownloadTamperedArtifactRejected(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	// Serve a tampered copy: flip one byte in the middle.
	tampered := append([]byte(nil), artifact...)
	tampered[len(tampered)/2] ^= 0xFF
	rig.mu.Lock()
	rig.artifact = tampered
	rig.mu.Unlock()

	u := rig.newUpdater(t, newTestStore(t), nil)
	info := rigInfo(t, rig, u)
	dir := u.cfg.DownloadDir
	if _, err := u.Download(context.Background(), info, nil); UpdateCodeOf(err) != CodeHashMismatch {
		t.Fatalf("code = %q (err %v), want %q", UpdateCodeOf(err), err, CodeHashMismatch)
	}
	assertNoArtifactFiles(t, dir)
}

// ACCEPTANCE NEGATIVE: the manifest's sha256 field itself is
// swapped (e.g. by a compromised mirror) while sig stays the one
// over the real digest. The hash comparison must reject.
func TestDownloadManifestHashTamperedRejected(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	other := sha256.Sum256([]byte("some other payload"))
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), func(m *UpdateManifest) {
		m.Artifacts[0].SHA256 = hex.EncodeToString(other[:])
	}), artifact)

	u := rig.newUpdater(t, newTestStore(t), nil)
	info := rigInfo(t, rig, u)
	if _, err := u.Download(context.Background(), info, nil); UpdateCodeOf(err) != CodeHashMismatch {
		t.Fatalf("code = %q, want %q", UpdateCodeOf(err), CodeHashMismatch)
	}
	assertNoArtifactFiles(t, u.cfg.DownloadDir)
}

// ACCEPTANCE NEGATIVE: sha256 in the manifest matches the real
// artifact, but the signature was made with an attacker's key.
func TestDownloadForgedSignatureRejected(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	forge := mustPriv(t, forgePrivB64)
	rig.set(manifestFixture(t, forge, artifact, rig.artifactURL(), nil), artifact)

	u := rig.newUpdater(t, newTestStore(t), nil) // verifies with the embedded TEST release key
	info := rigInfo(t, rig, u)
	if _, err := u.Download(context.Background(), info, nil); UpdateCodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("code = %q, want %q", UpdateCodeOf(err), CodeSignatureInvalid)
	}
	assertNoArtifactFiles(t, u.cfg.DownloadDir)
}

// ACCEPTANCE NEGATIVE: a truncated download (size mismatch) is
// rejected, not partially kept.
func TestDownloadTruncatedRejected(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact[:len(artifact)/2])

	u := rig.newUpdater(t, newTestStore(t), nil)
	info := rigInfo(t, rig, u)
	if _, err := u.Download(context.Background(), info, nil); UpdateCodeOf(err) != CodeHashMismatch {
		t.Fatalf("code = %q, want %q", UpdateCodeOf(err), CodeHashMismatch)
	}
	assertNoArtifactFiles(t, u.cfg.DownloadDir)
}

func TestDownloadCanceledLeavesNothing(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	// The artifact endpoint dribbles a chunk, then blocks until
	// the request dies.
	rig.mu.Lock()
	rig.artifactHook = func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		_, _ = w.Write(artifact[:1024])
		if fl != nil {
			fl.Flush()
		}
		<-r.Context().Done()
	}
	rig.mu.Unlock()

	u := rig.newUpdater(t, newTestStore(t), nil)
	info := rigInfo(t, rig, u)

	ctx, cancel := context.WithCancel(context.Background())
	progressSeen := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, err := u.Download(ctx, info, func(doneBytes, total int64) {
			select {
			case progressSeen <- struct{}{}:
			default:
			}
		})
		done <- err
	}()
	select {
	case <-progressSeen:
	case <-time.After(10 * time.Second):
		t.Fatal("no download progress within 10s")
	}
	cancel()
	select {
	case err := <-done:
		if UpdateCodeOf(err) != CodeDownloadCanceled {
			t.Fatalf("code = %q (err %v), want %q", UpdateCodeOf(err), err, CodeDownloadCanceled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("download did not stop after cancel")
	}
	assertNoArtifactFiles(t, u.cfg.DownloadDir)
}

// ---------------------------------------------------------------------------
// Apply: the platform hand-off
// ---------------------------------------------------------------------------

type fakeInstaller struct {
	available bool
	err       error
	calls     int
	lastPath  string
}

func (f *fakeInstaller) Available() bool { return f.available }
func (f *fakeInstaller) Install(path string) error {
	f.calls++
	f.lastPath = path
	return f.err
}

func TestApplyHappyPathHandsVerifiedFileToInstaller(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	inst := &fakeInstaller{available: true}
	u := rig.newUpdater(t, newTestStore(t), func(c *UpdaterConfig) { c.Installer = inst })
	info := rigInfo(t, rig, u)

	path, err := u.Apply(context.Background(), info, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inst.calls != 1 || inst.lastPath != path {
		t.Errorf("installer calls = %d, lastPath = %q, want 1 call with %q", inst.calls, inst.lastPath, path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("verified artifact missing after Apply: %v", err)
	}
}

func TestApplyInstallerUnavailableKeepsVerifiedPackage(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	u := rig.newUpdater(t, newTestStore(t), nil) // no installer wired → UnavailableInstaller
	info := rigInfo(t, rig, u)

	path, err := u.Apply(context.Background(), info, nil)
	if UpdateCodeOf(err) != CodeInstallUnavailable {
		t.Fatalf("code = %q (err %v), want %q", UpdateCodeOf(err), err, CodeInstallUnavailable)
	}
	if path == "" {
		t.Fatal("Apply returned no path; the verified package should be kept for manual install")
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil || string(got) != string(artifact) {
		t.Errorf("kept package unreadable or wrong: %v", rerr)
	}
}

func TestApplyInstallerFailureKeepsPackageAndOldVersion(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	inst := &fakeInstaller{available: true, err: errors.New("installer exploded")}
	u := rig.newUpdater(t, newTestStore(t), func(c *UpdaterConfig) { c.Installer = inst })
	info := rigInfo(t, rig, u)

	path, err := u.Apply(context.Background(), info, nil)
	if UpdateCodeOf(err) != CodeInstallFailed {
		t.Fatalf("code = %q, want %q", UpdateCodeOf(err), CodeInstallFailed)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Errorf("verified package should survive an install failure: %v", serr)
	}
}

// ---------------------------------------------------------------------------
// Privacy shape + periodic-check opt-in
// ---------------------------------------------------------------------------

func TestRequestsCarryNoDeviceIdentity(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	u := rig.newUpdater(t, newTestStore(t), nil)
	info := rigInfo(t, rig, u)
	if _, err := u.Download(context.Background(), info, nil); err != nil {
		t.Fatal(err)
	}

	rig.mu.Lock()
	defer rig.mu.Unlock()
	if len(rig.userAgents) < 2 {
		t.Fatalf("expected manifest + artifact requests, got %d", len(rig.userAgents))
	}
	for i, ua := range rig.userAgents {
		if ua != "Relavia/"+ClientVersion {
			t.Errorf("request %d User-Agent = %q, want exactly %q", i, ua, "Relavia/"+ClientVersion)
		}
	}
	for i, h := range rig.headerSets {
		for name := range h {
			if strings.HasPrefix(strings.ToLower(name), "x-") {
				t.Errorf("request %d carries a custom header %q — update traffic must not carry identifiers", i, name)
			}
		}
		if h.Get("Accept-Language") != "" {
			t.Errorf("request %d leaks Accept-Language", i)
		}
	}
}

func TestAutoCheckIsOptInAndThrottled(t *testing.T) {
	rig := newUpdateRig(t)
	artifact := testArtifact()
	priv := mustPriv(t, testReleasePrivB64)
	rig.set(manifestFixture(t, priv, artifact, rig.artifactURL(), nil), artifact)

	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	u := rig.newUpdater(t, newTestStore(t), func(c *UpdaterConfig) {
		c.Now = func() time.Time { return now }
	})

	if u.AutoCheckEnabled() {
		t.Fatal("periodic check must default to OFF")
	}
	if u.AutoCheckDue() {
		t.Fatal("AutoCheckDue with opt-in off")
	}
	if err := u.SetAutoCheck(true); err != nil {
		t.Fatal(err)
	}
	if !u.AutoCheckDue() {
		t.Fatal("opted in and never checked: should be due")
	}
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u.AutoCheckDue() {
		t.Fatal("just checked: must not be due again")
	}
	now = now.Add(23 * time.Hour)
	if u.AutoCheckDue() {
		t.Fatal("23h later: still within the 24h throttle")
	}
	now = now.Add(2 * time.Hour)
	if !u.AutoCheckDue() {
		t.Fatal("25h later: should be due again")
	}
	// Channel preference persists and validates.
	if err := u.SetChannel("nightly"); err == nil {
		t.Error("SetChannel(nightly) accepted an unknown channel")
	}
	if err := u.SetChannel(ChannelBeta); err != nil {
		t.Fatal(err)
	}
	if got := u.Channel(); got != ChannelBeta {
		t.Errorf("Channel() = %q, want beta", got)
	}
}

func TestDefaultManifestURLs(t *testing.T) {
	if got := DefaultManifestURL(ChannelStable); !strings.HasSuffix(got, "update-stable.json") || !strings.HasPrefix(got, "https://github.com/relavia/relavia/releases/") {
		t.Errorf("stable URL = %q", got)
	}
	if got := DefaultManifestURL(ChannelBeta); !strings.HasSuffix(got, "update-beta.json") {
		t.Errorf("beta URL = %q", got)
	}
	fmt.Sscan("") // keep fmt import if assertions above change
}
