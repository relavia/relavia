package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKeys generates an ephemeral keypair and writes it in the
// on-disk formats the tool consumes. Keys exist only for the life
// of the test — there are no key fixtures in this repository.
func testKeys(t *testing.T) (privPath, pubB64 string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(t.TempDir(), "release-test-only.key")
	privB64 := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(privPath, []byte(privB64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return privPath, base64.StdEncoding.EncodeToString(pub), pub
}

func writeArtifact(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// buildManifest runs the manifest subcommand against one artifact
// and returns the parsed manifest.
func buildManifest(t *testing.T, privPath, artifactPath string) (Manifest, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "update-stable.json")
	err := run([]string{"manifest",
		"--version", "0.2.0",
		"--channel", "stable",
		"--seq", "7",
		"--published-at", "2026-11-14T00:00:00Z",
		"--base-url", "https://example.invalid/releases/v0.2.0",
		"--key", privPath,
		"--artifact", "windows-amd64=" + artifactPath,
		"--out", out,
	})
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest output is not JSON: %v", err)
	}
	return m, out
}

func TestKeygenManifestVerifyRoundtrip(t *testing.T) {
	privPath, pubB64, pub := testKeys(t)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "relavia-windows-amd64.exe", "fake windows binary v0.2.0")

	m, manifestPath := buildManifest(t, privPath, artifact)

	// Shape checks against docs/relavia-update-v1.md §2.
	if m.Format != "relavia-update/v1" {
		t.Errorf("format = %q", m.Format)
	}
	if m.Version != "0.2.0" || m.VersionCode != 200 {
		t.Errorf("version/code = %s/%d, want 0.2.0/200", m.Version, m.VersionCode)
	}
	if m.Seq != 7 || m.Channel != "stable" {
		t.Errorf("seq/channel = %d/%q", m.Seq, m.Channel)
	}
	if m.Notes["en"] == "" {
		t.Error("notes.en missing")
	}
	if len(m.Artifacts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(m.Artifacts))
	}
	a := m.Artifacts[0]
	if a.Platform != "windows-amd64" {
		t.Errorf("platform = %q", a.Platform)
	}
	if a.Size != int64(len("fake windows binary v0.2.0")) {
		t.Errorf("size = %d", a.Size)
	}
	sum := sha256.Sum256([]byte("fake windows binary v0.2.0"))
	if a.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %q, want %q", a.SHA256, hex.EncodeToString(sum[:]))
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig does not decode to 64 bytes: %v", err)
	}
	// The signature must be over the RAW digest bytes (spec §4).
	if !ed25519.Verify(pub, sum[:], sig) {
		t.Error("sig does not verify over the raw digest")
	}
	if ed25519.Verify(pub, []byte(a.SHA256), sig) {
		t.Error("sig must NOT verify over the hex text (spec §4 forbids it)")
	}

	// Full verify, including re-hashing the file from its dir.
	if err := run([]string{"verify", "--manifest", manifestPath, "--pubkey", pubB64, "--dir", dir}); err != nil {
		t.Errorf("verify roundtrip: %v", err)
	}
}

func TestVerifyRejectsTamperedManifestFields(t *testing.T) {
	privPath, pubB64, pub := testKeys(t)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "relavia-windows-amd64.exe", "payload")
	good, _ := buildManifest(t, privPath, artifact)

	cases := map[string]func(m *Manifest){
		"sha256 flipped": func(m *Manifest) {
			b := []byte(m.Artifacts[0].SHA256)
			if b[0] == '0' {
				b[0] = '1'
			} else {
				b[0] = '0'
			}
			m.Artifacts[0].SHA256 = string(b)
		},
		"sig flipped": func(m *Manifest) {
			sig, _ := base64.StdEncoding.DecodeString(m.Artifacts[0].Sig)
			sig[0] ^= 0xff
			m.Artifacts[0].Sig = base64.StdEncoding.EncodeToString(sig)
		},
		"sig emptied (unsigned draft)": func(m *Manifest) { m.Artifacts[0].Sig = "" },
		"format wrong":                 func(m *Manifest) { m.Format = "relavia-update/v2" },
		"seq zero":                     func(m *Manifest) { m.Seq = 0 },
		"versionCode inconsistent":     func(m *Manifest) { m.VersionCode = 999 },
		"size zero":                    func(m *Manifest) { m.Artifacts[0].Size = 0 },
	}
	for name, mutate := range cases {
		m := good // shallow copy; artifacts slice shared but we replace fields per-case on a fresh copy below
		raw, _ := json.Marshal(good)
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mutate(&m)
		var buf bytes.Buffer
		if err := verifyManifest(&m, pub, "", &buf); err == nil {
			t.Errorf("%s: verify succeeded, want failure (output: %s)", name, buf.String())
		}
	}
	_ = pubB64
}

func TestVerifyRejectsWrongKeyAndTamperedFile(t *testing.T) {
	privPath, _, pub := testKeys(t)
	_, otherPub, _ := testKeys(t)
	_ = otherPub
	_, _, wrongPub := testKeys(t)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "relavia-windows-amd64.exe", "original bytes")
	_, manifestPath := buildManifest(t, privPath, artifact)

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := verifyManifest(&m, wrongPub, "", &buf); err == nil {
		t.Error("verify with wrong public key succeeded, want failure")
	}
	buf.Reset()
	if err := verifyManifest(&m, pub, dir, &buf); err != nil {
		t.Errorf("verify with correct key + pristine file failed: %v", err)
	}
	// Tamper with the artifact file: one appended byte changes
	// both its hash and its size.
	f, err := os.OpenFile(artifact, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	buf.Reset()
	if err := verifyManifest(&m, pub, dir, &buf); err == nil {
		t.Error("verify with tampered artifact file succeeded, want failure")
	}
}

func TestManifestUnsignedDraftHasEmptySig(t *testing.T) {
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "a.bin", "data")
	out := filepath.Join(dir, "update-beta.json")
	err := run([]string{"manifest",
		"--version", "0.3.0-beta.1", "--channel", "beta", "--seq", "1",
		"--artifact", "android-arm64=" + artifact,
		"--out", out,
	})
	if err != nil {
		t.Fatalf("unsigned draft manifest: %v", err)
	}
	raw, _ := os.ReadFile(out)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Artifacts[0].Sig != "" {
		t.Errorf("unsigned draft sig = %q, want empty", m.Artifacts[0].Sig)
	}
	if m.VersionCode != 300 {
		t.Errorf("versionCode for 0.3.0-beta.1 = %d, want 300 (prerelease ignored)", m.VersionCode)
	}
	if !strings.HasSuffix(out, "update-beta.json") {
		t.Errorf("unexpected out path %s", out)
	}
}

func TestManifestRequiresSeqAndRejectsDuplicatePlatform(t *testing.T) {
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "a.bin", "data")
	out := filepath.Join(dir, "u.json")
	if err := run([]string{"manifest", "--version", "0.1.0",
		"--artifact", "windows-amd64=" + artifact, "--out", out}); err == nil {
		t.Error("manifest without --seq succeeded, want failure")
	}
	privPath, _, _ := testKeys(t)
	if err := run([]string{"manifest", "--version", "0.1.0", "--seq", "1", "--key", privPath,
		"--artifact", "windows-amd64=" + artifact,
		"--artifact", "windows-amd64=" + artifact,
		"--out", out}); err == nil {
		t.Error("manifest with duplicate platform succeeded, want failure")
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "k.key")
	pub := filepath.Join(dir, "k.pub")
	if err := run([]string{"keygen", "--out-priv", priv, "--out-pub", pub}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	info, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %o, want 600", info.Mode().Perm())
	}
	if err := run([]string{"keygen", "--out-priv", priv, "--out-pub", pub}); err == nil {
		t.Error("second keygen without --force succeeded, want refusal")
	}
	// The generated key must load and its public half must match.
	loaded, err := loadPrivateKey(priv)
	if err != nil {
		t.Fatalf("loadPrivateKey: %v", err)
	}
	rawPub, _ := os.ReadFile(pub)
	pubFromFile, err := loadPublicKey(strings.TrimSpace(string(rawPub)))
	if err != nil {
		t.Fatalf("loadPublicKey: %v", err)
	}
	if !bytes.Equal(loaded.Public().(ed25519.PublicKey), pubFromFile) {
		t.Error("keygen private/public halves do not match")
	}
}

func TestVersionCodeOf(t *testing.T) {
	for in, want := range map[string]int{
		"0.1.0":        100,
		"0.2.0":        200,
		"v1.2.3":       10203,
		"0.3.0-beta.1": 300,
		"10.20.30":     102030,
	} {
		got, err := versionCodeOf(in)
		if err != nil || got != want {
			t.Errorf("versionCodeOf(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "1.0", "a.b.c", "1.2.x"} {
		if _, err := versionCodeOf(bad); err == nil {
			t.Errorf("versionCodeOf(%q) succeeded, want error", bad)
		}
	}
}
