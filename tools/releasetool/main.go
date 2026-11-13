// Command releasetool is the signing half of the Relavia release
// pipeline (proposal book Step 15). It implements the producer side
// of the update-manifest format relavia-update/v1, whose normative
// spec is docs/relavia-update-v1.md (owned by Step 16; this tool
// follows it field for field — any divergence is a bug here, not a
// format change).
//
// Subcommands:
//
//	keygen    generate the project release keypair (Ed25519)
//	manifest  hash artifacts, sign their SHA-256 digests, and emit
//	          an update-<channel>.json manifest
//	verify    verify a manifest against the release public key,
//	          optionally re-hashing artifact files from a directory
//
// Key material handling: the tool only ever reads key FILES (paths
// given by flag or by the RELAVIA_RELEASE_KEY / RELAVIA_RELEASE_PUBKEY
// environment variables). Keys are never printed, never written
// anywhere except by keygen, and must never be committed to the
// repository. Test keys used in drills are labelled test-only and
// live outside the repo (see docs/step15-签名与可复现构建.md).
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Manifest mirrors docs/relavia-update-v1.md §2 exactly. Field
// order in the emitted JSON follows the spec's example.
type Manifest struct {
	Format      string            `json:"format"`
	Version     string            `json:"version"`
	VersionCode int               `json:"versionCode"`
	Channel     string            `json:"channel"`
	Seq         int64             `json:"seq"`
	PublishedAt string            `json:"publishedAt"`
	Notes       map[string]string `json:"notes"`
	Artifacts   []Artifact        `json:"artifacts"`
}

// Artifact mirrors docs/relavia-update-v1.md §2 (artifacts[] entry).
type Artifact struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Sig      string `json:"sig"`
}

const formatName = "relavia-update/v1"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasetool:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: releasetool <keygen|manifest|verify> [flags]")
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:])
	case "manifest":
		return cmdManifest(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (want keygen|manifest|verify)", args[0])
	}
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	outPriv := fs.String("out-priv", "", "write the private key (base64) to this path (mode 0600)")
	outPub := fs.String("out-pub", "", "write the public key (base64) to this path")
	force := fs.Bool("force", false, "overwrite existing key files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outPriv == "" || *outPub == "" {
		return errors.New("keygen: --out-priv and --out-pub are both required")
	}
	for _, p := range []string{*outPriv, *outPub} {
		if _, err := os.Stat(p); err == nil && !*force {
			return fmt.Errorf("keygen: %s already exists (refusing to overwrite without --force)", p)
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(*outPriv, []byte(privB64+"\n"), 0o600); err != nil {
		return fmt.Errorf("keygen: write private key: %w", err)
	}
	// WriteFile honours the mode only on creation; tighten anyway.
	_ = os.Chmod(*outPriv, 0o600)
	if err := os.WriteFile(*outPub, []byte(pubB64+"\n"), 0o644); err != nil {
		return fmt.Errorf("keygen: write public key: %w", err)
	}
	fmt.Printf("public key:  %s\n", pubB64)
	fmt.Printf("fingerprint: %s\n", PublicKeyFingerprint(pub))
	fmt.Printf("private key written to %s (mode 0600) — keep it OUT of the repository\n", *outPriv)
	return nil
}

// PublicKeyFingerprint returns an SSH-style SHA256 fingerprint of a
// raw Ed25519 public key, for out-of-band comparison when the key
// is published (website, docs).
func PublicKeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// key loading
// ---------------------------------------------------------------------------

// loadPrivateKey reads a base64 Ed25519 private key file. Accepts
// the 64-byte private key form or a bare 32-byte seed.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("private key file %s is not base64: %w", path, err)
	}
	switch len(decoded) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	default:
		return nil, fmt.Errorf("private key file %s: decoded length %d, want %d (key) or %d (seed)",
			path, len(decoded), ed25519.PrivateKeySize, ed25519.SeedSize)
	}
}

// loadPublicKey accepts a path to a base64 public-key file, or a
// literal base64 public key.
func loadPublicKey(spec string) (ed25519.PublicKey, error) {
	data := spec
	if raw, err := os.ReadFile(spec); err == nil {
		data = strings.TrimSpace(string(raw))
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key decoded length %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// ---------------------------------------------------------------------------
// version helpers (encoding per docs/relavia-update-v1.md §2/§3)
// ---------------------------------------------------------------------------

// versionCodeOf encodes MAJOR.MINOR.PATCH as
// MAJOR*10000 + MINOR*100 + PATCH. A leading "v" and any
// "-prerelease" suffix are ignored for the numeric triple, exactly
// like service.VersionCodeOf on the client side.
func versionCodeOf(version string) (int, error) {
	s := strings.TrimPrefix(version, "v")
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", version)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("version %q has a non-numeric component %q", version, p)
		}
		nums[i] = n
	}
	return nums[0]*10000 + nums[1]*100 + nums[2], nil
}

// ---------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------

type artifactFlags []string

func (a *artifactFlags) String() string { return strings.Join(*a, ",") }
func (a *artifactFlags) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func cmdManifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	version := fs.String("version", "", "release version, MAJOR.MINOR.PATCH (required)")
	channel := fs.String("channel", "stable", "release channel: stable|beta")
	seq := fs.Int64("seq", 0, "per-channel release sequence number, >= 1, strictly increasing across releases (required; env RELAVIA_UPDATE_SEQ)")
	baseURL := fs.String("base-url", "", "download base URL; artifact url = <base-url>/<file name> (if empty, just the file name)")
	keyPath := fs.String("key", "", "path to the base64 Ed25519 release private key (env RELAVIA_RELEASE_KEY; if absent, an UNSIGNED DRAFT is emitted)")
	publishedAt := fs.String("published-at", "", "RFC 3339 UTC timestamp (default: now)")
	out := fs.String("out", "", "output path (default: update-<channel>.json in the current directory)")
	notesFile := fs.String("notes", "", "path to a JSON object of language -> release note (must contain \"en\" if given)")
	var artifacts artifactFlags
	fs.Var(&artifacts, "artifact", "platform=path to artifact file (repeatable, at least one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" {
		return errors.New("manifest: --version is required")
	}
	if *channel != "stable" && *channel != "beta" {
		return fmt.Errorf("manifest: --channel %q, want stable|beta", *channel)
	}
	if *seq == 0 {
		if v := os.Getenv("RELAVIA_UPDATE_SEQ"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("manifest: RELAVIA_UPDATE_SEQ %q is not an integer", v)
			}
			*seq = n
		}
	}
	if *seq < 1 {
		return errors.New("manifest: --seq >= 1 is required (per-channel, strictly increasing; see docs/relavia-update-v1.md §5)")
	}
	if len(artifacts) == 0 {
		return errors.New("manifest: at least one --artifact platform=path is required")
	}
	code, err := versionCodeOf(*version)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	ts := *publishedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return fmt.Errorf("manifest: --published-at %q is not RFC 3339", ts)
	}
	notes := map[string]string{"en": "Relavia " + *version}
	if *notesFile != "" {
		raw, err := os.ReadFile(*notesFile)
		if err != nil {
			return fmt.Errorf("manifest: read notes: %w", err)
		}
		var parsed map[string]string
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return fmt.Errorf("manifest: notes file is not a JSON string map: %w", err)
		}
		if parsed["en"] == "" {
			return errors.New("manifest: notes must contain a non-empty \"en\" entry (spec §2)")
		}
		notes = parsed
	}

	// Signing key: optional at the tool level so drafts can be
	// produced, but an empty sig is NOT a valid release manifest —
	// the client rejects it (spec §2/§4), and release.sh treats a
	// missing key as fatal unless explicitly in draft mode.
	var priv ed25519.PrivateKey
	key := *keyPath
	if key == "" {
		key = os.Getenv("RELAVIA_RELEASE_KEY")
	}
	if key != "" {
		priv, err = loadPrivateKey(key)
		if err != nil {
			return fmt.Errorf("manifest: %w", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "releasetool: WARNING: no release key (--key / RELAVIA_RELEASE_KEY); emitting an UNSIGNED DRAFT manifest — clients will reject it")
	}

	m := Manifest{
		Format:      formatName,
		Version:     *version,
		VersionCode: code,
		Channel:     *channel,
		Seq:         *seq,
		PublishedAt: ts,
		Notes:       notes,
	}
	seenPlatforms := map[string]bool{}
	for _, spec := range artifacts {
		platform, filePath, ok := strings.Cut(spec, "=")
		if !ok || platform == "" || filePath == "" {
			return fmt.Errorf("manifest: --artifact %q, want platform=path", spec)
		}
		if seenPlatforms[platform] {
			return fmt.Errorf("manifest: duplicate platform %q (the client selects by platform; duplicates are ambiguous)", platform)
		}
		seenPlatforms[platform] = true
		digest, size, err := hashFile(filePath)
		if err != nil {
			return fmt.Errorf("manifest: %w", err)
		}
		sig := ""
		if priv != nil {
			// Spec §4: the signed message is the raw 32-byte
			// SHA-256 digest of the artifact, nothing else.
			sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest))
		}
		name := filepath.Base(filePath)
		url := name
		if *baseURL != "" {
			url = strings.TrimSuffix(*baseURL, "/") + "/" + name
		}
		m.Artifacts = append(m.Artifacts, Artifact{
			Platform: platform,
			URL:      url,
			Size:     size,
			SHA256:   hex.EncodeToString(digest),
			Sig:      sig,
		})
		fmt.Printf("%s  %s (%d bytes, platform %s)\n", hex.EncodeToString(digest), name, size, platform)
	}

	outPath := *out
	if outPath == "" {
		outPath = "update-" + *channel + ".json"
	}
	encoded, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(outPath, encoded, 0o644); err != nil {
		return fmt.Errorf("manifest: write %s: %w", outPath, err)
	}
	fmt.Printf("wrote %s (version %s, versionCode %d, channel %s, seq %d, %d artifacts)\n",
		outPath, m.Version, m.VersionCode, m.Channel, m.Seq, len(m.Artifacts))
	return nil
}

// hashFile returns the raw SHA-256 digest and size of a file.
func hashFile(p string) ([]byte, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, 0, fmt.Errorf("hash %s: %w", p, err)
	}
	return h.Sum(nil), size, nil
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "path to the update-<channel>.json manifest (required)")
	pubSpec := fs.String("pubkey", "", "release public key: path to a base64 key file, or a literal base64 key (env RELAVIA_RELEASE_PUBKEY)")
	dir := fs.String("dir", "", "optional directory holding the artifact files (named by the basename of each artifact url); files are re-hashed and compared")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return errors.New("verify: --manifest is required")
	}
	spec := *pubSpec
	if spec == "" {
		spec = os.Getenv("RELAVIA_RELEASE_PUBKEY")
	}
	if spec == "" {
		return errors.New("verify: --pubkey (or RELAVIA_RELEASE_PUBKEY) is required")
	}
	pub, err := loadPublicKey(spec)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("verify: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("verify: manifest is not valid JSON: %w", err)
	}
	return verifyManifest(&m, pub, *dir, os.Stdout)
}

// verifyManifest checks a manifest exactly the way
// docs/relavia-update-v1.md §2/§4 prescribe (structure, then
// per-artifact digest + signature; files re-hashed when dir != "").
func verifyManifest(m *Manifest, pub ed25519.PublicKey, dir string, w io.Writer) error {
	var failures []string
	fail := func(format string, a ...any) {
		failures = append(failures, fmt.Sprintf(format, a...))
	}
	if m.Format != formatName {
		fail("format is %q, want %q", m.Format, formatName)
	}
	if m.Channel != "stable" && m.Channel != "beta" {
		fail("channel is %q, want stable|beta", m.Channel)
	}
	if m.Seq < 1 {
		fail("seq is %d, want >= 1", m.Seq)
	}
	if code, err := versionCodeOf(m.Version); err != nil {
		fail("version: %v", err)
	} else if code != m.VersionCode {
		fail("versionCode is %d, but version %s encodes to %d", m.VersionCode, m.Version, code)
	}
	if _, err := time.Parse(time.RFC3339, m.PublishedAt); err != nil {
		fail("publishedAt %q is not RFC 3339", m.PublishedAt)
	}
	if m.Notes["en"] == "" {
		fail("notes has no non-empty \"en\" entry")
	}
	if len(m.Artifacts) == 0 {
		fail("artifacts is empty")
	}
	for _, a := range m.Artifacts {
		digest, err := hex.DecodeString(a.SHA256)
		if err != nil || len(digest) != sha256.Size || a.SHA256 != strings.ToLower(a.SHA256) {
			fail("artifact %s: sha256 is not 64 lowercase hex characters", a.Platform)
			continue
		}
		if a.Size <= 0 {
			fail("artifact %s: size is %d, want > 0", a.Platform, a.Size)
		}
		sig, err := base64.StdEncoding.DecodeString(a.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			fail("artifact %s: sig is not a base64 Ed25519 signature (unsigned draft?)", a.Platform)
			continue
		}
		if !ed25519.Verify(pub, digest, sig) {
			fail("artifact %s: SIGNATURE INVALID", a.Platform)
			continue
		}
		status := "signature OK"
		if dir != "" {
			name := path.Base(a.URL)
			filePath := filepath.Join(dir, name)
			actual, size, err := hashFile(filePath)
			if err != nil {
				fail("artifact %s: %v", a.Platform, err)
				continue
			}
			if hex.EncodeToString(actual) != a.SHA256 {
				fail("artifact %s: file %s hashes to %s, manifest says %s — HASH MISMATCH", a.Platform, name, hex.EncodeToString(actual), a.SHA256)
				continue
			}
			if size != a.Size {
				fail("artifact %s: file %s is %d bytes, manifest says %d — SIZE MISMATCH", a.Platform, name, size, a.Size)
				continue
			}
			status += ", file hash OK"
		}
		fmt.Fprintf(w, "artifact %s: %s\n", a.Platform, status)
	}
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintf(w, "FAIL: %s\n", f)
		}
		return fmt.Errorf("verify: %d check(s) failed", len(failures))
	}
	fmt.Fprintf(w, "manifest OK: format %s, version %s (code %d), channel %s, seq %d, %d artifact(s) verified against %s\n",
		m.Format, m.Version, m.VersionCode, m.Channel, m.Seq, len(m.Artifacts), PublicKeyFingerprint(pub))
	return nil
}
