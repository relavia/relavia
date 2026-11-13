package openvpn

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"openproxy/core/kernel"
)

// writeFakeBinary creates an executable shell script that answers
// --version with the given output (unix only; skipped elsewhere).
func writeFakeBinary(t *testing.T, versionOut string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binaries are unix-only")
	}
	p := filepath.Join(t.TempDir(), "openvpn")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\nprintf '%s\\n' \"" + versionOut + "\"\nexit 0\nfi\nexit 1\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseVersion(t *testing.T) {
	v, err := parseVersion("OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)]\nlibrary versions: OpenSSL 3.0.13\n")
	if err != nil || v != "2.6.9" {
		t.Fatalf("parseVersion = %q, %v", v, err)
	}
	if _, err := parseVersion("garbage\n"); err == nil {
		t.Fatal("expected error on garbage banner")
	}
}

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.6.9", "2.5.0", 1},
		{"2.5.0", "2.5.0", 0},
		{"2.4.12", "2.5.0", -1},
		{"2.10.0", "2.9.9", 1},
	}
	for _, c := range cases {
		if got := compareVersion(c.a, c.b); got != c.want {
			t.Errorf("compareVersion(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestLocateExplicitBinary(t *testing.T) {
	p := writeFakeBinary(t, "OpenVPN 2.6.9 test")
	info, err := locateBinary(context.Background(), Options{BinaryPath: p})
	if err != nil {
		t.Fatalf("locateBinary: %v", err)
	}
	if info.Path != p || info.Version != "2.6.9" {
		t.Errorf("info = %+v", info)
	}
}

func TestLocateTooOld(t *testing.T) {
	p := writeFakeBinary(t, "OpenVPN 2.4.12 test")
	_, err := locateBinary(context.Background(), Options{BinaryPath: p})
	if err == nil {
		t.Fatal("expected refusal of a 2.4 binary")
	}
	if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Errorf("kind = %v, want platform_unavailable (%v)", kernel.KindOf(err), err)
	}
}

func TestLocateMissingIsExplicit(t *testing.T) {
	_, err := locateBinary(context.Background(), Options{
		BinaryPath: filepath.Join(t.TempDir(), "no-such-openvpn"),
	})
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Errorf("kind = %v, want platform_unavailable", kernel.KindOf(err))
	}
	if got := err.Error(); !strings.Contains(got, "not found") {
		t.Errorf("error should tell the user the binary was not found: %s", got)
	}
}
