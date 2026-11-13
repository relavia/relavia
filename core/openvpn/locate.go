package openvpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"openproxy/core/kernel"
)

// MinVersion is the oldest OpenVPN release this adapter drives.
// 2.5 is the floor because the adapter relies on negotiated data
// ciphers (--data-ciphers, 2.5+), peer-id and the management
// interface behaviour stabilised in the 2.5 series. Older binaries
// are refused explicitly instead of being driven into undefined
// behaviour.
const MinVersion = "2.5.0"

// BinaryInfo describes a located, version-verified openvpn
// executable.
type BinaryInfo struct {
	Path    string
	Version string // dotted version from `openvpn --version`, e.g. "2.6.9"
}

// binaryName is the executable file name per platform.
func binaryName() string {
	if runtime.GOOS == "windows" {
		return "openvpn.exe"
	}
	return "openvpn"
}

// candidatePaths returns the ordered search list for the openvpn
// executable: bundled locations first (the Step 2 audit's
// distribution form is an official binary bundled next to the
// application), then configured extra directories, then PATH.
//
// Order is part of the contract: a bundled binary always wins over
// a system one so a release package behaves identically everywhere.
func candidatePaths(opts Options) []string {
	var out []string
	name := binaryName()
	add := func(p string) {
		if p != "" {
			out = append(out, p)
		}
	}
	dirs := []string{opts.AppDir}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	dirs = append(dirs, opts.SearchDirs...)
	seen := map[string]bool{}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, sub := range []string{"openvpn", "bin", "."} {
			p := filepath.Join(d, sub, name)
			if !seen[p] {
				seen[p] = true
				add(p)
			}
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		add(p)
	}
	return out
}

// locateBinary finds and version-verifies the openvpn executable.
// An explicit Options.BinaryPath is authoritative: when set, it is
// the only candidate and a failure is reported, never silently
// bypassed in favour of another binary.
//
// Failure is a *kernel.Error of kind platform_unavailable with a
// message a user can act on — per the project's honesty contract
// the adapter never falls back to a degraded mode when the process
// engine is absent.
func locateBinary(ctx context.Context, opts Options) (*BinaryInfo, error) {
	var candidates []string
	if opts.BinaryPath != "" {
		candidates = []string{opts.BinaryPath}
	} else {
		candidates = candidatePaths(opts)
	}
	var tried []string
	for _, path := range candidates {
		if st, err := os.Stat(path); err != nil || st.IsDir() {
			continue
		}
		tried = append(tried, path)
		ver, err := probeVersion(ctx, path)
		if err != nil {
			continue
		}
		if compareVersion(ver, MinVersion) < 0 {
			return nil, kernel.NewError(kernel.KindPlatformUnavailable, "LocateBinary",
				fmt.Sprintf("OpenVPN at %s is version %s, but this adapter requires >= %s; please upgrade the bundled OpenVPN binary", path, ver, MinVersion), nil)
		}
		return &BinaryInfo{Path: path, Version: ver}, nil
	}
	searched := strings.Join(candidates, ", ")
	if opts.BinaryPath != "" {
		searched = opts.BinaryPath
	}
	return nil, kernel.NewError(kernel.KindPlatformUnavailable, "LocateBinary",
		fmt.Sprintf("OpenVPN executable not found (searched: %s). OpenVPN nodes need the OpenVPN program: install OpenVPN %s or newer, or use a Relavia package that bundles it. Nothing was started and no fallback was used.", searched, MinVersion),
		nil)
}

// probeVersion runs `openvpn --version` and parses the version out
// of the banner line ("OpenVPN 2.6.9 x86_64-pc-linux-gnu ...").
func probeVersion(ctx context.Context, path string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "--version").Output()
	if err != nil {
		return "", err
	}
	return parseVersion(string(out))
}

func parseVersion(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "OpenVPN" {
			v := fields[1]
			if _, err := parseSemver(v); err != nil {
				return "", fmt.Errorf("unparsable version %q", v)
			}
			return v, nil
		}
	}
	return "", fmt.Errorf("no OpenVPN banner in --version output")
}

func parseSemver(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, fmt.Errorf("bad version %q", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("bad version %q", v)
		}
		out[i] = n
	}
	return out, nil
}

// compareVersion returns -1/0/+1 for a <, ==, > b.
func compareVersion(a, b string) int {
	as, err1 := parseSemver(a)
	bs, err2 := parseSemver(b)
	if err1 != nil || err2 != nil {
		return strings.Compare(a, b)
	}
	for i := 0; i < 3; i++ {
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
