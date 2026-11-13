//go:build !unix

package openvpn

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

// mgmtEndpoint on non-unix platforms (Windows): a loopback TCP
// port protected by a random password held in a file inside the
// session directory (0600). Unix-domain sockets are not available
// to the Windows openvpn build, and an unauthenticated management
// port — even on loopback — would hand tunnel control to any local
// process, so the password is mandatory here.
type mgmtEndpoint struct {
	network  string
	address  string
	password string
	lines    []string
}

func newMgmtEndpoint(dir string) (*mgmtEndpoint, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	pw := randomHex(16)
	pwPath := filepath.Join(dir, "mgmt.pw")
	if err := os.WriteFile(pwPath, []byte(pw+"\n"), 0o600); err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	return &mgmtEndpoint{
		network:  "tcp",
		address:  addr,
		password: pw,
		lines:    []string{fmt.Sprintf("management %s %s", addr, pwPath)},
	}, nil
}

func setProcAttrs(cmd *exec.Cmd) {}

func termProcess(cmd *exec.Cmd) {
	// Windows has no SIGTERM for child processes; the graceful
	// path is the management "signal SIGTERM" issued by shutdown
	// before this fallback.
	killProcess(cmd)
}

func killProcess(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
