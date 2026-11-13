//go:build unix

package openvpn

import (
	"os/exec"
	"path/filepath"
	"syscall"
)

// mgmtEndpoint describes the child's management endpoint: the
// config lines that create it and how to dial it. On unix the
// endpoint is a unix-domain socket inside the session directory
// (filesystem permissions are the access control; no password, no
// TCP port). See endpoint_notunix.go for the TCP+password form
// used on Windows.
type mgmtEndpoint struct {
	network  string
	address  string
	password string
	lines    []string
}

func newMgmtEndpoint(dir string) (*mgmtEndpoint, error) {
	path := filepath.Join(dir, "mgmt.sock")
	return &mgmtEndpoint{
		network: "unix",
		address: path,
		lines:   []string{"management " + path + " unix"},
	}, nil
}

func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func termProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
}

func killProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
