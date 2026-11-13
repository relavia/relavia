package openvpn

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"openproxy/core/kernel"
)

func TestMissingBinaryFailsExplicitly(t *testing.T) {
	a := New(Options{BinaryPath: filepath.Join(t.TempDir(), "no-openvpn-here")})
	n := structuredNode()
	if _, err := a.TestHandshakeNode(context.Background(), n); err == nil {
		t.Fatal("TestHandshakeNode with no binary must fail")
	} else if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Errorf("kind = %v, want platform_unavailable: %v", kernel.KindOf(err), err)
	}
	if err := a.StartNode(context.Background(), n, kernel.PlatformOptions{Mode: kernel.ModeTUN}); err == nil {
		t.Fatal("StartNode with no binary must fail")
	} else if !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Errorf("kind = %v, want platform_unavailable: %v", kernel.KindOf(err), err)
	}
	if st := a.Status(); st.State != kernel.StateFailed {
		t.Errorf("state after failed start = %v, want failed", st.State)
	}
	// Capabilities must not claim a tunnel without the process.
	if a.Capabilities().Platform.TUN {
		t.Error("capabilities claim TUN with no binary present")
	}
}

func TestWrongProtocolRefused(t *testing.T) {
	a := New(Options{})
	n := structuredNode()
	n.Protocol = "trojan"
	n.OpenVPN = nil
	if err := a.ValidateSpec(context.Background(), n); err == nil {
		t.Fatal("non-openvpn node must be refused")
	}
}

func TestSystemProxyModeRefused(t *testing.T) {
	a := New(Options{BinaryPath: filepath.Join(t.TempDir(), "nope")})
	err := a.StartNode(context.Background(), structuredNode(), kernel.PlatformOptions{Mode: kernel.ModeSystemProxy})
	if err == nil || !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("system-proxy must be refused as platform_unavailable, got %v", err)
	}
}

func TestKillSwitchGate(t *testing.T) {
	a := New(Options{BinaryPath: filepath.Join(t.TempDir(), "nope")})
	err := a.StartNode(context.Background(), structuredNode(), kernel.PlatformOptions{Mode: kernel.ModeTUN, KillSwitch: true})
	if err == nil || !kernel.IsKind(err, kernel.KindPlatformUnavailable) {
		t.Fatalf("kill-switch request without enforcer must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "kill switch") {
		t.Errorf("error should name the kill switch: %v", err)
	}
}

// writeSleeperBinary creates a fake openvpn that answers --version
// and then just runs forever without a management interface.
func writeSleeperBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binaries are unix-only")
	}
	p := filepath.Join(t.TempDir(), "openvpn")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho 'OpenVPN 2.6.9 fake'\nexit 0\nfi\nexec sleep 120\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeAuthFailBinary creates a fake openvpn that prints an
// AUTH_FAILED log line and exits.
func writeAuthFailBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binaries are unix-only")
	}
	p := filepath.Join(t.TempDir(), "openvpn")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\necho 'OpenVPN 2.6.9 fake'\nexit 0\nfi\necho 'AUTH: Received control message: AUTH_FAILED'\nexit 1\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuthFailureClassification(t *testing.T) {
	a := New(Options{BinaryPath: writeAuthFailBinary(t), ConnectTimeout: 5 * time.Second})
	res, err := a.TestHandshakeNode(context.Background(), structuredNode())
	if err != nil {
		t.Fatalf("handshake failure must be a result, not a Go error: %v", err)
	}
	if res.OK {
		t.Fatal("handshake must not succeed against the auth-failing fake")
	}
	if res.Error == nil {
		t.Fatal("failed handshake must carry a classified error")
	}
	if !kernel.IsKind(res.Error, kernel.KindHandshakeFailed) {
		t.Errorf("kind = %v, want handshake_failed: %v", kernel.KindOf(res.Error), res.Error)
	}
}

func TestSleeperBinaryManagementTimeoutAndReap(t *testing.T) {
	bin := writeSleeperBinary(t)
	a := New(Options{BinaryPath: bin, ConnectTimeout: 2 * time.Second})
	n := structuredNode()
	done := make(chan error, 1)
	go func() {
		_, err := a.TestHandshakeNode(context.Background(), n)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected management-come-up failure against the sleeper")
		}
		if code := CodeOf(err); code != CodeManagementFailed {
			t.Errorf("code = %q, want %q (err: %v)", code, CodeManagementFailed, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("handshake against sleeper did not terminate")
	}
	// The fake child must have been reaped, not left running:
	// its session directory is gone and no sleep process lingers
	// under our control (checked indirectly: shutdown completed
	// before TestHandshake returned).
}
