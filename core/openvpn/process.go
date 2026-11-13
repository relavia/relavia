package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/specnode"
)

// Failure classification codes. Stable strings: the service/UI
// layer maps them to localised copy; tests assert on them.
const (
	CodeAuthFailed         = "auth_failed"
	CodeAuthNoCredentials  = "auth_credentials_missing"
	CodePrivateKeyPassword = "private_key_password_required"
	CodeTLSVerifyFailed    = "tls_verify_failed"
	CodeTLSFailed          = "tls_handshake_failed"
	CodeTunUnavailable     = "tun_unavailable"
	CodeConfigRejected     = "config_rejected"
	CodeConnectTimeout     = "connect_timeout"
	CodeProcessExited      = "process_exited"
	CodeManagementFailed   = "management_failed"
	CodeConnectionFailed   = "connection_failed"
)

// classifiedError couples a stable classification code with the
// kernel-layer structured error, so kernel.IsKind keeps working
// (via Unwrap) while callers can recover the finer code.
type classifiedError struct {
	code string
	kerr *kernel.Error
}

func (e *classifiedError) Error() string { return e.kerr.Error() }
func (e *classifiedError) Unwrap() error { return e.kerr }

// CodeOf extracts the openvpn classification code from an error
// returned by this package ("" when the error carries none).
func CodeOf(err error) string {
	var ce *classifiedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return ""
}

// resultError renders a classified failure as the *kernel.Error a
// HandshakeResult carries (that struct has no code field, so the
// stable code rides at the front of the message where logs and
// UIs can show it verbatim).
func resultError(ce *classifiedError) *kernel.Error {
	return kernel.NewError(ce.kerr.Kind, ce.kerr.Op,
		ce.code+": "+ce.kerr.Message, ce.kerr.Err)
}

func classify(code string, kind kernel.Kind, op, msg string, cause error) *classifiedError {
	return &classifiedError{code: code, kerr: kernel.NewError(kind, op, msg, cause)}
}

func kindForCode(code string) kernel.Kind {
	switch code {
	case CodeAuthFailed, CodeAuthNoCredentials, CodePrivateKeyPassword,
		CodeTLSVerifyFailed, CodeTLSFailed, CodeConnectionFailed:
		return kernel.KindHandshakeFailed
	case CodeTunUnavailable:
		return kernel.KindPlatformUnavailable
	case CodeConfigRejected:
		return kernel.KindInvalidConfig
	case CodeConnectTimeout:
		return kernel.KindTimeout
	}
	return kernel.KindNetwork
}

// session is one running (or finished) openvpn child process under
// adapter supervision.
type session struct {
	dir      string
	endpoint *mgmtEndpoint
	cmd      *exec.Cmd
	mgmt     *mgmtClient
	events   chan mgmtEvent
	red      *redactor
	onLog    func(level, message string)

	done        chan struct{} // closed once the process is reaped and output drained
	connectedCh chan struct{}
	startedAt   time.Time

	bytesIn  atomic.Uint64 // received from the server (download)
	bytesOut atomic.Uint64 // sent to the server (upload)

	mu          sync.Mutex
	stateName   string
	stateDetail string
	localIP     string
	failure     *classifiedError // first classified hard failure
	waitErr     error
	connOnce    sync.Once
}

// spawnSession writes the config into a fresh private directory,
// starts the child, connects the management client and starts
// supervision. It returns once the management channel is live; the
// tunnel itself may still be connecting (watch connectedCh/failure
// via waitConnected).
func spawnSession(ctx context.Context, bin *BinaryInfo, n *specnode.Node, opts Options) (*session, error) {
	root := opts.WorkDir
	if root == "" {
		root = os.TempDir()
	}
	dir, err := os.MkdirTemp(root, "relavia-openvpn-")
	if err != nil {
		return nil, kernel.NewError(kernel.KindInternal, "Start", "create session directory", err)
	}
	s := &session{
		dir:         dir,
		events:      make(chan mgmtEvent, 64),
		done:        make(chan struct{}),
		connectedCh: make(chan struct{}),
		startedAt:   time.Now(),
		red:         newRedactor(n),
		onLog:       opts.OnLog,
	}
	fail := func(err error) (*session, error) {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	ep, err := newMgmtEndpoint(dir)
	if err != nil {
		return fail(kernel.NewError(kernel.KindInternal, "Start", "create management endpoint", err))
	}
	s.endpoint = ep
	built, err := buildConfig(n, buildOptions{
		mgmtLines:   ep.lines,
		devOverride: opts.DevOverride,
		extra:       opts.ExtraDirectives,
	})
	if err != nil {
		return fail(err)
	}
	cfgPath := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(cfgPath, []byte(built.text), 0o600); err != nil {
		return fail(kernel.NewError(kernel.KindInternal, "Start", "write session config", err))
	}
	cmd := exec.Command(bin.Path, "--config", cfgPath)
	setProcAttrs(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fail(kernel.NewError(kernel.KindInternal, "Start", "child stdout pipe", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fail(kernel.NewError(kernel.KindInternal, "Start", "child stderr pipe", err))
	}
	if err := cmd.Start(); err != nil {
		return fail(kernel.NewError(kernel.KindInternal, "Start", "launch openvpn process", err))
	}
	s.cmd = cmd

	var outputWG sync.WaitGroup
	outputWG.Add(2)
	go s.pumpOutput(stdout, &outputWG)
	go s.pumpOutput(stderr, &outputWG)
	go s.consumeEvents()
	go func() {
		s.waitErr = cmd.Wait()
		outputWG.Wait()
		if s.mgmt != nil {
			s.mgmt.close()
		}
		close(s.done)
	}()

	creds := authCreds{}
	if n.OpenVPN != nil && n.OpenVPN.Username != "" {
		creds = authCreds{username: n.OpenVPN.Username, password: n.OpenVPN.Password, has: true}
	}
	// The management endpoint appears early in openvpn's init but
	// not instantly; retry briefly. Process exit aborts the wait.
	mgmtTimeout := 15 * time.Second
	if opts.ConnectTimeout > 0 && opts.ConnectTimeout < mgmtTimeout {
		mgmtTimeout = opts.ConnectTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, mgmtTimeout)
	defer cancel()
	for {
		mgmt, derr := dialMgmt(dialCtx, ep.network, ep.address, ep.password, creds, s.events)
		if derr == nil {
			s.mgmt = mgmt
			break
		}
		select {
		case <-s.done:
			if f := s.getFailure(); f != nil {
				return fail(f)
			}
			return fail(classify(CodeProcessExited, kernel.KindNetwork, "Start",
				"openvpn exited before its management interface came up: "+s.failureMessage(), s.waitErr))
		case <-dialCtx.Done():
			_ = s.shutdown(0)
			return fail(classify(CodeManagementFailed, kernel.KindNetwork, "Start",
				"openvpn management interface did not come up", derr))
		case <-time.After(100 * time.Millisecond):
		}
	}
	// Enable real-time state and byte-count notifications; a
	// failure here is not fatal (state can still be polled).
	_, _ = s.mgmt.command("state on", 3*time.Second)
	_, _ = s.mgmt.command("bytecount 1", 3*time.Second)
	return s, nil
}

// pumpOutput forwards child output lines (redacted) to the log
// sink and scans them for hard-failure patterns, which feed the
// same classification the management states produce.
func (s *session) pumpOutput(r interface{ Read([]byte) (int, error) }, wg *sync.WaitGroup) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := s.red.line(sc.Text())
		if s.onLog != nil {
			level := "info"
			if strings.Contains(line, "ERROR") || strings.Contains(line, "FATAL") {
				level = "error"
			}
			safeLog(s.onLog, level, line)
		}
		s.scanFailureLine(line)
	}
}

func safeLog(f func(string, string), level, msg string) {
	defer func() { _ = recover() }()
	f(level, msg)
}

// scanFailureLine maps well-known openvpn log lines to failure
// codes. First classification wins.
func (s *session) scanFailureLine(line string) {
	var code, msg string
	switch {
	case strings.Contains(line, "AUTH_FAILED"):
		code, msg = CodeAuthFailed, "server rejected the credentials (AUTH_FAILED)"
	case strings.Contains(line, "VERIFY ERROR") || strings.Contains(line, "VERIFY FAIL"):
		code, msg = CodeTLSVerifyFailed, "server certificate verification failed"
	case strings.Contains(line, "TLS handshake failed") || strings.Contains(line, "TLS Error"):
		code, msg = CodeTLSFailed, "TLS handshake with the server failed"
	case strings.Contains(line, "Cannot open TUN/TAP"):
		code, msg = CodeTunUnavailable, "cannot open the TUN/TAP device (missing device or permission)"
	case strings.Contains(line, "Options error"):
		code, msg = CodeConfigRejected, "openvpn rejected the configuration: "+line
	}
	if code != "" {
		s.setFailure(code, msg, nil)
	}
}

func (s *session) setFailure(code, msg string, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure == nil {
		s.failure = classify(code, kindForCode(code), "Session", msg, cause)
	}
}

func (s *session) getFailure() *classifiedError {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

// failureMessage is a short human description of why the session
// is not (or not going to be) connected.
func (s *session) failureMessage() string {
	if f := s.getFailure(); f != nil {
		return f.kerr.Message
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateName != "" {
		return fmt.Sprintf("last management state %s (%s)", s.stateName, s.stateDetail)
	}
	return "no management state observed"
}

func (s *session) consumeEvents() {
	for {
		select {
		case <-s.done:
			return
		case ev := <-s.events:
			switch ev.Kind {
			case mgmtEventState:
				s.mu.Lock()
				s.stateName = ev.State.Name
				s.stateDetail = ev.State.Detail
				if ev.State.LocalIP != "" {
					s.localIP = ev.State.LocalIP
				}
				s.mu.Unlock()
				switch {
				case ev.State.Name == "CONNECTED":
					s.connOnce.Do(func() { close(s.connectedCh) })
				case ev.State.Detail == "auth-failure":
					s.setFailure(CodeAuthFailed, "server rejected the credentials (auth-failure)", nil)
				case ev.State.Detail == "tls-error":
					s.setFailure(CodeTLSFailed, "TLS handshake with the server failed (tls-error)", nil)
				}
			case mgmtEventBytes:
				s.bytesIn.Store(ev.BytesIn)
				s.bytesOut.Store(ev.BytesOut)
			case mgmtEventFatal:
				s.setFailure(CodeProcessExited, "openvpn reported a fatal error: "+s.red.line(ev.Message), nil)
			case mgmtEventPasswordAuth:
				s.setFailure(CodeAuthNoCredentials, ev.Message, nil)
			case mgmtEventPasswordKey:
				s.setFailure(CodePrivateKeyPassword, ev.Message, nil)
			}
		}
	}
}

// waitConnected blocks until the tunnel reports CONNECTED, a hard
// failure is classified, the process exits, or ctx/timeout ends.
func (s *session) waitConnected(ctx context.Context, timeout time.Duration) error {
	wctx := ctx
	cancel := func() {}
	if timeout > 0 {
		wctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	// Poll the failure slot alongside the channels: a classified
	// failure ends the wait immediately instead of riding out the
	// child's retry loop (server configs in the wild retry
	// forever, e.g. resolv-retry infinite).
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.connectedCh:
			return nil
		case <-s.done:
			if f := s.getFailure(); f != nil {
				return f
			}
			return classify(CodeProcessExited, kernel.KindNetwork, "Connect",
				"openvpn process exited before connecting (exit: "+exitString(s.waitErr)+")", s.waitErr)
		case <-tick.C:
			if f := s.getFailure(); f != nil {
				return f
			}
		case <-wctx.Done():
			if f := s.getFailure(); f != nil {
				return f
			}
			if errors.Is(wctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				return classify(CodeConnectTimeout, kernel.KindTimeout, "Connect",
					fmt.Sprintf("no CONNECTED state within %s (%s)", timeout, s.failureMessage()), nil)
			}
			return kernel.NewError(kernel.KindCanceled, "Connect", "context canceled", wctx.Err())
		}
	}
}

func exitString(err error) string {
	if err == nil {
		return "clean"
	}
	return err.Error()
}

// shutdown stops the child: graceful management signal first,
// then process termination, then force kill. The session directory
// (config + key material) is always removed.
func (s *session) shutdown(grace time.Duration) error {
	defer func() { _ = os.RemoveAll(s.dir) }()
	if s.mgmt != nil {
		_ = s.mgmt.signal("SIGTERM")
	}
	select {
	case <-s.done:
		return nil
	case <-time.After(grace):
	}
	termProcess(s.cmd)
	select {
	case <-s.done:
		return nil
	case <-time.After(2 * time.Second):
	}
	killProcess(s.cmd)
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
	}
	return nil
}

// traffic snapshots the counters in kernel terms: openvpn's
// bytes_in is traffic received from the server (download),
// bytes_out is traffic sent to it (upload).
func (s *session) traffic() kernel.TrafficStats {
	return kernel.TrafficStats{
		UploadBytes:      s.bytesOut.Load(),
		DownloadBytes:    s.bytesIn.Load(),
		SampledAt:        time.Now(),
		SessionStartedAt: s.startedAt,
	}
}

func (s *session) currentState() (name, detail, localIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateName, s.stateDetail, s.localIP
}
