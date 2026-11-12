package platform

import (
	"context"
	"errors"
	"os"
	"sync"
)

// This file defines the VPN-service side of the platform layer:
// the lifecycle the Android shell owns (book 8.2: on Android the
// TUN facility is the OS VpnService), expressed platform-neutrally
// so the service layer and its tests run everywhere.
//
// Division of labour (the libbox pattern that the production
// Android build follows, ruled in docs/step10-Android客户端MVP.md):
//
//   - The shell (Kotlin, android/) owns android.net.VpnService:
//     the system consent flow, Builder().establish(), the
//     foreground notification, and revocation handling.
//   - The Go side owns everything else: node store, parsers,
//     service state machine, i18n, and (via libbox, the gomobile
//     build of the kernel) the data plane that reads and writes
//     the TUN file descriptor.
//   - The two meet at VPNBinder: the shell registers a binder at
//     startup; Prepare/Establish/Teardown calls cross into the
//     shell, and the established TUN fd crosses back.
//
// Until the libbox AAR lands, no production binder exists: the
// bridge implementation then reports ErrUnavailable — it never
// pretends a tunnel exists. Tests and logic-validation builds
// register FakeVPNService instead.

// ErrVPNNotPrepared is returned by Establish when the OS consent
// has not been granted. Callers must run the consent flow (on
// Android: VpnService.prepare) rather than retrying blindly.
var ErrVPNNotPrepared = errors.New("platform: VPN consent not granted")

// TUNRequest describes the TUN interface the shell must
// establish. The defaults mirror the sing-box TUN inbound
// defaults so the configuration the kernel compiles (Step 7)
// and the interface the shell builds cannot drift apart.
type TUNRequest struct {
	// IPv4Address is the interface address in CIDR form.
	IPv4Address string
	// IPv6Address is the interface IPv6 address in CIDR form,
	// empty when IPv6 is disabled for the session.
	IPv6Address string
	// DNSServers are pushed into the interface's DNS config.
	DNSServers []string
	// Routes are CIDR prefixes routed into the tunnel; empty
	// means the default route (all traffic).
	Routes []string
	// MTU of the interface.
	MTU int
}

// DefaultTUNRequest returns the session defaults (sing-box TUN
// inbound defaults: 172.18.0.1/30, fd00::1/126 when IPv6 is on,
// MTU 9000 as used by the gVisor stack; DNS starts with the
// tunnel-local resolver the kernel serves).
func DefaultTUNRequest(ipv6 bool) TUNRequest {
	req := TUNRequest{
		IPv4Address: "172.18.0.1/30",
		DNSServers:  []string{"172.18.0.2"},
		MTU:         9000,
	}
	if ipv6 {
		req.IPv6Address = "fd00::1/126"
	}
	return req
}

// TUNHandle is an established TUN interface. FD is the OS file
// descriptor the kernel data plane reads and writes (on Android
// it is the ParcelFileDescriptor's fd, dup'd by the shell before
// hand-off). Close tears the interface down; after Close the fd
// is invalid.
type TUNHandle interface {
	FD() int
	Close() error
}

// VPNService is the shell-owned VPN facility.
type VPNService interface {
	// Available reports whether the facility can be used in
	// this build at all (shell binder registered).
	Available() bool
	// Prepare runs the OS consent flow. It returns granted=false
	// (with a nil error) when the user declines; the Android
	// shell may need to launch a system dialog to complete it.
	Prepare(ctx context.Context) (granted bool, err error)
	// Establish creates the TUN interface. It fails with
	// ErrVPNNotPrepared when consent is missing.
	Establish(ctx context.Context, req TUNRequest) (TUNHandle, error)
	// Teardown ends the VPN session on the shell side (closes
	// the interface if still open and removes the foreground
	// notification). Safe to call when nothing is established.
	Teardown(ctx context.Context) error
}

// VPNBinder is the shell side of the bridge, registered once at
// shell startup (in production: the gomobile/libbox binding of
// the Kotlin shell; in tests: a fake). Method semantics mirror
// VPNService exactly.
type VPNBinder interface {
	Prepare(ctx context.Context) (bool, error)
	Establish(ctx context.Context, req TUNRequest) (TUNHandle, error)
	Teardown(ctx context.Context) error
}

var (
	binderMu sync.RWMutex
	binder   VPNBinder
)

// RegisterVPNBinder installs the shell-side binder. The Android
// shell calls it before any service starts; passing nil clears
// the registration (used by tests). It is process-global because
// the OS VPN facility itself is process-global.
func RegisterVPNBinder(b VPNBinder) {
	binderMu.Lock()
	defer binderMu.Unlock()
	binder = b
}

// RegisteredBinder returns the current binder, or nil.
func RegisteredBinder() VPNBinder {
	binderMu.RLock()
	defer binderMu.RUnlock()
	return binder
}

// BridgeVPNService is the Go side of the bridge: a VPNService
// that delegates to the registered shell binder. With no binder
// registered (every build until the shell ships) it reports
// unavailable, per the honesty contract.
type BridgeVPNService struct{}

func (BridgeVPNService) Available() bool { return RegisteredBinder() != nil }

func (BridgeVPNService) Prepare(ctx context.Context) (bool, error) {
	b := RegisteredBinder()
	if b == nil {
		return false, ErrUnavailable
	}
	return b.Prepare(ctx)
}

func (BridgeVPNService) Establish(ctx context.Context, req TUNRequest) (TUNHandle, error) {
	b := RegisteredBinder()
	if b == nil {
		return nil, ErrUnavailable
	}
	return b.Establish(ctx, req)
}

func (BridgeVPNService) Teardown(ctx context.Context) error {
	b := RegisteredBinder()
	if b == nil {
		return ErrUnavailable
	}
	return b.Teardown(ctx)
}

// --- fake ---------------------------------------------------------------

// FakeVPNService is an in-memory VPNService for tests and for
// logic-validation builds. Establish returns a handle backed by
// a real (pipe) file descriptor so fd hand-off code paths see a
// genuine fd; no traffic ever flows — the data plane is not
// part of the fake, and callers must not treat a fake session as
// a working tunnel (the Android logic build labels this with
// the android.fake_vpn_notice pack string).
type FakeVPNService struct {
	// GrantConsent controls Prepare's verdict.
	GrantConsent bool
	// EstablishErr, when set, is returned by Establish.
	EstablishErr error

	PrepareCalls   int
	EstablishCalls int
	TeardownCalls  int
	LastRequest    TUNRequest
	Handle         *FakeTUNHandle
}

var _ VPNService = (*FakeVPNService)(nil)

// NewFakeVPNService returns a fake that grants consent.
func NewFakeVPNService() *FakeVPNService { return &FakeVPNService{GrantConsent: true} }

func (f *FakeVPNService) Available() bool { return true }

func (f *FakeVPNService) Prepare(context.Context) (bool, error) {
	f.PrepareCalls++
	return f.GrantConsent, nil
}

func (f *FakeVPNService) Establish(_ context.Context, req TUNRequest) (TUNHandle, error) {
	f.EstablishCalls++
	f.LastRequest = req
	if !f.GrantConsent {
		return nil, ErrVPNNotPrepared
	}
	if f.EstablishErr != nil {
		return nil, f.EstablishErr
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	_ = w.Close() // the fake keeps only the read end, like a dup'd TUN fd
	f.Handle = &FakeTUNHandle{file: r}
	return f.Handle, nil
}

func (f *FakeVPNService) Teardown(context.Context) error {
	f.TeardownCalls++
	if f.Handle != nil {
		return f.Handle.Close()
	}
	return nil
}

// FakeTUNHandle wraps the pipe end handed out by FakeVPNService.
type FakeTUNHandle struct {
	file   *os.File
	closed bool
}

func (h *FakeTUNHandle) FD() int { return int(h.file.Fd()) }

func (h *FakeTUNHandle) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true
	return h.file.Close()
}

// Closed reports whether Close ran (tests).
func (h *FakeTUNHandle) Closed() bool { return h.closed }
