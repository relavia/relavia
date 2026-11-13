package libboxbind

// The Step 10 choreography endpoints, production form:
//
//   - shellBinder implements app/platform.VPNBinder by
//     delegating to the Kotlin ShellBridge. RegisterShellBridge
//     installs it into the platform registry, upgrading
//     BridgeVPNService from "explicitly unavailable" (the
//     placeholder contract of the logic-only builds) to the
//     real binding. In the merged release APK the bridge is
//     registered at process start, so TUN unavailability now
//     means a REAL failure: consent refused, interface
//     establishment failed, protect refused.
//   - shellURLOpener implements app/platform.URLBinder the
//     same way, behind platform.OpenURL's Android delegation
//     (the guide entry's browser open).
//   - tunStarter implements app/android.TunnelStarter: it
//     compiles the node into the libbox TUN configuration and
//     starts the service with the choreography's fd parked as
//     pending for the platform interface's OpenTun.

import (
	"context"
	"strings"
	"sync"

	"openproxy/app/android"
	"openproxy/app/platform"
	"openproxy/core/kernel"
	"openproxy/core/routecfg"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// shellURLOpener implements platform.URLBinder over
// ShellBridge, resolving the bridge at call time like
// shellBinder does.
type shellURLOpener struct{}

var _ platform.URLBinder = shellURLOpener{}

func (shellURLOpener) OpenURL(url string) error {
	b := currentBridge()
	if b == nil {
		return platform.ErrOpenURLUnsupported
	}
	return b.OpenURL(url)
}

// shellBinder implements platform.VPNBinder over ShellBridge.
type shellBinder struct{}

var _ platform.VPNBinder = shellBinder{}

func (shellBinder) Prepare(ctx context.Context) (bool, error) {
	b := currentBridge()
	if b == nil {
		return false, platform.ErrUnavailable
	}
	// The bridge's consent wait is internally bounded; the
	// choreography context remains the outer bound.
	return b.Prepare()
}

func (shellBinder) Establish(ctx context.Context, req platform.TUNRequest) (platform.TUNHandle, error) {
	b := currentBridge()
	if b == nil {
		return nil, platform.ErrUnavailable
	}
	fd, err := b.EstablishTun(tunParamsFromRequest(req))
	if err != nil {
		return nil, err
	}
	return &tunHandle{fd: int(fd)}, nil
}

func (shellBinder) Teardown(ctx context.Context) error {
	b := currentBridge()
	if b == nil {
		return platform.ErrUnavailable
	}
	return b.Teardown()
}

// tunParamsFromRequest encodes a platform.TUNRequest (whose
// source of truth is DefaultTUNRequest) for the bridge.
// TUNRequest addresses already carry their prefix lengths
// ("172.18.0.1/30", "fd00::1/126") — the same strings
// CompileTunConfig compiles into the tun inbound, kept in
// lockstep by this package's no-drift test.
func tunParamsFromRequest(req platform.TUNRequest) *TunParams {
	params := &TunParams{MTU: int32(req.MTU)}
	params.Inet4Address = req.IPv4Address
	params.Inet6Address = req.IPv6Address
	params.DNSServers = strings.Join(req.DNSServers, ",")
	params.Routes = strings.Join(req.Routes, ",")
	return params
}

// tunHandle implements platform.TUNHandle. The raw fd stays
// owned by the shell's ParcelFileDescriptor; Close routes to
// the bridge's CloseTun (which closes the interface), it does
// NOT os-close the number — the number is only valid inside
// the shell's descriptor bookkeeping.
type tunHandle struct {
	mu     sync.Mutex
	fd     int
	closed bool
}

var _ platform.TUNHandle = (*tunHandle)(nil)

func (h *tunHandle) FD() int { return h.fd }

func (h *tunHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if b := currentBridge(); b != nil {
		return b.CloseTun()
	}
	return nil
}

// tunStarter implements android.TunnelStarter over the libbox
// service manager.
type tunStarter struct {
	// fragment is the session's compiled Step 11 routing/DNS
	// policy (the default TUN policy unless the session
	// supplied another); nil compiles a bare final=out route.
	fragment *routecfg.Fragment
}

var _ android.TunnelStarter = (*tunStarter)(nil)

func (s *tunStarter) StartWithTUN(ctx context.Context, n *specnode.Node, fd int, opts kernel.PlatformOptions) error {
	config, err := singbox.CompileTunConfig(n, singbox.TunCompileOptions{
		Fragment: s.fragment,
	})
	if err != nil {
		return err
	}
	return manager.startWithPendingFD(string(config), int32(fd))
}

func (s *tunStarter) Stop(ctx context.Context) error {
	return manager.closeService()
}
