// Package android assembles the Relavia client for Android
// (proposal book Step 10): the same service layer, i18n packs
// and platform abstractions as the desktop client, wired for a
// platform whose only traffic facility is the OS VpnService
// (book 8.2: TUN mode via VpnService, no system-proxy mode,
// camera-scan import).
//
// Architecture (ruled in docs/step10-Android客户端MVP.md): the
// production APK is a thin Kotlin shell (repo-root android/)
// owning android.net.VpnService, plus this Go side bound through
// gomobile as libbox's host. The shell registers a
// platform.VPNBinder; this package orchestrates the connect
// choreography across the bridge. The product UI is the Gio
// surface (app/ui): since docs/android产品界面接入.md it runs
// in-process inside the merged APK over this same assembly;
// cmd/relavia-android remains the standalone logic-validation
// build of that surface.
//
// Honesty contract: with no binder registered, or with the
// placeholder TunnelStarter, a TUN connect fails explicitly —
// nothing in this package simulates a working data plane.
package android

import (
	"context"
	"errors"

	"openproxy/core/kernel"
	"openproxy/core/specnode"

	"openproxy/app/i18n"
	"openproxy/app/platform"
	"openproxy/app/service"
)

// ErrPermissionDenied reports that the user declined the OS VPN
// consent dialog. The UI maps it to the
// android.vpn_permission_denied pack string.
var ErrPermissionDenied = errors.New("android: VPN permission denied")

// ErrScanUnavailable reports that camera scanning is not
// implemented yet (interface landed, implementation pending a
// barcode component decision). The UI maps it to
// android.scan_unavailable.
var ErrScanUnavailable = errors.New("android: camera scan unavailable")

// ErrAlreadyConnected reports a second Connect while a TUN
// session is live.
var ErrAlreadyConnected = errors.New("android: already connected")

// TunnelStarter is the kernel side of an established TUN
// session: it consumes the TUN fd handed over by the shell and
// runs the data plane until Stop. In production this is the
// libbox starter (gomobile build of the kernel with an external
// TUN); until that binding lands, only test fakes and the
// explicit UnavailableTunnelStarter exist.
type TunnelStarter interface {
	StartWithTUN(ctx context.Context, n *specnode.Node, fd int, opts kernel.PlatformOptions) error
	Stop(ctx context.Context) error
}

// UnavailableTunnelStarter refuses every TUN start: the libbox
// data plane is not bound in this build. This is the production
// default until the libbox step lands — a connect attempt fails
// loudly instead of silently doing nothing with the fd.
type UnavailableTunnelStarter struct{}

func (UnavailableTunnelStarter) StartWithTUN(context.Context, *specnode.Node, int, kernel.PlatformOptions) error {
	return platform.ErrUnavailable
}

func (UnavailableTunnelStarter) Stop(context.Context) error { return nil }

// QRScanner abstracts camera barcode scanning for import
// (book 8.2: Android imports by camera scan). Implementations
// need a camera pipeline (CameraX + a decoder on the Kotlin
// side, most likely); this step lands the interface and the
// honest placeholder only.
type QRScanner interface {
	// Scan opens the camera and returns the decoded text of one
	// barcode (typically a share link or subscription URL).
	Scan(ctx context.Context) (string, error)
}

// UnavailableQRScanner is the placeholder scanner.
type UnavailableQRScanner struct{}

func (UnavailableQRScanner) Scan(context.Context) (string, error) {
	return "", ErrScanUnavailable
}

// Shell is the assembled Android client: service layer +
// translator + the VPN choreography. The Gio product UI
// drives it (in-process in the merged APK; through the shell
// facade in the Kotlin shell's session entries).
type Shell struct {
	Service    *service.Service
	Translator *i18n.Translator

	vpn     platform.VPNService
	starter TunnelStarter
	scanner QRScanner

	handle platform.TUNHandle
}

// Options wires a Shell. VPN defaults to the platform bridge;
// Starter defaults to UnavailableTunnelStarter (pass a fake in
// tests / logic-validation builds); Scanner defaults to the
// unavailable placeholder.
type Options struct {
	VPN     platform.VPNService
	Starter TunnelStarter
	Scanner QRScanner
}

// NewShell assembles the shell. On Android the only mode the
// platform offers is TUN (book 8.2), so a fresh settings
// document defaults to TUN here — desktop keeps its own manual
// default.
func NewShell(svc *service.Service, tr *i18n.Translator, opts Options) *Shell {
	if svc.Mode() == kernel.ModeManual && svc.Store().Settings().Mode == "" {
		svc.SetMode(kernel.ModeTUN)
	}
	s := &Shell{Service: svc, Translator: tr, vpn: opts.VPN, starter: opts.Starter, scanner: opts.Scanner}
	if s.vpn == nil {
		s.vpn = platform.BridgeVPNService{}
	}
	if s.starter == nil {
		s.starter = UnavailableTunnelStarter{}
	}
	if s.scanner == nil {
		s.scanner = UnavailableQRScanner{}
	}
	return s
}

// VPN returns the VPN facility in use (diagnostics/tests).
func (s *Shell) VPN() platform.VPNService { return s.vpn }

// Connect establishes a session to the node. In TUN mode (the
// Android norm) the choreography is: OS consent -> shell
// establishes the TUN interface -> fd crosses the bridge ->
// TunnelStarter runs the data plane. Any failure unwinds the
// partially built session (handle closed, shell torn down)
// before the error returns. In manual mode it defers to the
// service layer's in-process path (development builds only —
// book 8.2 gives Android no system-proxy/manual product mode,
// but the logic path stays exercisable in tests and the Gio
// logic build).
func (s *Shell) Connect(ctx context.Context, nodeID string) error {
	if s.Service.Mode() != kernel.ModeTUN {
		return s.Service.Connect(ctx, nodeID)
	}
	rec, ok := s.Service.Store().NodeByID(nodeID)
	if !ok {
		return service.ErrNoNodeSelected
	}
	if err := s.connectNode(ctx, rec.Node); err != nil {
		return err
	}
	s.Service.SelectNode(nodeID)
	return nil
}

// ConnectNode runs the TUN choreography for a node the caller
// already resolved. It is the entry the service layer's engine
// path uses (docs/android产品界面接入.md): service.Connect
// owns selection persistence and logging, so this method only
// performs consent -> establish -> data-plane start and does
// not touch the store. Mode is TUN by construction — Android
// has no other product mode (book 8.2).
func (s *Shell) ConnectNode(ctx context.Context, n *specnode.Node) error {
	if n == nil {
		return service.ErrNoNodeSelected
	}
	return s.connectNode(ctx, n)
}

// connectNode is the shared choreography behind Connect and
// ConnectNode.
func (s *Shell) connectNode(ctx context.Context, n *specnode.Node) error {
	if s.handle != nil {
		return ErrAlreadyConnected
	}
	if !s.vpn.Available() {
		return platform.ErrUnavailable
	}
	granted, err := s.vpn.Prepare(ctx)
	if err != nil {
		return err
	}
	if !granted {
		return ErrPermissionDenied
	}
	handle, err := s.vpn.Establish(ctx, platform.DefaultTUNRequest(false))
	if err != nil {
		return err
	}
	opts := kernel.PlatformOptions{Mode: kernel.ModeTUN}
	if err := s.starter.StartWithTUN(ctx, n, handle.FD(), opts); err != nil {
		_ = handle.Close()
		_ = s.vpn.Teardown(ctx)
		return err
	}
	s.handle = handle
	return nil
}

// Disconnect ends the session: data plane first, then the TUN
// handle, then the shell-side teardown (notification removal).
// All three run even when an earlier step fails; the first
// error is returned. With no TUN session live it defers to the
// service layer (the manual-mode logic path Connect defers to
// as well).
func (s *Shell) Disconnect(ctx context.Context) error {
	if s.handle == nil {
		return s.Service.Disconnect(ctx)
	}
	return s.StopTUN(ctx)
}

// StopTUN unwinds ONLY the TUN side — starter, handle, shell
// teardown — and never defers to the service layer. It is the
// stop used by the service engine path: routing it through
// Disconnect would recurse (engine Stop -> Disconnect ->
// service Disconnect -> engine Stop). Safe with no session
// live: the starter's Stop is idempotent, so an engine Stop
// after a failed or never-attempted connect cannot leak a box
// the starter may have half-started out of band.
func (s *Shell) StopTUN(ctx context.Context) error {
	if s.handle == nil {
		return s.starter.Stop(ctx)
	}
	var first error
	if err := s.starter.Stop(ctx); err != nil && first == nil {
		first = err
	}
	if err := s.handle.Close(); err != nil && first == nil {
		first = err
	}
	s.handle = nil
	if err := s.vpn.Teardown(ctx); err != nil && first == nil {
		first = err
	}
	return first
}

// Connected reports whether a TUN session is established.
func (s *Shell) Connected() bool { return s.handle != nil }

// ScanAndImport runs the camera-scan import path: scan one
// barcode, feed the text through the Step 8 parsers via the
// service importer. With the placeholder scanner it returns
// ErrScanUnavailable before touching the importer.
func (s *Shell) ScanAndImport(ctx context.Context) (*service.ImportReport, error) {
	text, err := s.scanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return s.Service.ImportText(text), nil
}
