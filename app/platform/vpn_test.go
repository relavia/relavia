package platform_test

import (
	"context"
	"errors"
	"testing"

	"openproxy/app/platform"
)

func TestDefaultTUNRequestMirrorsKernelDefaults(t *testing.T) {
	req := platform.DefaultTUNRequest(false)
	if req.IPv4Address != "172.18.0.1/30" {
		t.Errorf("IPv4Address = %q, want sing-box TUN default 172.18.0.1/30", req.IPv4Address)
	}
	if req.IPv6Address != "" {
		t.Errorf("IPv6Address = %q, want empty when IPv6 off", req.IPv6Address)
	}
	if req.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", req.MTU)
	}
	req6 := platform.DefaultTUNRequest(true)
	if req6.IPv6Address != "fd00::1/126" {
		t.Errorf("IPv6Address = %q, want fd00::1/126", req6.IPv6Address)
	}
}

func TestBridgeWithoutBinderIsHonestlyUnavailable(t *testing.T) {
	platform.RegisterVPNBinder(nil)
	var vpn platform.VPNService = platform.BridgeVPNService{}
	if vpn.Available() {
		t.Fatal("bridge without binder must report unavailable")
	}
	ctx := context.Background()
	if _, err := vpn.Prepare(ctx); !errors.Is(err, platform.ErrUnavailable) {
		t.Errorf("Prepare err = %v, want ErrUnavailable", err)
	}
	if _, err := vpn.Establish(ctx, platform.DefaultTUNRequest(false)); !errors.Is(err, platform.ErrUnavailable) {
		t.Errorf("Establish err = %v, want ErrUnavailable", err)
	}
	if err := vpn.Teardown(ctx); !errors.Is(err, platform.ErrUnavailable) {
		t.Errorf("Teardown err = %v, want ErrUnavailable", err)
	}
}

func TestBridgeDelegatesToRegisteredBinder(t *testing.T) {
	fake := platform.NewFakeVPNService()
	platform.RegisterVPNBinder(fake)
	defer platform.RegisterVPNBinder(nil)

	var vpn platform.VPNService = platform.BridgeVPNService{}
	if !vpn.Available() {
		t.Fatal("bridge with binder must report available")
	}
	ctx := context.Background()
	granted, err := vpn.Prepare(ctx)
	if err != nil || !granted {
		t.Fatalf("Prepare = %v, %v", granted, err)
	}
	h, err := vpn.Establish(ctx, platform.DefaultTUNRequest(true))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if h.FD() < 0 {
		t.Errorf("handle FD = %d, want a real fd", h.FD())
	}
	if fake.LastRequest.IPv6Address != "fd00::1/126" {
		t.Errorf("binder saw IPv6Address %q", fake.LastRequest.IPv6Address)
	}
	if err := vpn.Teardown(ctx); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if !fake.Handle.Closed() {
		t.Error("teardown must close the established handle")
	}
}

func TestFakeVPNDeniedConsentBlocksEstablish(t *testing.T) {
	fake := platform.NewFakeVPNService()
	fake.GrantConsent = false
	ctx := context.Background()
	granted, err := fake.Prepare(ctx)
	if err != nil || granted {
		t.Fatalf("Prepare = %v, %v; want denied without error", granted, err)
	}
	if _, err := fake.Establish(ctx, platform.DefaultTUNRequest(false)); !errors.Is(err, platform.ErrVPNNotPrepared) {
		t.Errorf("Establish err = %v, want ErrVPNNotPrepared", err)
	}
}
