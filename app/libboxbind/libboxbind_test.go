package libboxbind

// Host-side tests for the libbox binding. What can be proven
// here: bridge delegation, the pending-fd contract, protect()
// delegation, TUN config ↔ shell request consistency, parser
// acceptance of compiled configs by the real libbox, and the
// real libbox service lifecycle for a non-TUN config. What
// cannot: an actual TUN start (a host pipe fd is not a TUN
// device — libbox's wrapper fails the tun-name query, which
// the lifecycle test uses as the negative control proving the
// start chain reaches OpenTun), gomobile codegen and the AAR
// (CI), and real traffic (device).

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"

	"openproxy/app/platform"
	"openproxy/core/kernel"
	"openproxy/core/routecfg"
	"openproxy/core/singbox"
	"openproxy/core/specnode"
)

// --- fake shell bridge ---------------------------------------------

type fakeBridge struct {
	mu            sync.Mutex
	prepareResult bool
	prepareErr    error
	establishFD   int32
	establishErr  error
	established   []*TunParams
	closeTunCalls int
	teardownCalls int
	protectResult bool
	protectedFDs  []int32
	monitorStarts int
	monitorStops  int
	wifi          string
	ownerUID      int32
	packages      string
	ownerQueries  int
	posts         []string
	cancels       []string
}

func (f *fakeBridge) Prepare() (bool, error) { return f.prepareResult, f.prepareErr }

func (f *fakeBridge) EstablishTun(params *TunParams) (int32, error) {
	f.mu.Lock()
	f.established = append(f.established, params)
	f.mu.Unlock()
	return f.establishFD, f.establishErr
}

func (f *fakeBridge) CloseTun() error {
	f.mu.Lock()
	f.closeTunCalls++
	f.mu.Unlock()
	return nil
}

func (f *fakeBridge) ProtectSocket(fd int32) bool {
	f.mu.Lock()
	f.protectedFDs = append(f.protectedFDs, fd)
	f.mu.Unlock()
	return f.protectResult
}

func (f *fakeBridge) Teardown() error {
	f.mu.Lock()
	f.teardownCalls++
	f.mu.Unlock()
	return nil
}

func (f *fakeBridge) ConnectionOwnerUid(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) int32 {
	f.mu.Lock()
	f.ownerQueries++
	f.mu.Unlock()
	return f.ownerUID
}

func (f *fakeBridge) PackagesForUid(uid int32) string { return f.packages }

func (f *fakeBridge) StartInterfaceMonitor() error {
	f.mu.Lock()
	f.monitorStarts++
	f.mu.Unlock()
	return nil
}

func (f *fakeBridge) StopInterfaceMonitor() error {
	f.mu.Lock()
	f.monitorStops++
	f.mu.Unlock()
	return nil
}

func (f *fakeBridge) WifiState() string { return f.wifi }

func (f *fakeBridge) PostNotification(identifier string, title string, body string) error {
	f.mu.Lock()
	f.posts = append(f.posts, identifier)
	f.mu.Unlock()
	return nil
}

func (f *fakeBridge) CancelNotification(identifier string) error {
	f.mu.Lock()
	f.cancels = append(f.cancels, identifier)
	f.mu.Unlock()
	return nil
}

// registerFake installs a fake bridge for one test and
// restores the previous registration afterwards.
func registerFake(t *testing.T, f *fakeBridge) {
	t.Helper()
	previous := currentBridge()
	RegisterShellBridge(f)
	t.Cleanup(func() {
		bridgeMu.Lock()
		bridge = previous
		bridgeMu.Unlock()
	})
}

// --- fixtures ---------------------------------------------------------

func ssNode() *specnode.Node {
	return &specnode.Node{
		SchemaVersion: "1.0",
		ID:            "10000000-0000-4000-8000-0000000000aa",
		Name:          "libboxbind-test",
		Protocol:      specnode.ProtocolShadowsocks,
		Server:        "127.0.0.1",
		Port:          8388,
		Source:        specnode.SourceRef{Kind: "manual", Ref: "test", Authorization: "user-provided"},
		UDP:           true,
		// The 2022 key is a real 32-byte key (base64): unlike
		// the core package's shape-only fixtures, these nodes
		// go through libbox.CheckConfig's FULL construction,
		// which validates key material.
		Shadowsocks: &specnode.CredShadowsocks{Method: "2022-blake3-aes-256-gcm", Password: "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="},
	}
}

// --- no-drift: compiled TUN config vs shell request --------------------

func TestTunConfigMatchesShellRequest(t *testing.T) {
	frag, err := routecfg.Compile(routecfg.DefaultTUNPolicy())
	if err != nil {
		t.Fatalf("default TUN policy: %v", err)
	}
	for _, ipv6 := range []bool{false, true} {
		raw, err := singbox.CompileTunConfig(ssNode(), singbox.TunCompileOptions{Fragment: frag, IPv6: ipv6})
		if err != nil {
			t.Fatalf("CompileTunConfig(ipv6=%v): %v", ipv6, err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("config not JSON: %v", err)
		}
		ibs := cfg["inbounds"].([]any)
		ib := ibs[0].(map[string]any)
		params := tunParamsFromRequest(platform.DefaultTUNRequest(ipv6))
		addrs := ib["address"].([]any)
		if addrs[0] != params.Inet4Address {
			t.Fatalf("tun address %v != shell request %q (ipv6=%v)", addrs[0], params.Inet4Address, ipv6)
		}
		if ipv6 && addrs[1] != params.Inet6Address {
			t.Fatalf("tun inet6 %v != shell request %q", addrs[1], params.Inet6Address)
		}
		if ib["mtu"] != float64(params.MTU) {
			t.Fatalf("tun mtu %v != shell request %d", ib["mtu"], params.MTU)
		}
		// The real libbox parser must accept what the starter
		// will hand to StartOrReloadService.
		if err := libbox.CheckConfig(string(raw)); err != nil {
			t.Fatalf("libbox.CheckConfig(ipv6=%v): %v", ipv6, err)
		}
	}
}

// --- binder delegation ---------------------------------------------------

func TestBinderDelegation(t *testing.T) {
	fake := &fakeBridge{prepareResult: true, establishFD: 77, protectResult: true}
	registerFake(t, fake)

	binder := platform.RegisteredBinder()
	if binder == nil {
		t.Fatal("RegisterShellBridge must install the production binder")
	}
	ctx := context.Background()
	granted, err := binder.Prepare(ctx)
	if err != nil || !granted {
		t.Fatalf("Prepare = %v, %v", granted, err)
	}
	handle, err := binder.Establish(ctx, platform.DefaultTUNRequest(false))
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if handle.FD() != 77 {
		t.Fatalf("handle fd = %d, want 77", handle.FD())
	}
	if len(fake.established) != 1 || fake.established[0].Inet4Address != "172.18.0.1/30" || fake.established[0].MTU != 9000 {
		t.Fatalf("bridge saw params %+v", fake.established)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("handle Close: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("handle Close (2nd) must be a no-op: %v", err)
	}
	if fake.closeTunCalls != 1 {
		t.Fatalf("CloseTun calls = %d, want exactly 1", fake.closeTunCalls)
	}
	if err := binder.Teardown(ctx); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if fake.teardownCalls != 1 {
		t.Fatalf("Teardown calls = %d, want 1", fake.teardownCalls)
	}
}

func TestBinderWithoutBridge(t *testing.T) {
	bridgeMu.Lock()
	saved := bridge
	bridge = nil
	bridgeMu.Unlock()
	defer func() {
		bridgeMu.Lock()
		bridge = saved
		bridgeMu.Unlock()
	}()
	binder := shellBinder{}
	if _, err := binder.Prepare(context.Background()); err != platform.ErrUnavailable {
		t.Fatalf("Prepare without bridge = %v, want ErrUnavailable", err)
	}
	if _, err := binder.Establish(context.Background(), platform.DefaultTUNRequest(false)); err != platform.ErrUnavailable {
		t.Fatalf("Establish without bridge = %v, want ErrUnavailable", err)
	}
}

// --- platform implementation ------------------------------------------------

type testStringIterator struct {
	items []string
	index int
}

func (it *testStringIterator) Len() int32 { return int32(len(it.items) - it.index) }
func (it *testStringIterator) HasNext() bool {
	return it.index < len(it.items)
}
func (it *testStringIterator) Next() string {
	v := it.items[it.index]
	it.index++
	return v
}

// emptyTunOptions fabricates the zero TunOptions. Prefix
// getters return an always-exhausted iterator: libbox's
// RoutePrefix has unexported fields, so non-empty prefixes
// cannot be fabricated outside libbox (documented limit; the
// non-empty mapping is covered by the real start path).
type emptyTunOptions struct{ include []string }

func exhaustedPrefixes() libbox.RoutePrefixIterator { return &exhaustedPrefixIterator{} }

type exhaustedPrefixIterator struct{}

func (e *exhaustedPrefixIterator) HasNext() bool             { return false }
func (e *exhaustedPrefixIterator) Next() *libbox.RoutePrefix { return nil }

func (o emptyTunOptions) GetInet4Address() libbox.RoutePrefixIterator { return exhaustedPrefixes() }
func (o emptyTunOptions) GetInet6Address() libbox.RoutePrefixIterator { return exhaustedPrefixes() }
func (o emptyTunOptions) GetDNSMode() *libbox.StringBox               { return nil }
func (o emptyTunOptions) GetDNSServerAddress() (libbox.StringIterator, error) {
	return &testStringIterator{}, nil
}
func (o emptyTunOptions) GetMTU() int32        { return 9000 }
func (o emptyTunOptions) GetAutoRoute() bool   { return true }
func (o emptyTunOptions) GetStrictRoute() bool { return true }
func (o emptyTunOptions) GetInet4RouteAddress() libbox.RoutePrefixIterator {
	return exhaustedPrefixes()
}
func (o emptyTunOptions) GetInet6RouteAddress() libbox.RoutePrefixIterator {
	return exhaustedPrefixes()
}
func (o emptyTunOptions) GetInet4RouteExcludeAddress() libbox.RoutePrefixIterator {
	return exhaustedPrefixes()
}
func (o emptyTunOptions) GetInet6RouteExcludeAddress() libbox.RoutePrefixIterator {
	return exhaustedPrefixes()
}
func (o emptyTunOptions) GetInet4RouteRange() libbox.RoutePrefixIterator {
	return exhaustedPrefixes()
}
func (o emptyTunOptions) GetInet6RouteRange() libbox.RoutePrefixIterator {
	return exhaustedPrefixes()
}
func (o emptyTunOptions) GetIncludePackage() libbox.StringIterator {
	return &testStringIterator{items: o.include}
}
func (o emptyTunOptions) GetExcludePackage() libbox.StringIterator {
	return &testStringIterator{}
}
func (o emptyTunOptions) IsHTTPProxyEnabled() bool      { return false }
func (o emptyTunOptions) GetHTTPProxyServer() string    { return "" }
func (o emptyTunOptions) GetHTTPProxyServerPort() int32 { return 0 }
func (o emptyTunOptions) GetHTTPProxyBypassDomain() libbox.StringIterator {
	return &testStringIterator{}
}
func (o emptyTunOptions) GetHTTPProxyMatchDomain() libbox.StringIterator {
	return &testStringIterator{}
}

func TestPlatformPendingFDAndDirectPath(t *testing.T) {
	fake := &fakeBridge{establishFD: 55, protectResult: true}
	registerFake(t, fake)
	p := newPlatformImpl()

	// Pending path: consumed once, bridge untouched.
	p.setPendingFD(42)
	fd, err := p.OpenTun(emptyTunOptions{})
	if err != nil || fd != 42 {
		t.Fatalf("OpenTun(pending) = %d, %v", fd, err)
	}
	if len(fake.established) != 0 {
		t.Fatalf("pending path must not call the bridge, saw %d EstablishTun", len(fake.established))
	}
	// Pending consumed: the next open goes direct via bridge.
	fd, err = p.OpenTun(emptyTunOptions{})
	if err != nil || fd != 55 {
		t.Fatalf("OpenTun(direct) = %d, %v", fd, err)
	}
	// Direct fd is released on service stop; a pending one
	// would NOT be (choreography owns it).
	p.onServiceStopped()
	if fake.closeTunCalls != 1 {
		t.Fatalf("direct fd must be CloseTun'd on stop, calls=%d", fake.closeTunCalls)
	}
}

func TestPlatformRejectsIncludePackage(t *testing.T) {
	fake := &fakeBridge{establishFD: 55}
	registerFake(t, fake)
	p := newPlatformImpl()
	_, err := p.OpenTun(emptyTunOptions{include: []string{"com.example.app"}})
	if err == nil || !strings.Contains(err.Error(), "include_package") {
		t.Fatalf("include_package must be refused honestly, got %v", err)
	}
	if len(fake.established) != 0 {
		t.Fatal("refused options must not reach the bridge")
	}
}

func TestPlatformProtectDelegation(t *testing.T) {
	fake := &fakeBridge{protectResult: true}
	registerFake(t, fake)
	p := newPlatformImpl()
	if !p.UsePlatformAutoDetectInterfaceControl() {
		t.Fatal("auto-detect control must be on when a bridge is registered")
	}
	if err := p.AutoDetectInterfaceControl(9); err != nil {
		t.Fatalf("AutoDetectInterfaceControl: %v", err)
	}
	if len(fake.protectedFDs) != 1 || fake.protectedFDs[0] != 9 {
		t.Fatalf("bridge protected %v, want [9]", fake.protectedFDs)
	}
	fake.protectResult = false
	if err := p.AutoDetectInterfaceControl(10); err == nil {
		t.Fatal("a refused protect must surface as an error, not be swallowed")
	}
}

func TestPlatformConnectionOwner(t *testing.T) {
	fake := &fakeBridge{ownerUID: 10123, packages: "com.example.a,com.example.b"}
	registerFake(t, fake)
	p := newPlatformImpl()
	owner, err := p.FindConnectionOwner(6, "10.0.0.2", 1234, "1.2.3.4", 443)
	if err != nil {
		t.Fatalf("FindConnectionOwner: %v", err)
	}
	if owner.UserId != 10123 {
		t.Fatalf("owner uid = %d, want 10123", owner.UserId)
	}
	names := owner.AndroidPackageNames()
	var got []string
	for names.HasNext() {
		got = append(got, names.Next())
	}
	if len(got) != 2 || got[0] != "com.example.a" {
		t.Fatalf("owner packages = %v", got)
	}
	fake.ownerUID = -1
	if _, err := p.FindConnectionOwner(6, "10.0.0.2", 1234, "1.2.3.4", 443); err == nil {
		t.Fatal("unknown owner (uid -1) must be an error so rules treat it as unmatched")
	}
}

// --- facade basics -------------------------------------------------------------

func TestLocalizeFallback(t *testing.T) {
	if v := Localize("app.title"); v == "" || v == "app.title" {
		t.Fatalf("Localize(app.title) = %q, want the source-pack string", v)
	}
	if v := Localize("no.such.key.exists"); v != "" {
		t.Fatalf("Localize(unknown) = %q, want \"\" for the shell fallback", v)
	}
	if st := SessionStatus(); st != "idle" && !strings.HasPrefix(st, "error:") {
		t.Fatalf("SessionStatus before any session = %q", st)
	}
}

// --- real libbox lifecycle on the host -------------------------------------------

func TestLibboxServiceLifecycleHost(t *testing.T) {
	fake := &fakeBridge{prepareResult: true, protectResult: true}
	registerFake(t, fake)

	dir := t.TempDir()
	if err := Setup(dir, dir+"/work", dir+"/tmp"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// A non-TUN config must fully start and stop through the
	// real libbox runtime on the host.
	mixed := `{"log":{"level":"error"},"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":12080}],"outbounds":[{"type":"direct","tag":"out"}]}`
	if err := StartService(mixed); err != nil {
		t.Fatalf("StartService(mixed): %v", err)
	}
	if !ServiceRunning() {
		t.Fatal("ServiceRunning must be true after a successful start")
	}
	if err := CloseService(); err != nil {
		t.Fatalf("CloseService: %v", err)
	}
	if ServiceRunning() {
		t.Fatal("ServiceRunning must be false after close")
	}

	// TUN start with a non-TUN fd (pipe) must fail inside
	// libbox — the negative control proving the chain reached
	// OpenTun and consumed the pending fd. On Android the fd
	// is a real interface and this same chain succeeds (that
	// half is a device item).
	frag, err := routecfg.Compile(routecfg.DefaultTUNPolicy())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	raw, err := singbox.CompileTunConfig(ssNode(), singbox.TunCompileOptions{Fragment: frag})
	if err != nil {
		t.Fatalf("CompileTunConfig: %v", err)
	}
	if err := libbox.CheckConfig(string(raw)); err != nil {
		t.Fatalf("libbox.CheckConfig(tun config): %v", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	starter := &tunStarter{fragment: frag}
	err = starter.StartWithTUN(context.Background(), ssNode(), int(r.Fd()), kernel.PlatformOptions{})
	if err == nil {
		t.Fatal("TUN start over a pipe fd must fail on the host (not a TUN device)")
	}
	t.Logf("host TUN start failure mode (expected): %v", err)
	if ServiceRunning() {
		t.Fatal("a failed TUN start must not leave the service marked running")
	}
	if pending := manager.platform.takePendingFD(); pending != -1 {
		t.Fatalf("pending fd must be consumed/cleared after the attempt, got %d", pending)
	}
	if fake.closeTunCalls != 0 {
		t.Fatalf("the pending path must not CloseTun from the platform side, calls=%d", fake.closeTunCalls)
	}
	if err := CloseService(); err != nil {
		t.Fatalf("CloseService after failed start: %v", err)
	}
}
