package libboxbind

// The libbox PlatformInterface implementation: the Go half of
// the platform division of labour. It owns no Android API
// itself — every platform capability is delegated to the
// registered ShellBridge (Kotlin), which is the side that can
// touch android.net / android.os. Where a capability has no
// shell backing, this implementation degrades honestly
// (documented per method) instead of pretending.

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// platformImpl implements libbox.PlatformInterface.
type platformImpl struct {
	mu sync.Mutex
	// pendingFD is the shell-established TUN fd parked by the
	// choreography's starter, consumed exactly once by
	// OpenTun. -1 = none.
	pendingFD int32
	// directEstablished marks that OpenTun obtained the
	// current fd directly from the bridge (no choreography),
	// so service stop must CloseTun it. A pending fd is NOT
	// closed here: its ParcelFileDescriptor belongs to the
	// choreography/shell lifecycle.
	directEstablished bool
	listener          libbox.InterfaceUpdateListener
	myInterface       string
}

var _ libbox.PlatformInterface = (*platformImpl)(nil)

func newPlatformImpl() *platformImpl {
	return &platformImpl{pendingFD: -1}
}

func (p *platformImpl) setPendingFD(fd int32) {
	p.mu.Lock()
	p.pendingFD = fd
	p.mu.Unlock()
}

func (p *platformImpl) takePendingFD() int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	fd := p.pendingFD
	p.pendingFD = -1
	return fd
}

// onServiceStopped reconciles fd state after the box closed:
// a directly-established interface is released through the
// bridge; any unconsumed pending fd is forgotten (the shell's
// choreography closes its own handle on failure unwind).
func (p *platformImpl) onServiceStopped() {
	p.mu.Lock()
	direct := p.directEstablished
	p.directEstablished = false
	p.pendingFD = -1
	p.mu.Unlock()
	if direct {
		if b := currentBridge(); b != nil {
			_ = b.CloseTun()
		}
	}
}

// --- TUN opening -------------------------------------------------

// OpenTun returns the TUN fd for the box's tun inbound.
//
// Primary path (the Step 10 choreography): the fd was
// established by the shell up front and parked via
// setPendingFD. libbox's platform wrapper dups the returned
// fd; sing-tun owns and closes the duplicate, the original
// stays with the shell — that split ownership is what lets
// the choreography's handle.Close/teardown run after the box
// stops without a double-close hazard.
//
// Fallback path (service reload after a process restart,
// StartService without choreography): the TunOptions are
// translated and the bridge establishes the interface
// directly; the fd is then ours to release on service stop.
//
// Configurations asking for per-package include/exclude
// routing are refused: the v1 shell establishes an
// all-apps interface, and silently dropping package rules
// would be a dishonest capability claim.
func (p *platformImpl) OpenTun(options libbox.TunOptions) (int32, error) {
	if fd := p.takePendingFD(); fd >= 0 {
		return fd, nil
	}
	b := currentBridge()
	if b == nil {
		return -1, ErrNoBridge
	}
	params, err := tunParamsFromOptions(options)
	if err != nil {
		return -1, err
	}
	fd, err := b.EstablishTun(params)
	if err != nil {
		return -1, fmt.Errorf("libboxbind: establish tun: %w", err)
	}
	p.mu.Lock()
	p.directEstablished = true
	p.mu.Unlock()
	return fd, nil
}

// tunParamsFromOptions translates libbox's TunOptions into
// the bridge encoding. Routes: explicit route addresses win;
// otherwise "" (default route). Range-based routing (Android
// VpnService cannot express arbitrary ranges without
// enumerating them) is refused rather than approximated,
// except the route ranges this package itself compiles —
// CompileTunConfig never emits ranges, so a range here means
// a foreign configuration, which the v1 shell contract does
// not cover.
func tunParamsFromOptions(options libbox.TunOptions) (*TunParams, error) {
	if it := options.GetIncludePackage(); it != nil && it.HasNext() {
		return nil, errors.New("libboxbind: tun include_package is not supported by the v1 shell")
	}
	if it := options.GetExcludePackage(); it != nil && it.HasNext() {
		return nil, errors.New("libboxbind: tun exclude_package is not supported by the v1 shell")
	}
	if it := options.GetInet4RouteRange(); it != nil && it.HasNext() {
		return nil, errors.New("libboxbind: tun route ranges are not supported by the v1 shell")
	}
	if it := options.GetInet6RouteRange(); it != nil && it.HasNext() {
		return nil, errors.New("libboxbind: tun route ranges are not supported by the v1 shell")
	}
	if options.IsHTTPProxyEnabled() {
		return nil, errors.New("libboxbind: tun http_proxy is not supported by the v1 shell")
	}

	params := &TunParams{MTU: options.GetMTU()}
	if prefixes := drainPrefixes(options.GetInet4Address()); len(prefixes) > 0 {
		params.Inet4Address = prefixes[0]
	}
	if prefixes := drainPrefixes(options.GetInet6Address()); len(prefixes) > 0 {
		params.Inet6Address = prefixes[0]
	}
	dnsServers, err := options.GetDNSServerAddress()
	if err != nil {
		return nil, fmt.Errorf("libboxbind: tun dns servers: %w", err)
	}
	if dnsServers != nil {
		params.DNSServers = strings.Join(drainStrings(dnsServers), ",")
	}
	routes := drainPrefixes(options.GetInet4RouteAddress())
	routes = append(routes, drainPrefixes(options.GetInet6RouteAddress())...)
	params.Routes = strings.Join(routes, ",")
	return params, nil
}

// --- Interface control (protect) ---------------------------------

// UsePlatformAutoDetectInterfaceControl gates whether libbox
// consults this implementation for outbound socket protection.
// It is enabled exactly when a shell bridge exists to protect
// with — in the release APK the bridge is registered at
// process start, before any service starts.
func (p *platformImpl) UsePlatformAutoDetectInterfaceControl() bool {
	return currentBridge() != nil
}

// AutoDetectInterfaceControl is the protect() path: every
// outbound dial of the box presents its socket fd here (via
// route.auto_detect_interface in the compiled config) and the
// shell marks it with VpnService.protect, exempting it from
// the VPN so the tunnel never routes into itself.
func (p *platformImpl) AutoDetectInterfaceControl(fd int32) error {
	b := currentBridge()
	if b == nil {
		return ErrNoBridge
	}
	if !b.ProtectSocket(fd) {
		return fmt.Errorf("libboxbind: protect(%d) refused by the shell", fd)
	}
	return nil
}

// --- Local DNS -----------------------------------------------------

// LocalDNSTransport returns nil: the platform-transport is an
// optional libbox capability (its base context only registers
// it when non-nil), and the compiled DNS policy resolves
// through the box's own remote/local servers, not through an
// Android-API DNS exchange.
func (p *platformImpl) LocalDNSTransport() libbox.LocalDNSTransport {
	return nil
}

// --- Connection owner ----------------------------------------------

// FindConnectionOwner backs per-process/per-package route
// rules. It delegates to the shell's
// ConnectivityManager.getConnectionOwnerUid (API 29+): the
// procfs resolver libbox bundles is unreliable from an app
// process under Android 10+ SELinux policy, which is why the
// platform API is the correct source here. Uid -1 (unknown or
// pre-API-29) is reported as an error so rule evaluation
// treats the owner as unmatched rather than misattributed.
func (p *platformImpl) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*libbox.ConnectionOwner, error) {
	b := currentBridge()
	if b == nil {
		return nil, ErrNoBridge
	}
	uid := b.ConnectionOwnerUid(ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort)
	if uid < 0 {
		return nil, errors.New("libboxbind: connection owner unknown")
	}
	owner := &libbox.ConnectionOwner{UserId: uid}
	if pkgs := b.PackagesForUid(uid); pkgs != "" {
		owner.SetAndroidPackageNames(newStringIterator(strings.Split(pkgs, ",")))
	}
	return owner, nil
}

// --- Default interface monitor --------------------------------------

func (p *platformImpl) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	b := currentBridge()
	if b == nil {
		return ErrNoBridge
	}
	p.mu.Lock()
	p.listener = listener
	p.mu.Unlock()
	if err := b.StartInterfaceMonitor(); err != nil {
		p.mu.Lock()
		p.listener = nil
		p.mu.Unlock()
		return err
	}
	return nil
}

func (p *platformImpl) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	p.mu.Lock()
	p.listener = nil
	p.mu.Unlock()
	if b := currentBridge(); b != nil {
		return b.StopInterfaceMonitor()
	}
	return nil
}

func (p *platformImpl) notifyDefaultInterface(name string, index int32, expensive bool, constrained bool) {
	p.mu.Lock()
	listener := p.listener
	p.mu.Unlock()
	if listener != nil {
		listener.UpdateDefaultInterface(name, index, expensive, constrained)
	}
}

// --- Interfaces -------------------------------------------------------

// GetInterfaces enumerates with Go's net package (the
// sandbox-visible interface set — exactly what an app process
// can see on Android). Interface types use a name heuristic:
// Android has no userspace API for "what kind is this
// interface" in this list form; wlan* is Wi-Fi, rmnet*/ccmni*
// are cellular data, eth* is ethernet. DNS servers and
// gateways are not exposed by net.Interfaces and are left
// empty rather than guessed.
func (p *platformImpl) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	items := make([]*libbox.NetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		item := &libbox.NetworkInterface{
			Index:     int32(iface.Index),
			MTU:       int32(iface.MTU),
			Name:      iface.Name,
			Flags:     int32(iface.Flags),
			Type:      interfaceType(iface.Name),
			DNSServer: newStringIterator(nil),
			Gateway:   newStringIterator(nil),
		}
		var addrs []string
		if list, err := iface.Addrs(); err == nil {
			for _, addr := range list {
				addrs = append(addrs, addr.String())
			}
		}
		item.Addresses = newStringIterator(addrs)
		items = append(items, item)
	}
	return &networkInterfaceIterator{items: items}, nil
}

func interfaceType(name string) int32 {
	switch {
	case strings.HasPrefix(name, "wlan"):
		return libbox.InterfaceTypeWIFI
	case strings.HasPrefix(name, "rmnet"), strings.HasPrefix(name, "ccmni"), strings.HasPrefix(name, "pdp"):
		return libbox.InterfaceTypeCellular
	case strings.HasPrefix(name, "eth"):
		return libbox.InterfaceTypeEthernet
	default:
		return libbox.InterfaceTypeOther
	}
}

func (p *platformImpl) RegisterMyInterface(name string) {
	p.mu.Lock()
	p.myInterface = name
	p.mu.Unlock()
}

func (p *platformImpl) UnderNetworkExtension() bool { return false }
func (p *platformImpl) IncludeAllNetworks() bool    { return false }

// --- Wi-Fi / DNS cache / notifications ---------------------------------

// ReadWIFIState: the shell returns "" when the state is
// unavailable or location permission is missing; nil is
// libbox's supported "no state" answer.
func (p *platformImpl) ReadWIFIState() *libbox.WIFIState {
	b := currentBridge()
	if b == nil {
		return nil
	}
	raw := b.WifiState()
	if raw == "" {
		return nil
	}
	ssid, bssid, _ := strings.Cut(raw, "\n")
	return &libbox.WIFIState{SSID: ssid, BSSID: bssid}
}

// ClearDNSCache: Android exposes no per-app DNS cache flush;
// the box's own DNS cache is governed by its configuration.
// No-op by platform limitation, not by omission.
func (p *platformImpl) ClearDNSCache() {}

// SendNotification forwards kernel notifications to the shell
// (the shell owns the notification manager and channels).
func (p *platformImpl) SendNotification(notification *libbox.Notification) error {
	b := currentBridge()
	if b == nil {
		return ErrNoBridge
	}
	title := notification.Title
	if title == "" {
		title = notification.TypeName
	}
	body := notification.Body
	if notification.Subtitle != "" {
		if body != "" {
			body = notification.Subtitle + "\n" + body
		} else {
			body = notification.Subtitle
		}
	}
	return b.PostNotification(notification.Identifier, title, body)
}

func (p *platformImpl) CancelNotification(identifier string, typeID int32) error {
	b := currentBridge()
	if b == nil {
		return ErrNoBridge
	}
	return b.CancelNotification(identifier)
}

// --- Unsupported platform surfaces (honest errors) ----------------------

func (p *platformImpl) StartNeighborMonitor(listener libbox.NeighborUpdateListener) error {
	return errors.New("libboxbind: neighbor monitor is not supported")
}

func (p *platformImpl) CloseNeighborMonitor(listener libbox.NeighborUpdateListener) error {
	return nil
}

func (p *platformImpl) UsePlatformShell() bool { return false }

func (p *platformImpl) CheckPlatformShell() error {
	return errors.New("libboxbind: platform shell is not supported")
}

func (p *platformImpl) OpenShellSession(user *libbox.PlatformUser, command string, environ libbox.StringIterator, term string, rows int32, cols int32) (libbox.ShellSession, error) {
	return nil, errors.New("libboxbind: platform shell is not supported")
}

func (p *platformImpl) LookupUser(username string) (*libbox.PlatformUser, error) {
	return nil, errors.New("libboxbind: platform user lookup is not supported")
}

func (p *platformImpl) LookupSFTPServer() (string, error) {
	return "", errors.New("libboxbind: sftp server lookup is not supported")
}

func (p *platformImpl) ReadSystemSSHHostKey() (string, error) {
	return "", errors.New("libboxbind: system ssh host key is not supported")
}

func (p *platformImpl) TailscaleHostname() string { return "" }

func (p *platformImpl) UsePlatformBridge() bool { return false }

func (p *platformImpl) CreateBridge(options *libbox.BridgeOptions) (libbox.BridgeSession, error) {
	return nil, errors.New("libboxbind: platform bridge is not supported")
}

// --- Iterators -----------------------------------------------------------

type stringIterator struct {
	items []string
	index int
}

var _ libbox.StringIterator = (*stringIterator)(nil)

func newStringIterator(items []string) *stringIterator {
	return &stringIterator{items: items}
}

func (it *stringIterator) Len() int32 { return int32(len(it.items) - it.index) }

func (it *stringIterator) HasNext() bool { return it.index < len(it.items) }

func (it *stringIterator) Next() string {
	if !it.HasNext() {
		return ""
	}
	v := it.items[it.index]
	it.index++
	return v
}

type networkInterfaceIterator struct {
	items []*libbox.NetworkInterface
	index int
}

var _ libbox.NetworkInterfaceIterator = (*networkInterfaceIterator)(nil)

func (it *networkInterfaceIterator) HasNext() bool { return it.index < len(it.items) }

func (it *networkInterfaceIterator) Next() *libbox.NetworkInterface {
	if !it.HasNext() {
		return nil
	}
	v := it.items[it.index]
	it.index++
	return v
}

func drainStrings(it libbox.StringIterator) []string {
	var out []string
	for it != nil && it.HasNext() {
		out = append(out, it.Next())
	}
	return out
}

func drainPrefixes(it libbox.RoutePrefixIterator) []string {
	var out []string
	for it != nil && it.HasNext() {
		if prefix := it.Next(); prefix != nil {
			out = append(out, prefix.String())
		}
	}
	return out
}
