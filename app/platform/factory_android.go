//go:build android

package platform

// Android constructors (Step 10). Android differs from the
// desktop targets in kind, per book 8.2:
//
//   - There is NO system-proxy mode on Android (the table marks
//     it "—"); the app must not invent one, so the constructor
//     returns the honest unsupported implementation.
//   - The TUN facility is the OS VpnService, owned by the shell
//     and reached through the bridge (vpn.go). Its availability
//     is exactly "a shell binder is registered".
//   - There is no system tray on Android; the foreground-service
//     notification is the shell's surface instead (Kotlin side,
//     strings resolved from the i18n packs via the bridge).

func NewSystemProxy() SystemProxy { return UnsupportedSystemProxy{} }

func NewTUN() TUNDevice { return androidTUN{} }

func NewTray(ev TrayEvents) Tray { return NoopTray{Events: ev} }

// androidTUN reports the VpnService facility state.
type androidTUN struct{}

func (androidTUN) Available() bool {
	bridge := BridgeVPNService{}
	return bridge.Available()
}

func (androidTUN) Detail() string {
	bridge := BridgeVPNService{}
	if bridge.Available() {
		return "Android VpnService bridge registered; TUN is established by the shell on connect"
	}
	return "Android VpnService bridge not registered in this build (shell/libbox binding pending); TUN unavailable"
}
