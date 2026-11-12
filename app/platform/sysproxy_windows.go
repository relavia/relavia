//go:build windows

package platform

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows system proxy: the per-user WinINet settings in
// HKCU\...\Internet Settings (ProxyEnable / ProxyServer /
// ProxyOverride), followed by an InternetSetOption broadcast so
// running applications pick the change up.
//
// STATUS (Step 9): real implementation, COMPILE-VERIFIED ONLY.
// The build sandbox has no Windows machine; first real-machine
// verification is item W-1 of the Step 9 pending checklist
// (docs/step9-Windows客户端MVP.md). Do not describe this as
// verified until that item is signed off.

const internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var wininet = windows.NewLazySystemDLL("wininet.dll")
var procInternetSetOption = wininet.NewProc("InternetSetOptionW")

type winSystemProxy struct{}

func (winSystemProxy) Available() bool { return true }

func (winSystemProxy) Get() (ProxySettings, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return ProxySettings{}, fmt.Errorf("platform: open Internet Settings: %w", err)
	}
	defer key.Close()
	enable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil && err != registry.ErrNotExist {
		return ProxySettings{}, fmt.Errorf("platform: read ProxyEnable: %w", err)
	}
	server, _, _ := key.GetStringValue("ProxyServer")
	bypass, _, _ := key.GetStringValue("ProxyOverride")
	return ProxySettings{
		Enabled: enable != 0,
		Server:  server,
		Bypass:  bypass,
	}, nil
}

func (winSystemProxy) Set(server string) error {
	return writeProxySettings(ProxySettings{Enabled: true, Server: server, Bypass: "<local>"})
}

func (winSystemProxy) Clear() error {
	cur, _ := (winSystemProxy{}).Get()
	cur.Enabled = false
	return writeProxySettings(cur)
}

func writeProxySettings(s ProxySettings) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("platform: open Internet Settings: %w", err)
	}
	defer key.Close()
	enable := uint32(0)
	if s.Enabled {
		enable = 1
	}
	if err := key.SetDWordValue("ProxyEnable", enable); err != nil {
		return fmt.Errorf("platform: set ProxyEnable: %w", err)
	}
	if s.Enabled {
		if err := key.SetStringValue("ProxyServer", s.Server); err != nil {
			return fmt.Errorf("platform: set ProxyServer: %w", err)
		}
		if s.Bypass != "" {
			if err := key.SetStringValue("ProxyOverride", s.Bypass); err != nil {
				return fmt.Errorf("platform: set ProxyOverride: %w", err)
			}
		}
	}
	notifyWinINet()
	return nil
}

// notifyWinINet broadcasts the settings change so WinINet clients
// re-read the registry values.
func notifyWinINet() {
	procInternetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOption.Call(0, internetOptionRefresh, 0, 0)
}
