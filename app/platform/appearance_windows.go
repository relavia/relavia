//go:build windows

package platform

import (
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Windows exposes the app appearance choice in the registry
// (HKCU\...\Themes\Personalize\AppsUseLightTheme: 1 = light,
// 0 = dark). The value is cached for a few seconds so the UI
// render loop never hammers the registry; an unreadable value
// reports ok=false and the caller falls back to light.

var appearanceCache struct {
	sync.Mutex
	at   time.Time
	dark bool
	ok   bool
}

func SystemDarkMode() (dark bool, ok bool) {
	appearanceCache.Lock()
	defer appearanceCache.Unlock()
	if appearanceCache.ok && time.Since(appearanceCache.at) < 5*time.Second {
		return appearanceCache.dark, true
	}
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`,
		registry.QUERY_VALUE)
	if err != nil {
		return false, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false, false
	}
	appearanceCache.at = time.Now()
	appearanceCache.dark = v == 0
	appearanceCache.ok = true
	return appearanceCache.dark, true
}
