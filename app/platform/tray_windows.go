//go:build windows

package platform

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows system tray: a hidden message window owning one
// Shell_NotifyIcon icon; right-click opens a popup menu built
// from the caller's (already localized) items, double-click asks
// to show the main window.
//
// STATUS (Step 9): real implementation, COMPILE-VERIFIED ONLY.
// The build sandbox has no Windows machine or display; first
// real-machine verification is item W-2 of the Step 9 pending
// checklist. Menu strings are supplied per SetMenu call, so a
// runtime language switch is honored by simply re-setting the
// menu (the service/UI layer does this on language change).

const (
	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1
	wmTrayShow      = wmApp + 2
	wmTrayHide      = wmApp + 3
	wmTraySetMenu   = wmApp + 4
	wmDestroy       = 0x0002
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	mfString    = 0x00000000
	mfGrayed    = 0x00000001
	mfSeparator = 0x00000800

	tpmReturnCmd   = 0x0100
	tpmRightButton = 0x0002

	idiApplication = 32512
)

var (
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostMessage      = user32.NewProc("PostMessageW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
)

// notifyIconData mirrors NOTIFYICONDATAW (Vista+ layout).
type notifyIconData struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

// wndClassEx mirrors WNDCLASSEXW.
type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type point struct{ X, Y int32 }

type msg struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type winTray struct {
	events TrayEvents

	mu      sync.Mutex
	hwnd    windows.Handle
	tooltip string
	menu    []TrayMenuItem
	started bool
	ready   chan struct{}
}

func newWinTray(ev TrayEvents) *winTray {
	return &winTray{events: ev, ready: make(chan struct{})}
}

func (t *winTray) Available() bool { return true }

// Show starts the tray thread (once) and installs the icon.
func (t *winTray) Show(tooltip string) error {
	t.mu.Lock()
	t.tooltip = tooltip
	if !t.started {
		t.started = true
		go t.loop()
	}
	hwnd := t.hwnd
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessage.Call(uintptr(hwnd), wmTrayShow, 0, 0)
		return nil
	}
	<-t.ready
	t.mu.Lock()
	hwnd = t.hwnd
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessage.Call(uintptr(hwnd), wmTrayShow, 0, 0)
	}
	return nil
}

func (t *winTray) SetMenu(items []TrayMenuItem) {
	t.mu.Lock()
	t.menu = append([]TrayMenuItem{}, items...)
	hwnd := t.hwnd
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessage.Call(uintptr(hwnd), wmTraySetMenu, 0, 0)
	}
}

func (t *winTray) SetTooltip(tooltip string) {
	t.mu.Lock()
	t.tooltip = tooltip
	hwnd := t.hwnd
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessage.Call(uintptr(hwnd), wmTrayShow, 1, 0) // 1 = modify only
	}
}

func (t *winTray) Hide() error {
	t.mu.Lock()
	hwnd := t.hwnd
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessage.Call(uintptr(hwnd), wmTrayHide, 0, 0)
	}
	return nil
}

// loop creates the hidden window and pumps messages. It runs on
// its own goroutine, which is the tray window's thread.
func (t *winTray) loop() {
	hinst, _, _ := procGetModuleHandle.Call(0)
	className, _ := windows.UTF16PtrFromString("RelaviaTrayWindow")
	wc := wndClassEx{
		LpfnWndProc:   windows.NewCallback(t.wndProc),
		HInstance:     windows.Handle(hinst),
		LpszClassName: className,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

	windowName, _ := windows.UTF16PtrFromString("Relavia Tray")
	hwndRet, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 0, 0, 0, 0,
		hinst, 0)
	hwnd := windows.Handle(hwndRet)
	t.mu.Lock()
	t.hwnd = hwnd
	t.mu.Unlock()
	close(t.ready)
	if hwnd == 0 {
		return
	}

	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (t *winTray) iconData(flags uint32) notifyIconData {
	icon, _, _ := procLoadIcon.Call(0, idiApplication)
	data := notifyIconData{
		HWnd:             t.hwnd,
		UID:              1,
		UFlags:           flags,
		UCallbackMessage: wmTrayCallback,
		HIcon:            icon,
	}
	data.CbSize = uint32(unsafe.Sizeof(data))
	t.mu.Lock()
	tip := t.tooltip
	t.mu.Unlock()
	if u16, err := windows.UTF16FromString(tip); err == nil {
		copy(data.SzTip[:len(data.SzTip)-1], u16)
	}
	return data
}

func (t *winTray) addIcon(modify bool) {
	data := t.iconData(nifMessage | nifIcon | nifTip)
	action := uintptr(nimAdd)
	if modify {
		action = nimModify
	}
	procShellNotifyIcon.Call(action, uintptr(unsafe.Pointer(&data)))
}

func (t *winTray) removeIcon() {
	data := t.iconData(0)
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&data)))
}

// popupMenu builds and shows the context menu, returning the
// chosen item ID ("" when dismissed).
func (t *winTray) popupMenu() string {
	t.mu.Lock()
	items := append([]TrayMenuItem{}, t.menu...)
	t.mu.Unlock()
	if len(items) == 0 {
		return ""
	}
	hmenu, _, _ := procCreatePopupMenu.Call()
	if hmenu == 0 {
		return ""
	}
	defer procDestroyMenu.Call(hmenu)
	for i, item := range items {
		label, _ := windows.UTF16PtrFromString(item.Label)
		flags := uintptr(mfString)
		if item.Disabled {
			flags |= mfGrayed
		}
		if item.ID == "-" {
			flags = mfSeparator
		}
		procAppendMenu.Call(hmenu, flags, uintptr(i+1), uintptr(unsafe.Pointer(label)))
	}
	procSetForegroundWin.Call(uintptr(t.hwnd))
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	cmd, _, _ := procTrackPopupMenu.Call(hmenu, tpmReturnCmd|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
	if cmd == 0 || int(cmd) > len(items) {
		return ""
	}
	return items[cmd-1].ID
}

func (t *winTray) wndProc(hwnd windows.Handle, message uint32, wparam, lparam uintptr) uintptr {
	switch message {
	case wmTrayShow:
		t.addIcon(wparam == 1)
		return 0
	case wmTrayHide:
		t.removeIcon()
		return 0
	case wmTraySetMenu:
		return 0 // menu state already stored; nothing to rebuild eagerly
	case wmTrayCallback:
		switch lparam {
		case wmLButtonDblClk:
			if t.events.OnShowWindow != nil {
				go t.events.OnShowWindow()
			}
		case wmRButtonUp:
			if id := t.popupMenu(); id != "" && t.events.OnMenuItem != nil {
				go t.events.OnMenuItem(id)
			}
		}
		return 0
	case wmDestroy:
		t.removeIcon()
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wparam, lparam)
	return ret
}
