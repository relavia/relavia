// Package ui is the desktop shell of the client (proposal book
// 5.1 UI layer): a Gio window over the platform-independent
// service layer. Gio was chosen over Fyne in the Step 9 framework
// ruling (docs/step9-Windows客户端MVP.md): pure Go, CGO-free
// cross-compilation to Windows from any host, and an Android
// backend for Step 10 reuse. All display text comes from the
// i18n packs — this package contains no hardcoded user-visible
// strings (enforced by tools/i18ncheck in CI).
//
// Layout direction is never hardcoded: rows use Gio's layout
// directions only through the helpers in this package, and the
// translator reports the active language's direction so future
// RTL packs can flip the shell without restructuring it.
package ui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"sync"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"openproxy/core/kernel"

	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/platform"
	"openproxy/app/service"
)

// Tabs.
const (
	tabNodes = iota
	tabImport
	tabLogs
	tabSettings
)

// App is the desktop shell's state. The zero value is not usable;
// build with New.
type App struct {
	svc *service.Service
	tr  *i18n.Translator
	th  *material.Theme

	Tray          platform.Tray
	OnLangChanged func(lang string)

	tab     int
	tabBtns [4]widget.Clickable

	groupEnum                                      widget.Enum
	nodeList                                       widget.List
	rowBtns                                        map[string]*rowButtons
	connectBtn, disconnectBtn, autoBtn, testAllBtn widget.Clickable

	linksEd                    widget.Editor
	urlEd                      widget.Editor
	fileEd                     widget.Editor
	importBtn, urlBtn, fileBtn widget.Clickable

	logList  widget.List
	clearLog widget.Clickable

	langEnum widget.Enum

	// mu guards the fields written by action goroutines and read
	// during layout (busy, errKey, importResult, trafficText).
	mu           sync.Mutex
	busy         bool
	errKey       string // i18n key of the last error, "" when none
	importResult string

	trafficMu   chan struct{}
	trafficText string
}

type rowButtons struct {
	selectBtn, testBtn, delBtn widget.Clickable
}

// New builds the shell around a service and translator.
func New(svc *service.Service, tr *i18n.Translator, th *material.Theme) *App {
	a := &App{
		svc:       svc,
		tr:        tr,
		th:        th,
		rowBtns:   map[string]*rowButtons{},
		trafficMu: make(chan struct{}, 1),
	}
	a.nodeList.List.Axis = layout.Vertical
	a.logList.List.Axis = layout.Vertical
	a.linksEd.Submit = false
	a.groupEnum.Value = "all"
	a.langEnum.Value = tr.Lang()
	if sel := svc.SelectedNodeID(); sel != "" {
		// Selection is restored implicitly by the service.
		_ = sel
	}
	if g := svc.Store().Settings().SelectedGroup; g != "" {
		a.groupEnum.Value = "g:" + g
	}
	return a
}

// T is the localization shortcut used by every view below.
func (a *App) T(key string, args map[string]string) string { return a.tr.T(key, args) }

// CurrentGroup returns the service group key for the radio state
// ("" = ungrouped, service.AllGroups = everything).
func (a *App) currentGroup() string {
	switch a.groupEnum.Value {
	case "all":
		return service.AllGroups
	default:
		v := a.groupEnum.Value
		if len(v) > 2 && v[:2] == "g:" {
			return v[2:]
		}
		return service.AllGroups
	}
}

// Layout renders one frame and processes widget events.
func (a *App) Layout(gtx layout.Context) layout.Dimensions {
	a.handleClicks(gtx)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(a.layoutHeader),
		layout.Rigid(a.layoutTabs),
		layout.Flexed(1, a.layoutBody),
		layout.Rigid(a.layoutFooter),
	)
}

func (a *App) handleClicks(gtx layout.Context) {
	for i := range a.tabBtns {
		if a.tabBtns[i].Clicked(gtx) {
			a.tab = i
		}
	}
	if a.connectBtn.Clicked(gtx) {
		a.runAsync(func(ctx context.Context) error {
			id := a.svc.SelectedNodeID()
			if id == "" {
				return service.ErrNoNodeSelected
			}
			return a.svc.Connect(ctx, id)
		})
	}
	if a.disconnectBtn.Clicked(gtx) {
		a.runAsync(func(ctx context.Context) error { return a.svc.Disconnect(ctx) })
	}
	if a.autoBtn.Clicked(gtx) {
		group := a.currentGroup()
		a.runAsync(func(ctx context.Context) error {
			_, err := a.svc.AutoSelectAndConnect(ctx, group)
			return err
		})
	}
	if a.testAllBtn.Clicked(gtx) {
		group := a.currentGroup()
		a.runAsync(func(ctx context.Context) error {
			_, err := a.svc.TestGroup(ctx, group)
			return err
		})
	}
	if a.importBtn.Clicked(gtx) {
		text := a.linksEd.Text()
		a.runImport(func() *service.ImportReport { return a.svc.ImportText(text) })
	}
	if a.urlBtn.Clicked(gtx) {
		u := a.urlEd.Text()
		a.runAsync(func(ctx context.Context) error {
			rep, err := a.svc.ImportSubscriptionURL(ctx, u, "")
			if rep != nil {
				a.setImportResult(rep)
			}
			return err
		})
	}
	if a.fileBtn.Clicked(gtx) {
		path := a.fileEd.Text()
		a.runAsync(func(ctx context.Context) error {
			data, err := readFileBytes(path)
			if err != nil {
				return err
			}
			rep := a.svc.ImportFile(path, data)
			a.setImportResult(rep)
			return nil
		})
	}
	if a.clearLog.Clicked(gtx) {
		a.svc.Logs().Clear()
	}
	if a.langEnum.Update(gtx) {
		lang := a.langEnum.Value
		if err := a.tr.SetLang(lang); err == nil {
			a.svc.Store().UpdateSettings(func(st *service.Settings) { st.Language = lang })
			_ = a.svc.Store().Save()
			if a.OnLangChanged != nil {
				a.OnLangChanged(lang)
			}
		}
	}
	if a.groupEnum.Update(gtx) {
		g := a.currentGroup()
		if g == service.AllGroups {
			g = ""
		}
		a.svc.Store().UpdateSettings(func(st *service.Settings) { st.SelectedGroup = g })
		_ = a.svc.Store().Save()
	}
}

// runAsync executes a service operation off the UI goroutine and
// records its (localized) outcome.
func (a *App) runAsync(fn func(ctx context.Context) error) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.errKey = ""
	a.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		err := fn(ctx)
		a.mu.Lock()
		a.busy = false
		if err != nil {
			a.errKey = ErrorKey(err)
		}
		a.mu.Unlock()
		a.invalidate()
	}()
}

// runImport is runAsync for the synchronous import calls.
func (a *App) runImport(fn func() *service.ImportReport) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.errKey = ""
	a.mu.Unlock()
	go func() {
		rep := fn()
		if rep != nil {
			a.setImportResult(rep)
		}
		a.mu.Lock()
		a.busy = false
		a.mu.Unlock()
		a.invalidate()
	}()
}

// state snapshots for layout (mutex-guarded).
func (a *App) isBusy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.busy
}

func (a *App) lastErrKey() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.errKey
}

func (a *App) lastImportResult() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.importResult
}

func (a *App) setImportResult(rep *service.ImportReport) {
	text := a.T("import.result", map[string]string{
		"ok": fmt.Sprint(rep.OK()), "fail": fmt.Sprint(len(rep.Failed)),
	})
	a.mu.Lock()
	a.importResult = text
	a.mu.Unlock()
}

// invalidate is set by the entry point (it owns the window).
var invalidateFunc func()

// SetInvalidateFunc wires the window invalidation hook.
func SetInvalidateFunc(fn func()) { invalidateFunc = fn }

func (a *App) invalidate() {
	if invalidateFunc != nil {
		invalidateFunc()
	}
}

// ErrorKey maps service/kernel errors to i18n keys.
func ErrorKey(err error) string {
	switch {
	case errors.Is(err, service.ErrNoNodeSelected):
		return "err.no_node_selected"
	case errors.Is(err, service.ErrNoTestedNode):
		return "err.no_tested_node"
	case errors.Is(err, service.ErrNoEngine):
		return "err.platform_unavailable"
	}
	switch kernel.KindOf(err) {
	case kernel.KindPlatformUnavailable:
		return "err.platform_unavailable"
	case kernel.KindUnsupported:
		return "err.unsupported"
	case kernel.KindInvalidConfig:
		return "err.invalid_config"
	case kernel.KindHandshakeFailed:
		return "err.handshake_failed"
	case kernel.KindNetwork:
		return "err.network"
	case kernel.KindWrongState:
		return "err.wrong_state"
	case kernel.KindTimeout:
		return "err.timeout"
	}
	return "err.generic"
}

// --- layout pieces -------------------------------------------------

func (a *App) layoutHeader(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: unit.Dp(10), Left: unit.Dp(14), Right: unit.Dp(14)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(material.H6(a.th, a.T("app.title", nil)).Layout),
				layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
				layout.Rigid(material.Caption(a.th, a.T("app.tagline", nil)).Layout),
				layout.Flexed(1, layout.Spacer{}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.Body1(a.th, a.statusText()).Layout(gtx)
				}),
			)
		})
}

func (a *App) statusText() string {
	st := a.svc.Status()
	switch st.State {
	case kernel.StateRunning:
		return a.T("status.connected", nil)
	case kernel.StateStarting, kernel.StateStopping:
		return a.T("status.connecting", nil)
	case kernel.StateFailed:
		return a.T("status.failed", nil)
	default:
		if a.isBusy() {
			return a.T("status.connecting", nil)
		}
		return a.T("status.disconnected", nil)
	}
}

func (a *App) layoutTabs(gtx layout.Context) layout.Dimensions {
	keys := []string{"nav.nodes", "nav.import", "nav.logs", "nav.settings"}
	return layout.Inset{Left: unit.Dp(14), Top: unit.Dp(6), Bottom: unit.Dp(6)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			children := make([]layout.FlexChild, 0, len(keys))
			for i, key := range keys {
				i, key := i, key
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(a.th, &a.tabBtns[i], a.T(key, nil))
					if a.tab == i {
						btn.Background = a.th.Palette.ContrastBg
						btn.Color = a.th.Palette.ContrastFg
					}
					return btn.Layout(gtx)
				}))
				children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout))
			}
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
		})
}

func (a *App) layoutBody(gtx layout.Context) layout.Dimensions {
	switch a.tab {
	case tabImport:
		return a.layoutImport(gtx)
	case tabLogs:
		return a.layoutLogs(gtx)
	case tabSettings:
		return a.layoutSettings(gtx)
	default:
		return a.layoutNodes(gtx)
	}
}

func (a *App) layoutFooter(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Left: unit.Dp(14), Right: unit.Dp(14), Bottom: unit.Dp(8), Top: unit.Dp(4)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			children := []layout.FlexChild{
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					mode := a.T("mode.manual", nil)
					if addr := a.svc.MixedAddr(); addr != "" {
						mode = a.T("mode.manual_addr", map[string]string{"addr": addr})
					}
					return material.Caption(a.th, a.T("mode.label", nil)+": "+mode).Layout(gtx)
				}),
				layout.Flexed(1, layout.Spacer{}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.Caption(a.th, a.trafficSummary()).Layout(gtx)
				}),
			}
			if errKey := a.lastErrKey(); errKey != "" {
				children = append([]layout.FlexChild{
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.Body2(a.th, a.T(errKey, nil))
						lbl.Color = color.NRGBA{R: 0xb0, G: 0x20, B: 0x20, A: 0xff}
						return lbl.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				}, children...)
			}
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
		})
}

// trafficSummary samples the engine counters at most once per
// second (driven by the entry point's ticker invalidating frames)
// and formats them localized.
func (a *App) trafficSummary() string {
	if a.svc.Status().State != kernel.StateRunning {
		return ""
	}
	select {
	case a.trafficMu <- struct{}{}:
		go func() {
			defer func() { <-a.trafficMu }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stats, err := a.svc.Traffic(ctx)
			if err == nil {
				text := a.T("traffic.upload", nil) + " " + FormatBytes(stats.UploadBytes) +
					" · " + a.T("traffic.download", nil) + " " + FormatBytes(stats.DownloadBytes)
				a.mu.Lock()
				a.trafficText = text
				a.mu.Unlock()
			}
		}()
	default:
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.trafficText
}

// FormatBytes renders a byte count compactly (unit suffixes are
// SI symbols, not localized words).
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// languages returns the pack order for the settings radio group.
func (a *App) languages() []string { return locales.Supported }
