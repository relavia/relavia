// Package ui is the desktop shell of the client (proposal book
// 5.1 UI layer): a Gio window over the platform-independent
// service layer. Gio was chosen over Fyne in the Step 9 framework
// ruling (docs/step9-Windows客户端MVP.md): pure Go, CGO-free
// cross-compilation to Windows from any host, and an Android
// backend for Step 10 reuse. All display text comes from the
// i18n packs — this package contains no hardcoded user-visible
// strings (enforced by tools/i18ncheck in CI).
//
// The presentation implements the approved mockups in
// docs/ui-mockups/ (design tokens and shared widgets live in
// theme.go); behavior — which service calls a click makes, what
// is persisted, which states exist — is unchanged from the
// plain material layout that preceded it.
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
	"image"
	"strings"
	"sync"
	"time"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"openproxy/core/kernel"

	"openproxy/app/android"
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

	// groupEnum only stores the current group radio value
	// ("all" or "g:<name>"); the mockup chips write it through
	// applyGroupSelection, which persists exactly like the old
	// material RadioButton path did.
	groupEnum widget.Enum
	groupBtns map[string]*widget.Clickable
	nodeList  widget.List
	// groupList is the horizontally scrolling container for
	// the group tabs (2026-11-14 defect fix: a plain horizontal
	// Flex of every group name starved the last entries of
	// width on real devices, wrapping their labels per
	// character and exploding the row height).
	groupList widget.List
	rowBtns   map[string]*rowButtons

	disconnectBtn widget.Clickable

	// v3 first-screen and page controls.
	heroBtn, heroRetryBtn, heroReasonBtn widget.Clickable
	checkAllBtn, guideBtn, recBtn        widget.Clickable
	detourBtn, searchClearBtn            widget.Clickable
	riskLinkBtn, viewAllBtn, errStripBtn widget.Clickable
	pickedBtns                           [3]widget.Clickable
	methodBtns                           [3]widget.Clickable
	themeBtns                            [4]widget.Clickable
	// expandedMethod is the import page's open method row
	// (0 = none, 1..3 = links / subscription / file).
	expandedMethod int
	// menuOpenID is the node whose overflow strip is open.
	menuOpenID string
	// themeID caches the resolved palette id so the material
	// theme is only re-synced when the palette changes.
	themeID string

	// searchEd filters the node list (name / address / group),
	// applied on the layout goroutine from its current text.
	searchEd widget.Editor

	linksEd widget.Editor
	urlEd   widget.Editor
	fileEd  widget.Editor
	// importBtn / urlBtn run their imports directly; fileBtn
	// only expands the file-path row (presentation state), and
	// fileGoBtn runs the file import — the same two-step the
	// old always-visible editor + OK button performed.
	importBtn, urlBtn, fileBtn, fileGoBtn widget.Clickable
	showFilePath                          bool

	// VPN Gate source controls (Import tab sources section).
	// The risk gate itself is the bottom sheet: sheet is nil
	// while closed and is touched only on the layout goroutine.
	vgRiskBtn, vgEnableBtn, vgRefreshBtn, vgRevokeBtn widget.Clickable
	sheet                                             *riskSheetState
	sheetAgreeBtn, sheetCloseBtn                      widget.Clickable
	sheetFullBtn, sheetScrimBtn                       widget.Clickable

	logList      widget.List
	importList   widget.List
	settingsList widget.List
	sheetList    widget.List
	clearLog     widget.Clickable

	// langEnum stores the settings language value; the custom
	// radio rows write it through applyLanguage.
	langEnum widget.Enum
	langBtns map[string]*widget.Clickable

	// Settings preference radios (protocol preference + run
	// mode), keyed by their setting values.
	prefBtns map[string]*widget.Clickable
	modeBtns map[string]*widget.Clickable

	// mu guards the fields written by action goroutines and read
	// during layout (busy, errKey, importResult, traffic).
	mu           sync.Mutex
	busy         bool
	errKey       string // i18n key of the last error, "" when none
	importResult string
	// importFailKey is the pack key of the first failed item's
	// reason in the last import ("" when nothing failed), and
	// importNote a one-off guidance line for the import tab
	// (e.g. the looks-like-a-subscription-address hint).
	importFailKey string
	importNote    string

	// heroStage / heroErr / heroFailed carry the one-tap
	// connect chain's progress for the hero card (stageNone =
	// not running); autoPickedFlag marks a connection made by
	// the chain's auto-select; helpHint is the guide-open
	// failure line. All guarded by mu like the fields above.
	heroStage      heroStage
	heroErr        error
	heroFailed     bool
	autoPickedFlag bool
	helpHint       string

	trafficMu    chan struct{}
	trafficStats *kernel.TrafficStats // last successful counter sample
	trafficOK    bool
}

type rowButtons struct {
	selectBtn, testBtn, delBtn, favBtn widget.Clickable
	menuBtn, connBtn                   widget.Clickable
}

// New builds the shell around a service and translator.
func New(svc *service.Service, tr *i18n.Translator, th *material.Theme) *App {
	a := &App{
		svc:       svc,
		tr:        tr,
		th:        th,
		rowBtns:   map[string]*rowButtons{},
		groupBtns: map[string]*widget.Clickable{},
		langBtns:  map[string]*widget.Clickable{},
		prefBtns:  map[string]*widget.Clickable{},
		modeBtns:  map[string]*widget.Clickable{},
		trafficMu: make(chan struct{}, 1),
	}
	a.nodeList.List.Axis = layout.Vertical
	a.groupList.List.Axis = layout.Horizontal
	a.logList.List.Axis = layout.Vertical
	a.importList.List.Axis = layout.Vertical
	a.settingsList.List.Axis = layout.Vertical
	a.sheetList.List.Axis = layout.Vertical
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

// applyGroupSelection persists the chip selection exactly like
// the old groupEnum.Update branch did.
func (a *App) applyGroupSelection() {
	g := a.currentGroup()
	if g == service.AllGroups {
		g = ""
	}
	a.svc.Store().UpdateSettings(func(st *service.Settings) { st.SelectedGroup = g })
	_ = a.svc.Store().Save()
}

// applyLanguage performs a language switch with the same
// effects as the old langEnum.Update branch: switch the
// translator, persist the choice, notify the entry point.
func (a *App) applyLanguage(lang string) {
	if err := a.tr.SetLang(lang); err != nil {
		return
	}
	a.langEnum.Value = lang
	a.svc.Store().UpdateSettings(func(st *service.Settings) { st.Language = lang })
	_ = a.svc.Store().Save()
	if a.OnLangChanged != nil {
		a.OnLangChanged(lang)
	}
}

func (a *App) groupButton(value string) *widget.Clickable {
	b, ok := a.groupBtns[value]
	if !ok {
		b = &widget.Clickable{}
		a.groupBtns[value] = b
	}
	return b
}

func (a *App) langButton(lang string) *widget.Clickable {
	b, ok := a.langBtns[lang]
	if !ok {
		b = &widget.Clickable{}
		a.langBtns[lang] = b
	}
	return b
}

func (a *App) prefButton(value string) *widget.Clickable {
	b, ok := a.prefBtns[value]
	if !ok {
		b = &widget.Clickable{}
		a.prefBtns[value] = b
	}
	return b
}

func (a *App) modeButton(value string) *widget.Clickable {
	b, ok := a.modeBtns[value]
	if !ok {
		b = &widget.Clickable{}
		a.modeBtns[value] = b
	}
	return b
}

// Layout renders one frame and processes widget events.
func (a *App) Layout(gtx layout.Context) layout.Dimensions {
	a.applyTheme()
	a.handleClicks(gtx)
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			size := gtx.Constraints.Min
			paint.FillShape(gtx.Ops, pal.Bg, clip.Rect{Max: size}.Op())
			return layout.Dimensions{Size: size}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(a.layoutHeader),
				layout.Rigid(a.layoutTabs),
				layout.Rigid(a.layoutErrorStrip),
				layout.Flexed(1, a.layoutBody),
			)
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			if a.sheet == nil {
				return layout.Dimensions{}
			}
			return a.layoutRiskSheet(gtx)
		}),
	)
}

// applyTheme resolves the persisted background choice into the
// active palette and, on change, re-syncs the material theme's
// base colors. "system" follows the OS appearance (navy when
// dark); where the OS value cannot be read it falls back to
// light, and the settings page says so (theme.system_fallback).
func (a *App) applyTheme() {
	setting := service.ThemeLight
	if a.svc != nil {
		setting = a.svc.Theme()
	}
	id := setting
	if setting == service.ThemeSystem {
		if dark, ok := platform.SystemDarkMode(); ok && dark {
			id = service.ThemeNavy
		} else {
			id = service.ThemeLight
		}
	}
	switch id {
	case service.ThemeNavy:
		pal = paletteNavy
	case service.ThemeInk:
		pal = paletteInk
	default:
		pal = paletteLight
	}
	if id != a.themeID {
		a.themeID = id
		a.th.Bg = pal.Bg
		a.th.Fg = pal.Text
		a.th.ContrastBg = pal.Primary
		a.th.ContrastFg = pal.White
	}
}

// systemUnreadable reports whether "follow system" is in
// effect but the OS appearance cannot be read on this device
// (the settings note's condition).
func (a *App) systemUnreadable() bool {
	if a.svc == nil || a.svc.Theme() != service.ThemeSystem {
		return false
	}
	_, ok := platform.SystemDarkMode()
	return !ok
}

func (a *App) handleClicks(gtx layout.Context) {
	for i := range a.tabBtns {
		if a.tabBtns[i].Clicked(gtx) {
			a.tab = i
		}
	}
	if a.disconnectBtn.Clicked(gtx) {
		a.setAutoPicked(false)
		a.runAsync("disconnect", func(ctx context.Context) error { return a.svc.Disconnect(ctx) })
	}
	if a.heroBtn.Clicked(gtx) {
		a.heroPrimaryAction()
	}
	if a.heroRetryBtn.Clicked(gtx) {
		a.startOneTap()
	}
	if a.heroReasonBtn.Clicked(gtx) {
		a.tab = tabLogs
	}
	if a.checkAllBtn.Clicked(gtx) {
		group := a.currentGroup()
		a.runAsync("check-all", func(ctx context.Context) error {
			_, err := a.svc.TestGroup(ctx, group)
			return err
		})
	}
	if a.guideBtn.Clicked(gtx) {
		a.openGuide()
	}
	if a.recBtn.Clicked(gtx) {
		a.openRiskSheet(sheetGateEnable)
	}
	if a.riskLinkBtn.Clicked(gtx) {
		if a.svc.VPNGateStatus().ConsentState == service.VPNGateConsentAcknowledged {
			a.openRiskSheet(sheetInfo)
		} else {
			a.openRiskSheet(sheetGateConnect)
		}
	}
	if a.viewAllBtn.Clicked(gtx) {
		a.groupEnum.Value = "all"
		a.applyGroupSelection()
		a.nodeList.Position.First = 0
		a.nodeList.Position.Offset = 0
	}
	if a.searchClearBtn.Clicked(gtx) {
		a.searchEd.SetText("")
	}
	if a.detourBtn.Clicked(gtx) {
		// "OK, move it over": the subscription was already
		// prefilled by the detour detection; just open the
		// subscription method row.
		a.expandedMethod = 2
	}
	if a.errStripBtn.Clicked(gtx) {
		a.tab = tabLogs
	}
	// Risk sheet controls.
	if a.sheet != nil {
		if a.sheetFullBtn.Clicked(gtx) {
			a.sheet.full = true
		}
		if a.sheetCloseBtn.Clicked(gtx) {
			a.sheet = nil
		}
		if a.sheetScrimBtn.Clicked(gtx) && a.sheet.mode == sheetInfo {
			a.sheet = nil
		}
		if a.sheetAgreeBtn.Clicked(gtx) {
			a.agreeRiskSheet()
		}
	}
	if a.importBtn.Clicked(gtx) {
		text := a.linksEd.Text()
		if u, ok := looksLikeSubscriptionURL(text); ok {
			// A bare http(s) address in the links box is almost
			// certainly a subscription URL pasted into the wrong
			// field (2026-11-14 usability ruling): do not feed
			// it to the link parser to die as an unexplained
			// failure — say what it looks like, and prefill the
			// subscription box so one more tap does the import.
			// We deliberately do NOT fetch it automatically:
			// an unrequested network fetch is the wrong default.
			a.urlEd.SetText(u)
			a.setImportNote(a.T("import.looks_like_url", nil))
		} else {
			a.setImportNote("")
			a.runImport(func() *service.ImportReport { return a.svc.ImportText(text) })
		}
	}
	if a.urlBtn.Clicked(gtx) {
		u := a.urlEd.Text()
		a.setImportNote("")
		a.runAsync("import-url", func(ctx context.Context) error {
			rep, err := a.svc.ImportSubscriptionURL(ctx, u, "")
			if rep != nil {
				a.setImportResult(rep)
			}
			return err
		})
	}
	if a.fileBtn.Clicked(gtx) {
		a.showFilePath = !a.showFilePath
	}
	if a.fileGoBtn.Clicked(gtx) {
		path := a.fileEd.Text()
		a.setImportNote("")
		a.runAsync("import-file", func(ctx context.Context) error {
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
}

// runAsync executes a service operation off the UI goroutine
// and records its (localized) outcome. Every failure it
// surfaces is ALSO written to the service's local log with its
// stage and real reason (op is the stage label): the banner
// tells the user the details are in the log, so the log must
// actually contain them — the broken error chain behind the
// 2026-11-14 "empty log page" report.
func (a *App) runAsync(op string, fn func(ctx context.Context) error) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.errKey = ""
	a.heroErr = nil
	a.heroFailed = false
	a.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		err := fn(ctx)
		if err != nil {
			a.svc.LogFailure(op, err)
		}
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
	a.heroErr = nil
	a.heroFailed = false
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

// --- v3 first-screen chain, guide, risk sheet ---------------------------

// guideURL is the website's illustrated guide; the in-app
// guide entries open it in the platform browser.
const guideURL = "https://relavia.github.io/guide.html"

// heroPrimaryAction dispatches the hero card's main button by
// the state the hero is showing.
func (a *App) heroPrimaryAction() {
	kind, view := a.heroKind()
	switch kind {
	case heroReconnect:
		if view != nil {
			id := view.Record.Node.ID
			a.setAutoPicked(false)
			a.runAsync("connect", func(ctx context.Context) error { return a.svc.Connect(ctx, id) })
		}
	case heroFastest, heroNew:
		a.startOneTap()
	}
}

// startOneTap begins the first-screen one-tap connect. When
// the pool's risk has not been acknowledged, the risk sheet
// gates the chain (agreeing there continues it); otherwise the
// chain runs at once.
func (a *App) startOneTap() {
	st := a.svc.VPNGateStatus()
	if st.Attached && st.ConsentState != service.VPNGateConsentAcknowledged {
		a.openRiskSheet(sheetGateConnect)
		return
	}
	a.runHeroChain()
}

// runHeroChain runs the one-tap sequence on the existing
// service chain — pool refresh (when consented), a real
// availability check of every node, then auto-select +
// connect — reporting its stage to the hero card. It mirrors
// runAsync's bookkeeping but keeps failures on the hero
// (with a retry) instead of the global error strip; failures
// are still logged with their stage like every other op.
func (a *App) runHeroChain() {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.errKey = ""
	a.heroErr = nil
	a.heroFailed = false
	a.heroStage = stageCheck
	if st := a.svc.VPNGateStatus(); st.Attached && st.ConsentState == service.VPNGateConsentAcknowledged {
		a.heroStage = stageRefresh
	}
	a.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := a.heroChainSteps(ctx)
		if err != nil {
			a.svc.LogFailure("one-tap-connect", err)
		}
		a.mu.Lock()
		a.busy = false
		a.heroStage = stageNone
		if err != nil {
			a.heroErr = err
			a.heroFailed = true
		}
		a.mu.Unlock()
		a.invalidate()
	}()
}

func (a *App) heroChainSteps(ctx context.Context) error {
	st := a.svc.VPNGateStatus()
	if st.Attached && st.ConsentState == service.VPNGateConsentAcknowledged {
		if !st.Enabled {
			_ = a.svc.EnableVPNGate()
		}
		if _, err := a.svc.RefreshVPNGate(ctx, false); err != nil {
			// A failed refresh keeps the last list (marked
			// stale by the service); the chain continues with
			// what is on record rather than dying here.
			a.svc.LogFailure("vpngate-refresh", err)
		}
	}
	a.setHeroStage(stageCheck)
	if _, err := a.svc.TestGroup(ctx, service.AllGroups); err != nil {
		return err
	}
	a.setHeroStage(stageConnect)
	if _, err := a.svc.AutoSelectAndConnect(ctx, service.AllGroups); err != nil {
		return err
	}
	a.setAutoPicked(true)
	return nil
}

// heroStage enumerates the one-tap chain's phases for the
// hero card's progress line.
type heroStage int

const (
	stageNone heroStage = iota
	stageRefresh
	stageCheck
	stageConnect
)

func (a *App) setHeroStage(s heroStage) {
	a.mu.Lock()
	a.heroStage = s
	a.mu.Unlock()
	a.invalidate()
}

// heroProgress snapshots the chain state for the hero card.
func (a *App) heroProgress() (stage heroStage, err error, failed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.heroStage, a.heroErr, a.heroFailed
}

func (a *App) autoPicked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.autoPickedFlag
}

func (a *App) setAutoPicked(b bool) {
	a.mu.Lock()
	a.autoPickedFlag = b
	a.mu.Unlock()
}

func (a *App) helpHintText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.helpHint
}

// openGuide opens the illustrated guide in the platform
// browser. A failure is logged and leaves a plain-language
// hint (with the address) under the guide entry — never a
// silent no-op.
func (a *App) openGuide() {
	go func() {
		err := platform.OpenURL(guideURL)
		if err != nil {
			a.svc.LogFailure("open-guide", err)
		}
		a.mu.Lock()
		if err != nil {
			a.helpHint = a.T("help.open_failed", nil)
		} else {
			a.helpHint = ""
		}
		a.mu.Unlock()
		a.invalidate()
	}()
}

// agreeRiskSheet performs the sheet's agree action: record
// the risk acknowledgement, close the sheet, then continue
// with the mode's follow-through (the one-tap chain, or
// enable + first refresh).
func (a *App) agreeRiskSheet() {
	if a.sheet == nil {
		return
	}
	mode := a.sheet.mode
	if err := a.svc.AcknowledgeVPNGateRisk(); err != nil {
		a.svc.LogFailure("vpngate-consent", err)
		a.mu.Lock()
		a.errKey = ErrorKey(err)
		a.mu.Unlock()
		a.sheet = nil
		return
	}
	a.sheet = nil
	if mode == sheetGateConnect {
		a.runHeroChain()
		return
	}
	a.runAsync("vpngate-enable", func(ctx context.Context) error {
		if err := a.svc.EnableVPNGate(); err != nil {
			return err
		}
		_, err := a.svc.RefreshVPNGate(ctx, true)
		return err
	})
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
	failKey := ""
	if len(rep.Failed) > 0 {
		failKey = importFailKey(rep.Failed[0].Code)
	}
	a.mu.Lock()
	a.importResult = text
	a.importFailKey = failKey
	a.mu.Unlock()
}

// importFailKey maps a parser failure code to its human,
// localized reason key. The full code set is core/parsers'
// stable error vocabulary plus the importer's own
// "model-conversion"; unknown codes fall back to a generic
// "could not recognize it" rather than leaking the raw code.
func importFailKey(code string) string {
	switch code {
	case "empty-input":
		return "import.fail.empty-input"
	case "input-too-large":
		return "import.fail.input-too-large"
	case "unknown-scheme":
		return "import.fail.unknown-scheme"
	case "unsupported-protocol":
		return "import.fail.unsupported-protocol"
	case "bad-base64":
		return "import.fail.bad-base64"
	case "bad-json":
		return "import.fail.bad-json"
	case "bad-uri":
		return "import.fail.bad-uri"
	case "missing-field":
		return "import.fail.missing-field"
	case "bad-port":
		return "import.fail.bad-port"
	case "bad-uuid":
		return "import.fail.bad-uuid"
	case "bad-key-format":
		return "import.fail.bad-key-format"
	case "unsupported-value":
		return "import.fail.unsupported-value"
	case "bad-format":
		return "import.fail.bad-format"
	case "model-conversion":
		return "import.fail.model-conversion"
	default:
		return "import.fail.unknown"
	}
}

// lastImportFailText renders the first-failure reason line for
// the import result area ("" when the last import had no
// failures).
func (a *App) lastImportFailText() string {
	a.mu.Lock()
	key := a.importFailKey
	a.mu.Unlock()
	if key == "" {
		return ""
	}
	return a.T("import.fail_first", map[string]string{"reason": a.T(key, nil)})
}

func (a *App) setImportNote(note string) {
	a.mu.Lock()
	a.importNote = note
	a.mu.Unlock()
}

func (a *App) lastImportNote() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.importNote
}

// looksLikeSubscriptionURL reports whether the pasted text is
// exactly one bare http(s) URL — the shape of a subscription
// address pasted into the links box.
func looksLikeSubscriptionURL(text string) (string, bool) {
	t := strings.TrimSpace(text)
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", false
	}
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return t, true
	}
	return "", false
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
	case errors.Is(err, android.ErrPermissionDenied):
		// The OS VPN consent was refused (Android TUN
		// choreography). The pack string is the same one the
		// Android shell surfaces: it tells the user the
		// connection was not established and consent can be
		// granted on the next attempt.
		return "android.vpn_permission_denied"
	case errors.Is(err, service.ErrNoTestedNode):
		return "err.no_tested_node"
	case errors.Is(err, service.ErrNoEngine):
		return "err.platform_unavailable"
	case errors.Is(err, service.ErrVPNGateConsentRequired):
		return "err.vpngate_consent_required"
	case errors.Is(err, service.ErrVPNGateFetchFailed):
		return "err.vpngate_fetch_failed"
	case errors.Is(err, service.ErrVPNGateNotAttached):
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

// statusKind classifies the header status pill.
type statusKind int

const (
	statusIdle statusKind = iota
	statusBusy
	statusRunning
	statusFailed
)

func (a *App) statusKind() statusKind {
	st := a.svc.Status()
	switch st.State {
	case kernel.StateRunning:
		return statusRunning
	case kernel.StateStarting, kernel.StateStopping:
		return statusBusy
	case kernel.StateFailed:
		return statusFailed
	default:
		if a.isBusy() {
			return statusBusy
		}
		return statusIdle
	}
}

// isConnecting reports whether a connection attempt is in
// flight (engine starting, or an async connect op running).
func (a *App) isConnecting() bool {
	st := a.svc.Status()
	if st.State == kernel.StateStarting || st.State == kernel.StateStopping {
		return true
	}
	return a.isBusy() && st.State != kernel.StateRunning
}

func (a *App) layoutHeader(gtx layout.Context) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(12), Bottom: unit.Dp(10),
		Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(eyeMark),
			layout.Rigid(layout.Spacer{Width: unit.Dp(9)}.Layout),
			layout.Rigid(a.lbl(17, font.Bold, pal.Text, a.T("app.title", nil)).Layout),
			layout.Flexed(1, layout.Spacer{}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// Status is a single dot here; the sentence
				// lives on the hero card (v3 first screen).
				d := gtx.Dp(unit.Dp(10))
				size := image.Pt(d, d)
				switch a.statusKind() {
				case statusRunning:
					paint.FillShape(gtx.Ops, pal.Success, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
				case statusBusy:
					paint.FillShape(gtx.Ops, pal.Primary, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
				case statusFailed:
					paint.FillShape(gtx.Ops, pal.Danger, clip.Ellipse(image.Rect(0, 0, d, d)).Op(gtx.Ops))
				default:
					paint.FillShape(gtx.Ops, pal.Hint, clip.Stroke{
						Path:  clip.Ellipse(image.Rect(0, 0, d, d)).Path(gtx.Ops),
						Width: float32(gtx.Dp(unit.Dp(1.6))),
					}.Op())
				}
				return layout.Dimensions{Size: size}
			}),
		)
	})
}

func (a *App) layoutTabs(gtx layout.Context) layout.Dimensions {
	keys := []string{"nav.nodes", "nav.import", "nav.logs", "nav.settings"}
	icons := []iconKind{iconGlobe, iconDownload, iconList, iconGear}
	return layout.Inset{Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(44))
			return layout.Stack{}.Layout(gtx,
				layout.Expanded(func(gtx layout.Context) layout.Dimensions {
					size := gtx.Constraints.Min
					fillRRect(gtx, size, 12, pal.PillIdle)
					return layout.Dimensions{Size: size}
				}),
				layout.Stacked(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Left: unit.Dp(4), Right: unit.Dp(4),
						Top: unit.Dp(4), Bottom: unit.Dp(4),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						children := make([]layout.FlexChild, 0, len(keys))
						for i, key := range keys {
							i, key := i, key
							children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								selected := a.tab == i
								return material.Clickable(gtx, &a.tabBtns[i], func(gtx layout.Context) layout.Dimensions {
									return layout.Stack{}.Layout(gtx,
										layout.Expanded(func(gtx layout.Context) layout.Dimensions {
											size := gtx.Constraints.Min
											if selected {
												fillRRect(gtx, size, 9, pal.Card)
												strokeRRect(gtx, size, 9, pal.Border)
											}
											return layout.Dimensions{Size: size}
										}),
										layout.Stacked(func(gtx layout.Context) layout.Dimensions {
											// Carry the tab height (44
											// container minus its 4dp
											// insets) on the Stacked
											// child: Gio Stacks size
											// from Stacked children
											// alone, so the selected
											// capsule fill otherwise
											// paints at content height.
											gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(36))
											fg := pal.Secondary
											w := font.Normal
											if selected {
												fg = pal.Text
												w = font.Bold
											}
											return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return iconLayout(gtx, icons[i], 18, fg)
													}),
													layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
													layout.Rigid(a.lbl(14, w, fg, a.T(key, nil)).Layout),
												)
											})
										}),
									)
								})
							}))
						}
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
					})
				}),
			)
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

// layoutErrorStrip is the global error line's v3 home: a
// full-width danger strip under the tabs (the v2 footer row is
// gone - the run mode it announced now lives in Settings).
// Capped at two lines, however long the text is; tapping it
// opens the log page the text points to.
func (a *App) layoutErrorStrip(gtx layout.Context) layout.Dimensions {
	errKey := a.lastErrKey()
	if errKey == "" {
		return layout.Dimensions{}
	}
	return layout.Inset{
		Left: unit.Dp(dpMargin), Right: unit.Dp(dpMargin), Top: unit.Dp(8),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return material.Clickable(gtx, &a.errStripBtn, func(gtx layout.Context) layout.Dimensions {
			return layout.Stack{}.Layout(gtx,
				layout.Expanded(func(gtx layout.Context) layout.Dimensions {
					size := gtx.Constraints.Min
					fillRRect(gtx, size, dpBtnRad, pal.DangerBg)
					return layout.Dimensions{Size: size}
				}),
				layout.Stacked(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Left: unit.Dp(12), Right: unit.Dp(10),
						Top: unit.Dp(9), Bottom: unit.Dp(9),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return iconLayout(gtx, iconWarn, 16, pal.Danger)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Flexed(1, a.lblMax(12.5, font.Normal, pal.Danger, a.T(errKey, nil), 2).Layout),
							layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return iconLayout(gtx, iconChevron, 16, pal.Danger)
							}),
						)
					})
				}),
			)
		})
	})
}

// sampleTraffic kicks an asynchronous engine counter read (at
// most one in flight) and caches the last successful sample.
// Counters only ever come from the engine (service.Traffic);
// platforms whose engine exposes none keep trafficOK false and
// the UI shows no traffic figures at all.
func (a *App) sampleTraffic() {
	select {
	case a.trafficMu <- struct{}{}:
		go func() {
			defer func() { <-a.trafficMu }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stats, err := a.svc.Traffic(ctx)
			if err == nil && stats != nil {
				a.mu.Lock()
				a.trafficStats = stats
				a.trafficOK = true
				a.mu.Unlock()
			}
		}()
	default:
	}
}

// trafficAvailable reports whether this build's engine exposes
// real traffic counters AND a sample has landed. The capability
// half of the gate is what keeps the Android TUN build (whose
// binding exposes no counters, Features.TrafficStats=false)
// from ever rendering the traffic card.
func (a *App) trafficAvailable() bool {
	if !a.svc.Capabilities().Features.TrafficStats {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.trafficOK
}

func (a *App) traffic() *kernel.TrafficStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.trafficStats
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
