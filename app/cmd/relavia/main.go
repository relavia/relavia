// Command relavia is the Relavia desktop client entry point
// (Windows-first; the same shell runs on Linux for development).
//
// Wiring: unified-model store (interim plain JSON — Step 13 swaps
// in encrypted storage at service.Store) -> application service
// layer -> sing-box kernel adapter (in-process, manual mode in
// this step; TUN/system-proxy platform work lands in Steps
// 11-12 and the UI labels that honestly) -> Gio shell + platform
// tray.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"openproxy/app/i18n"
	"openproxy/app/locales"
	"openproxy/app/platform"
	"openproxy/app/service"
	"openproxy/app/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "relavia:", err)
		os.Exit(1)
	}
}

func run() error {
	storePath, err := service.DefaultStorePath()
	if err != nil {
		return err
	}
	store, err := service.OpenStore(storePath)
	if err != nil {
		return err
	}

	// The engine's log sink needs the service, and the service
	// needs the engine; bind the sink through a late reference.
	var svc *service.Service
	logSink := func(level, message string) {
		if svc != nil {
			svc.OnKernelLog(level, message)
		}
	}
	// Protocol dispatch: sing-box families to the sing-box
	// adapter, OpenVPN nodes (incl. the VPN Gate pool) to the
	// independent-process adapter.
	engine := service.NewDispatchEngine(
		service.NewSingBoxEngine(logSink),
		service.NewOpenVPNEngine(logSink),
	)
	svc = service.New(store, engine)
	service.AttachVPNGateDefault(svc, storePath)

	initialLang := store.Settings().Language
	if initialLang == "" {
		initialLang = locales.Source
	}
	tr, err := i18n.New(locales.FS, locales.Supported, initialLang, locales.Fallback)
	if err != nil {
		return err
	}

	th := material.NewTheme()
	th.Shaper = ui.NewShaper()
	if desc := ui.BundledCJKDescription(); desc != "" {
		svc.Logs().Add(fmt.Sprintf("fonts: bundled font collection active (%s); no system fonts are used", desc))
	} else {
		svc.Logs().Add("fonts: WARNING bundled CJK font failed to parse; CJK text may render as boxes")
	}

	w := new(app.Window)
	w.Option(
		app.Title(tr.T("app.title", nil)),
		app.Size(unit.Dp(960), unit.Dp(640)),
		app.MinSize(unit.Dp(640), unit.Dp(420)),
	)

	shell := ui.New(svc, tr, th)
	ui.SetInvalidateFunc(w.Invalidate)

	// Tray: menu labels are (re)built from the active language;
	// a language switch rebuilds them without restart.
	tray := platform.NewTray(platform.TrayEvents{
		OnShowWindow: func() { w.Invalidate() },
		OnMenuItem: func(id string) {
			switch id {
			case "connect":
				if sel := svc.SelectedNodeID(); sel != "" {
					go func() { _ = svc.Connect(context.Background(), sel) }()
				}
			case "disconnect":
				go func() { _ = svc.Disconnect(context.Background()) }()
			case "quit":
				w.Perform(system.ActionClose)
			}
			w.Invalidate()
		},
	})
	shell.Tray = tray
	buildTrayMenu := func() {
		tray.SetMenu([]platform.TrayMenuItem{
			{ID: "show", Label: tr.T("tray.show", nil)},
			{ID: "connect", Label: tr.T("tray.connect", nil)},
			{ID: "disconnect", Label: tr.T("tray.disconnect", nil)},
			{ID: "-", Label: "-"},
			{ID: "quit", Label: tr.T("tray.quit", nil)},
		})
		tray.SetTooltip(tr.T("tray.tooltip", nil))
	}
	buildTrayMenu()
	shell.OnLangChanged = func(string) { buildTrayMenu() }
	if tray.Available() {
		_ = tray.Show(tr.T("tray.tooltip", nil))
		defer func() { _ = tray.Hide() }()
	}

	// Periodic refresh while running (traffic + status).
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			w.Invalidate()
		}
	}()

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			shell.Layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}
