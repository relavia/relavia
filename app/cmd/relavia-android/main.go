// Command relavia-android is the Android entry point of the
// Relavia client (Step 10): the Step 9 Gio shell and service
// layer running on Android. It is built with gogio (Gio's
// Android packager) — see scripts/build-android.sh and the CI
// android job.
//
// This file deliberately carries NO "//go:build android"
// constraint: gogio resolves the package with a host-side
// "go list" before cross-compiling, and an android-only
// constraint makes that listing fail with "build constraints
// exclude all Go files" (CI run 43289103659, Step 10 android
// job). The package is only ever packaged for Android (the
// gogio step above); platform differences live behind the
// platform package's own per-OS files, as on desktop. The production APK additionally embeds the
// Kotlin VpnService shell from the repo-root android/ directory,
// which is the only component allowed to create the TUN
// interface (book 8.2); the TUN connect choreography itself
// lives in openproxy/app/android and is exercised by its tests.
//
// Posture of this Gio build until the libbox binding lands: it
// is a logic/UI validation shell. The in-process kernel runs as
// on desktop; the VpnService bridge reports unavailable unless
// a binder is registered, and TUN-mode connects refuse
// explicitly (adapter capability, Step 7). A logic-validation
// variant (RELAVIA_FAKE_VPN=1 in the app environment) registers
// the platform fake so the consent -> establish -> fd hand-off
// choreography can be exercised on a device; it carries NO real
// traffic and announces that in the log with the
// android.fake_vpn_notice pack string.
package main

import (
	"fmt"
	"os"
	"time"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/text"
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
	// On Android the app sandbox path is owned by the shell;
	// the Gio logic build has no shell, so an explicit override
	// is honored and DefaultStorePath is the fallback.
	storePath := os.Getenv("RELAVIA_STORE")
	if storePath == "" {
		var err error
		storePath, err = service.DefaultStorePath()
		if err != nil {
			return err
		}
	}
	store, err := service.OpenStore(storePath)
	if err != nil {
		return err
	}

	var svc *service.Service
	logSink := func(level, message string) {
		if svc != nil {
			svc.OnKernelLog(level, message)
		}
	}
	// Protocol dispatch with the Android OpenVPN slot: the
	// process adapter cannot run on Android, so OpenVPN nodes
	// (incl. the VPN Gate pool) stay importable/probeable and
	// connects fail honestly (see service.NewAndroidOpenVPNEngine).
	engine := service.NewDispatchEngine(
		service.NewSingBoxEngine(logSink),
		service.NewAndroidOpenVPNEngine(),
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

	if os.Getenv("RELAVIA_FAKE_VPN") == "1" {
		platform.RegisterVPNBinder(platform.NewFakeVPNService())
		svc.Logs().Add(tr.T("android.fake_vpn_notice", nil))
	}

	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(ui.FontCollection()))

	w := new(app.Window)
	w.Option(
		app.Title(tr.T("app.title", nil)),
		app.Size(unit.Dp(420), unit.Dp(760)),
	)

	gshell := ui.New(svc, tr, th)
	gshell.Tray = platform.NewTray(platform.TrayEvents{})
	ui.SetInvalidateFunc(w.Invalidate)

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
			gshell.Layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}
