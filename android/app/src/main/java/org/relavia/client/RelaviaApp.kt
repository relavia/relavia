package org.relavia.client

import android.app.Application

/**
 * Process bootstrap for the merged APK
 * (docs/android产品界面接入.md).
 *
 * Every process entry point funnels through here before any
 * surface exists: [ShellRuntime.ensureStarted] records the
 * storage paths with the Go library and registers the shell
 * bridge — and, on the Go side, the Setup facade call is what
 * starts the product (Gio) UI's window loop, so the UI is
 * ready before the launcher activity (org.gioui.GioActivity)
 * creates its view. RelaviaVpnService.onCreate calls
 * ensureStarted as well; it is idempotent, so a process
 * started for the service alone converges to the same state.
 */
class RelaviaApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ShellRuntime.ensureStarted(this)
    }
}
