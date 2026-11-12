package org.relavia.client

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * The shell's single Activity (Step 10, libbox-bound): owns the
 * things Android reserves for an Activity — the VpnService
 * consent flow (VpnService.prepare) and the POST_NOTIFICATIONS
 * runtime request — plus minimal start/stop controls so the
 * shell is exercisable on its own. The product UI is the
 * Go/Gio surface; this Activity is deliberately not it.
 *
 * Connect/disconnect now drive the Go session
 * (GoBridge.sessionStart/sessionStop) on a background thread:
 * the session's choreography calls back into the shell through
 * ShellBridgeImpl for consent, interface establishment and
 * teardown. The service is started by the bridge when Go asks
 * for the interface — this Activity must NOT start it directly
 * anymore.
 *
 * The Activity doubles as the consent surface for
 * bridge-initiated connects (ACTION_CONSENT from
 * ShellBridgeImpl.prepare, e.g. when a future Gio surface
 * starts a session without this Activity's own button flow):
 * it runs the same dialog and reports the outcome to the
 * bridge latch instead of starting a session itself.
 *
 * All visible text comes from string resources, which are the
 * bootstrap fallbacks of the trilingual packs (see res/values*
 * and GoBridge): once the Go runtime is bound, the packs in
 * app/locales are the source of truth.
 */
class MainActivity : Activity() {

    private lateinit var statusView: TextView

    /** True while this instance serves a ShellBridgeImpl consent request. */
    private var consentForBridge: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Bring the Go runtime up first so pack-backed text is
        // available to everything below (falls back silently in
        // unbound builds).
        ShellRuntime.ensureStarted(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        statusView = TextView(this).apply {
            text = getString(R.string.main_status_idle)
            gravity = Gravity.CENTER
        }
        val connectButton = Button(this).apply {
            text = getString(R.string.main_connect)
            setOnClickListener { requestConnect() }
        }
        val disconnectButton = Button(this).apply {
            text = getString(R.string.main_disconnect)
            setOnClickListener { requestDisconnect() }
        }
        root.addView(statusView)
        root.addView(connectButton)
        root.addView(disconnectButton)
        setContentView(root)

        requestNotificationPermission()

        if (intent?.action == ACTION_CONSENT) {
            handleConsentAction()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.action == ACTION_CONSENT) {
            handleConsentAction()
        }
    }

    /** Bridge-initiated consent: dialog only, result to the bridge latch. */
    private fun handleConsentAction() {
        consentForBridge = true
        val consent = VpnService.prepare(this)
        if (consent == null) {
            ShellBridgeImpl.onConsentResult(true)
            finish()
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQ_VPN_CONSENT)
        }
    }

    private fun requestConnect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            // Not yet granted: the system consent dialog runs,
            // and onActivityResult continues the flow.
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQ_VPN_CONSENT)
        } else {
            startSessionAsync()
        }
    }

    private fun requestDisconnect() {
        Thread {
            GoBridge.sessionStop()
            runOnUiThread {
                statusView.text = getString(R.string.main_status_idle)
            }
        }.start()
    }

    private fun startSessionAsync() {
        statusView.text = getString(R.string.notif_title_connecting)
        Thread {
            val ok = GoBridge.sessionStart()
            runOnUiThread {
                statusView.text = if (ok) {
                    GoBridge.text("android.notif_title_connected", getString(R.string.notif_title_connected))
                } else {
                    getString(R.string.vpn_permission_denied)
                }
            }
        }.start()
    }

    @Deprecated("Activity result API kept for the thin shell; the consent flow is a single request")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_VPN_CONSENT) return
        if (consentForBridge) {
            // Report to the bridge latch and leave; the Go
            // session waiting in prepare() proceeds (or fails)
            // on its own thread.
            consentForBridge = false
            ShellBridgeImpl.onConsentResult(resultCode == RESULT_OK)
            finish()
            return
        }
        if (resultCode == RESULT_OK) {
            startSessionAsync()
        } else {
            statusView.text = GoBridge.text(
                "android.vpn_permission_denied",
                getString(R.string.vpn_permission_denied),
            )
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
        }
    }

    companion object {
        /** Intent action: run the consent dialog for ShellBridgeImpl.prepare(). */
        const val ACTION_CONSENT = "org.relavia.client.action.CONSENT"

        private const val REQ_VPN_CONSENT = 1001
        private const val REQ_NOTIFICATIONS = 1002
    }
}
