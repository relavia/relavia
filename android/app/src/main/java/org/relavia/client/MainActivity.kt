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
import androidx.core.content.ContextCompat

/**
 * The shell's single Activity (Step 10): owns the two things
 * Android reserves for an Activity — the VpnService consent
 * flow (VpnService.prepare) and the POST_NOTIFICATIONS runtime
 * request — plus minimal start/stop controls so the shell is
 * exercisable on its own. The product UI is the Go/Gio surface;
 * this Activity is deliberately not it.
 *
 * All visible text comes from string resources, which are the
 * bootstrap fallbacks of the trilingual packs (see res/values*
 * and GoBridge): once the Go runtime is bound, the packs in
 * app/locales are the source of truth.
 */
class MainActivity : Activity() {

    private lateinit var statusView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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
    }

    private fun requestConnect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            // Not yet granted: the system consent dialog runs,
            // and onActivityResult continues the flow.
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQ_VPN_CONSENT)
        } else {
            startVpn()
        }
    }

    private fun requestDisconnect() {
        startService(Intent(this, RelaviaVpnService::class.java).setAction(RelaviaVpnService.ACTION_STOP))
        statusView.text = getString(R.string.main_status_idle)
    }

    private fun startVpn() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, RelaviaVpnService::class.java).setAction(RelaviaVpnService.ACTION_START),
        )
        statusView.text = GoBridge.text(
            "android.notif_title_connecting",
            getString(R.string.notif_title_connecting),
        )
    }

    @Deprecated("Activity result API kept for the thin shell; the consent flow is a single request")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_VPN_CONSENT) return
        if (resultCode == RESULT_OK) {
            startVpn()
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
        private const val REQ_VPN_CONSENT = 1001
        private const val REQ_NOTIFICATIONS = 1002
    }
}
