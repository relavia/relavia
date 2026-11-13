package org.relavia.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/**
 * The VPN consent surface (docs/android产品界面接入.md §5).
 *
 * This is the consent half of the retired shell MainActivity,
 * kept as a dedicated invisible activity: only an Activity can
 * run the system's VpnService consent dialog, and the product
 * UI (org.gioui.GioActivity) cannot be reused for it — the Go
 * session asks for consent through ShellBridgeImpl.prepare(),
 * which starts this activity with [ACTION_CONSENT] and waits
 * on the bridge latch.
 *
 * The activity itself renders nothing (translucent theme in
 * the manifest): if consent is already granted it reports
 * success and finishes immediately; otherwise it shows the
 * system dialog and reports the user's decision to
 * [ShellBridgeImpl.onConsentResult]. A refusal unwinds the Go
 * connect into its typed permission error, which the product
 * UI surfaces with the android.vpn_permission_denied pack
 * string — the same honest copy the shell page used to show.
 */
class ConsentActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ShellRuntime.ensureStarted(this)
        if (intent?.action == ACTION_CONSENT) {
            handleConsentAction()
        } else {
            // Not a consent request: nothing for this surface
            // to do (it is not a launcher and shows no UI).
            finish()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.action == ACTION_CONSENT) {
            handleConsentAction()
        }
    }

    private fun handleConsentAction() {
        val consent = VpnService.prepare(this)
        if (consent == null) {
            ShellBridgeImpl.onConsentResult(true)
            finish()
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQ_VPN_CONSENT)
        }
    }

    @Deprecated("Activity result API kept deliberately: the consent flow is a single request")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_VPN_CONSENT) return
        ShellBridgeImpl.onConsentResult(resultCode == RESULT_OK)
        finish()
    }

    companion object {
        /**
         * Intent action: run the consent dialog for
         * ShellBridgeImpl.prepare(). The string is unchanged
         * from the retired MainActivity's contract.
         */
        const val ACTION_CONSENT = "org.relavia.client.action.CONSENT"

        private const val REQ_VPN_CONSENT = 1001
    }
}
