package org.relavia.client

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import org.relavia.libboxbind.Libboxbind
import org.relavia.libboxbind.Ovpn3Bridge

/**
 * Shared state for the one OpenVPN 3 session this process can
 * host: the pending profile the Go engine handed over (waiting
 * for the service to pick it up) and the live client (so a
 * stop request from Go reaches the core's stop() directly).
 * The Go engine serialises sessions (wrong-state on a second
 * start), so single slots are the honest shape.
 */
object Ovpn3SessionController {

    class Pending(val profile: String, val username: String, val password: String)

    @Volatile
    var pending: Pending? = null

    @Volatile
    var client: Ovpn3Client? = null

    /** Ask the live core to disconnect. Safe when idle. */
    fun requestStop() {
        try {
            client?.stop()
        } catch (e: Exception) {
            // A core tearing itself down concurrently answers
            // with a dead object; stopping is idempotent.
        }
    }
}

/**
 * The Kotlin implementation of the Go Ovpn3Bridge interface:
 * Go hands over a rendered profile; this object starts the
 * VPN service in its OpenVPN 3 mode and lets the service's
 * [Ovpn3Client] run it. Session outcomes travel back through
 * the Libboxbind.notifyOvpn3* facade entries, never through
 * return values (a connect can take tens of seconds).
 */
object Ovpn3BridgeImpl : Ovpn3Bridge {

    @Volatile
    var appContext: Context? = null

    /**
     * Register with Go when — and only when — the native
     * library is actually in the APK. A build without
     * libovpn3android.so must leave the engine in its honest
     * unavailable state, so a failed load registers nothing.
     */
    fun registerIfAvailable() {
        try {
            System.loadLibrary("ovpn3android")
            Libboxbind.registerOvpn3Bridge(this)
        } catch (e: UnsatisfiedLinkError) {
            // Native side absent: stay unregistered on purpose.
        } catch (e: NoClassDefFoundError) {
            // Binding classes absent (unbound build): same.
        }
    }

    override fun startOvpn3Session(profile: String, username: String, password: String) {
        val ctx = appContext
            ?: throw IllegalStateException("ovpn3 bridge has no application context")
        Ovpn3SessionController.pending =
            Ovpn3SessionController.Pending(profile, username, password)
        ContextCompat.startForegroundService(
            ctx,
            Intent(ctx, RelaviaVpnService::class.java)
                .setAction(RelaviaVpnService.ACTION_OVPN3_START),
        )
    }

    override fun stopOvpn3Session() {
        Ovpn3SessionController.requestStop()
        // If the service is still in bring-up (no client yet),
        // the stop intent tells it to stand down instead of
        // connecting a session Go already gave up on.
        val ctx = appContext ?: return
        try {
            ctx.startService(
                Intent(ctx, RelaviaVpnService::class.java)
                    .setAction(RelaviaVpnService.ACTION_OVPN3_STOP),
            )
        } catch (e: Exception) {
            // Service not running: nothing to stand down.
        }
    }
}
