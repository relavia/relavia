package org.relavia.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import org.relavia.libboxbind.TunParams

/**
 * The VpnService thin shell (Step 10, libbox-bound).
 *
 * Owns exactly what the Android platform reserves for the app
 * process: the TUN interface lifecycle, the mandatory
 * foreground notification, and system revocation (onRevoke).
 *
 * Since the libbox binding, the service no longer establishes
 * the interface on its own schedule with hardcoded parameters.
 * Go's session choreography drives: consent, interface
 * parameters (from the compiled TUN configuration, mirrored by
 * platform.DefaultTUNRequest) and teardown all arrive through
 * [ShellBridgeImpl]; this service executes them against
 * [Builder]. The fd it returns travels: Builder ->
 * ShellBridgeImpl.establishTun -> Go choreography (pending fd)
 * -> libbox platform OpenTun (which dups it internally). This
 * service keeps owning the [ParcelFileDescriptor] and closes
 * it only when the choreography says so (bridge CloseTun /
 * Teardown), or when the system takes the interface away
 * (onRevoke / onDestroy).
 *
 * No root and no non-public APIs are used anywhere here.
 */
class RelaviaVpnService : VpnService() {

    private val tunLock = Any()
    private var tun: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        ShellRuntime.ensureStarted(applicationContext)
        ShellBridgeImpl.onServiceReady(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                // A user disconnect: unwind through the Go
                // session (box stop -> interface close -> this
                // service's teardown), falling back to a purely
                // local teardown if Go never answers.
                Thread {
                    GoBridge.sessionStop()
                    stopTunnelLocal()
                }.start()
                START_NOT_STICKY
            }
            ACTION_START -> {
                // Bring-up only: foreground state promptly (the
                // bridge starts this service via
                // startForegroundService when Go asks for the
                // interface), then wait for bridge calls. The
                // interface itself is established on Go's word,
                // not here.
                showForeground(connected = false)
                START_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        // The system or the user revoked the VPN (another VPN
        // app took over, consent withdrawn in settings,
        // always-on conflict). The interface is already dead:
        // tell Go first (it closes the box whose dup'd fd died
        // with the interface), then tear down locally.
        GoBridge.notifyTunRevoked()
        stopTunnelLocal()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnelLocal()
        ShellBridgeImpl.onServiceGone(this)
        super.onDestroy()
    }

    // --- bridge-facing operations (called via ShellBridgeImpl) ----

    /**
     * Establish the TUN interface from the Go-supplied
     * parameters and return its raw fd. Throws on any failure —
     * the Go side surfaces it as the connection error. The
     * notification flips to "connected" on hand-off: if the box
     * then fails to start, Go's failure unwind runs Teardown
     * and the notification disappears with the service.
     */
    fun establishFromBridge(params: TunParams): Int {
        synchronized(tunLock) {
            closeTunLocked()
            val builder = Builder()
                .setSession(getString(R.string.notif_title_connected))
                .setBlocking(false)
            addAddressIfPresent(builder, params.getInet4Address())
            addAddressIfPresent(builder, params.getInet6Address())
            val dns = params.getDNSServers()?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?: emptyList()
            for (server in dns) {
                builder.addDnsServer(server)
            }
            val routes = params.getRoutes()?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?: emptyList()
            if (routes.isEmpty()) {
                builder.addRoute("0.0.0.0", 0)
                if (!params.getInet6Address().isNullOrEmpty()) {
                    builder.addRoute("::", 0)
                }
            } else {
                for (route in routes) {
                    addRouteIfPresent(builder, route)
                }
            }
            if (params.getMTU() > 0) {
                builder.setMtu(params.getMTU())
            }
            val pfd = builder.establish()
                ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
            tun = pfd
            showForeground(connected = true)
            return pfd.fd
        }
    }

    /** Close the established interface, if any. Idempotent. */
    fun closeTunFromBridge() {
        synchronized(tunLock) {
            closeTunLocked()
        }
    }

    /** Full local teardown: interface, foreground, service. Idempotent. */
    fun teardownFromBridge() {
        stopTunnelLocal()
    }

    // --- internals ---------------------------------------------------

    private fun closeTunLocked() {
        try {
            tun?.close()
        } catch (e: Exception) {
            // Closing an already-dead interface is fine.
        }
        tun = null
    }

    private fun stopTunnelLocal() {
        synchronized(tunLock) {
            closeTunLocked()
        }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun addAddressIfPresent(builder: Builder, cidr: String?) {
        if (cidr.isNullOrEmpty()) return
        val parts = cidr.split("/", limit = 2)
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: if (parts[0].contains(":")) 128 else 32
        builder.addAddress(parts[0], prefix)
    }

    private fun addRouteIfPresent(builder: Builder, cidr: String) {
        val parts = cidr.split("/", limit = 2)
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: if (parts[0].contains(":")) 128 else 32
        builder.addRoute(parts[0], prefix)
    }

    private fun showForeground(connected: Boolean) {
        ensureChannel(this)
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification(connected),
            foregroundServiceType(),
        )
    }

    private fun buildNotification(connected: Boolean): Notification {
        val titleKey = if (connected) KEY_NOTIF_TITLE_CONNECTED else KEY_NOTIF_TITLE_CONNECTING
        val titleFallback = if (connected) R.string.notif_title_connected else R.string.notif_title_connecting
        val disconnectIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, RelaviaVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, org.gioui.GioActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle(GoBridge.text(titleKey, getString(titleFallback)))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                GoBridge.text(KEY_NOTIF_ACTION_DISCONNECT, getString(R.string.notif_action_disconnect)),
                disconnectIntent,
            )
            .build()
    }

    private fun foregroundServiceType(): Int {
        // Matches android:foregroundServiceType="specialUse" in
        // the manifest; only meaningful on API 34+.
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
    }

    companion object {
        const val ACTION_START = "org.relavia.client.action.START"
        const val ACTION_STOP = "org.relavia.client.action.STOP"

        const val CHANNEL_ID = "relavia-connection"
        private const val NOTIFICATION_ID = 1

        // i18n keys (app/locales packs) for every shell string.
        private const val KEY_NOTIF_TITLE_CONNECTED = "android.notif_title_connected"
        private const val KEY_NOTIF_TITLE_CONNECTING = "android.notif_title_connecting"
        private const val KEY_NOTIF_ACTION_DISCONNECT = "android.notif_action_disconnect"

        /** Create the notification channel once (idempotent). */
        fun ensureChannel(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val nm = context.getSystemService(NotificationManager::class.java)
                if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
                    val name = GoBridge.text(
                        "android.notif_channel_name",
                        context.getString(R.string.notif_channel_name),
                    )
                    nm?.createNotificationChannel(
                        NotificationChannel(CHANNEL_ID, name, NotificationManager.IMPORTANCE_LOW),
                    )
                }
            }
        }
    }
}
