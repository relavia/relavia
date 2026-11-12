package org.relavia.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * The VpnService thin shell (Step 10).
 *
 * Owns exactly what the Android platform reserves for the app
 * process: the TUN interface lifecycle (Builder.establish /
 * close), the mandatory foreground notification, and system
 * revocation (onRevoke). Everything else — node choice, session
 * state machine, the data plane itself — lives on the Go side
 * and is reached through [GoBridge]: the established fd is
 * handed over, Go reads and writes it (libbox pattern).
 *
 * The TUN parameters mirror platform.DefaultTUNRequest on the
 * Go side (app/platform/vpn.go), which mirrors the sing-box TUN
 * inbound defaults; keep the two in step — the Go values are
 * the source of truth.
 *
 * No root and no non-public APIs are used anywhere here.
 */
class RelaviaVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                START_NOT_STICKY
            }
            ACTION_START -> {
                startTunnel()
                START_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        // The system or the user revoked the VPN permission
        // (e.g. another VPN app took over, or consent was
        // withdrawn in settings). Tear down exactly like a
        // user disconnect.
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun startTunnel() {
        if (tun != null) return // already established; idempotent

        createChannel()
        // Foreground first (required promptly after
        // startForegroundService), showing the connecting state.
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification(connected = false, nodeName = null),
            foregroundServiceType(),
        )

        // Consent is the Activity's job (VpnService.prepare);
        // if it is somehow missing, prepare() here returns an
        // intent and establish() would fail — fail closed.
        if (VpnService.prepare(this) != null) {
            stopTunnel()
            return
        }

        val pfd = try {
            Builder()
                .setSession(GoBridge.text(KEY_NOTIF_TITLE_CONNECTED, getString(R.string.notif_title_connected)))
                .addAddress(TUN_IPV4_ADDR, TUN_IPV4_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(TUN_DNS)
                .setMtu(TUN_MTU)
                .setBlocking(false)
                .establish()
        } catch (e: Exception) {
            null
        }
        if (pfd == null) {
            stopTunnel()
            return
        }
        tun = pfd

        // Hand the fd to the Go data plane. When the Go runtime
        // is not bound into this build yet, the honest outcome
        // is to close the interface again rather than blackhole
        // the device's traffic into a dead fd.
        if (!GoBridge.tunEstablished(pfd.fd)) {
            stopTunnel()
            return
        }

        // Connected state on the persistent notification.
        val nm = getSystemService(NotificationManager::class.java)
        nm?.notify(NOTIFICATION_ID, buildNotification(connected = true, nodeName = null))
    }

    private fun stopTunnel() {
        GoBridge.tunClosed()
        try {
            tun?.close()
        } catch (e: Exception) {
            // Closing an already-dead interface is fine.
        }
        tun = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val name = GoBridge.text(KEY_NOTIF_CHANNEL, getString(R.string.notif_channel_name))
            val channel = NotificationChannel(CHANNEL_ID, name, NotificationManager.IMPORTANCE_LOW)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(connected: Boolean, nodeName: String?): Notification {
        val titleKey = if (connected) KEY_NOTIF_TITLE_CONNECTED else KEY_NOTIF_TITLE_CONNECTING
        val titleFallback = if (connected) R.string.notif_title_connected else R.string.notif_title_connecting
        val text = if (connected && nodeName != null) {
            GoBridge.text(KEY_NOTIF_TEXT_CONNECTED, getString(R.string.notif_text_connected, nodeName))
        } else {
            null
        }
        val disconnectIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, RelaviaVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
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
        if (text != null) builder.setContentText(text)
        return builder.build()
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

        private const val CHANNEL_ID = "relavia-connection"
        private const val NOTIFICATION_ID = 1

        // Mirror of platform.DefaultTUNRequest (Go, app/platform/vpn.go).
        private const val TUN_IPV4_ADDR = "172.18.0.1"
        private const val TUN_IPV4_PREFIX = 30
        private const val TUN_DNS = "172.18.0.2"
        private const val TUN_MTU = 9000

        // i18n keys (app/locales packs) for every shell string.
        private const val KEY_NOTIF_CHANNEL = "android.notif_channel_name"
        private const val KEY_NOTIF_TITLE_CONNECTED = "android.notif_title_connected"
        private const val KEY_NOTIF_TITLE_CONNECTING = "android.notif_title_connecting"
        private const val KEY_NOTIF_TEXT_CONNECTED = "android.notif_text_connected"
        private const val KEY_NOTIF_ACTION_DISCONNECT = "android.notif_action_disconnect"
    }
}
