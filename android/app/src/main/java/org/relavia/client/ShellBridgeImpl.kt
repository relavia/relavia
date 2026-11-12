package org.relavia.client

import android.annotation.SuppressLint
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.relavia.libboxbind.Libboxbind
import org.relavia.libboxbind.ShellBridge
import org.relavia.libboxbind.TunParams

/**
 * Go runtime bootstrap: first call from any shell entry point
 * records the storage paths with libbox and registers
 * [ShellBridgeImpl] as the platform bridge. Idempotent and
 * fully defensive — in an unbound (pure-Kotlin) build it
 * silently leaves the shell in its degraded mode.
 */
object ShellRuntime {

    @Volatile
    private var started: Boolean = false

    fun ensureStarted(context: Context) {
        if (started) return
        synchronized(this) {
            if (started) return
            ShellBridgeImpl.appContext = context.applicationContext
            try {
                val base = context.filesDir.absolutePath
                val working = File(context.filesDir, "libbox").absolutePath
                Libboxbind.setup(base, working, context.cacheDir.absolutePath)
                Libboxbind.registerShellBridge(ShellBridgeImpl)
                GoBridge.markBound()
                started = true
            } catch (e: UnsatisfiedLinkError) {
                // Unbound build: stay unstarted (honest degraded mode).
            } catch (e: NoClassDefFoundError) {
                // Unbound build: stay unstarted.
            } catch (e: Exception) {
                // Setup failed; a later entry point retries.
            }
        }
    }
}

/**
 * The Kotlin implementation of the Go ShellBridge interface
 * (libbox binding): every platform capability the Go data
 * plane needs, served by the shell.
 *
 * Concurrency contract: methods are called from Go goroutines
 * (gomobile threads), never from the Android main thread;
 * waits are bounded so a stuck shell cannot wedge the data
 * plane. DEADLOCK RULE: bridge methods must not call facade
 * entries that touch session state (startSession/stopSession/
 * setup) — a bridge call can run while Go holds the session
 * lock for an in-flight connect, and a re-entrant call would
 * block behind it until the connect times out. Two safe
 * exceptions: Libboxbind.localize (lock-free — it reads an
 * atomic translator pointer on the Go side, used for
 * notification text), and the default-network callback below,
 * which is invoked by the SYSTEM (never from inside a bridge
 * call) and only forwards a fire-and-forget notification.
 */
object ShellBridgeImpl : ShellBridge {

    @Volatile
    var appContext: Context? = null

    @Volatile
    private var service: RelaviaVpnService? = null

    @Volatile
    private var serviceLatch: CountDownLatch = CountDownLatch(1)

    // --- service registry (called by RelaviaVpnService) ------

    fun onServiceReady(svc: RelaviaVpnService) {
        service = svc
        serviceLatch.countDown()
    }

    fun onServiceGone(svc: RelaviaVpnService) {
        if (service === svc) {
            service = null
            serviceLatch = CountDownLatch(1)
        }
    }

    private fun awaitService(timeoutSeconds: Long): RelaviaVpnService? {
        service?.let { return it }
        val ctx = appContext ?: return null
        try {
            ContextCompat.startForegroundService(
                ctx,
                Intent(ctx, RelaviaVpnService::class.java).setAction(RelaviaVpnService.ACTION_START),
            )
        } catch (e: Exception) {
            return null
        }
        serviceLatch.await(timeoutSeconds, TimeUnit.SECONDS)
        return service
    }

    // --- consent ----------------------------------------------

    @Volatile
    private var consentLatch: CountDownLatch? = null

    @Volatile
    private var consentGranted: Boolean = false

    /** MainActivity reports the consent dialog outcome here. */
    fun onConsentResult(granted: Boolean) {
        consentGranted = granted
        consentLatch?.countDown()
    }

    override fun prepare(): Boolean {
        val ctx = appContext ?: return false
        if (VpnService.prepare(ctx) == null) return true
        // Consent is missing: route the system dialog through
        // MainActivity (only an Activity can show it) and wait,
        // bounded. From a background state Android may refuse
        // the activity start; that surfaces as false (refused),
        // which the Go side maps to its typed permission error.
        val latch = CountDownLatch(1)
        consentLatch = latch
        consentGranted = false
        val intent = Intent(ctx, MainActivity::class.java)
            .setAction(MainActivity.ACTION_CONSENT)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            ctx.startActivity(intent)
        } catch (e: Exception) {
            return false
        }
        val completed = latch.await(CONSENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        return completed && consentGranted && VpnService.prepare(ctx) == null
    }

    // --- TUN establishment --------------------------------------

    override fun establishTun(params: TunParams): Int {
        val svc = awaitService(SERVICE_TIMEOUT_SECONDS)
            ?: throw IllegalStateException("vpn service did not start")
        return svc.establishFromBridge(params)
    }

    override fun closeTun() {
        service?.closeTunFromBridge()
    }

    override fun protectSocket(fd: Int): Boolean {
        // THE anti-loop call: VpnService.protect exempts the
        // box's outbound sockets from the VPN. Without a live
        // service there is nothing to protect with — report
        // refusal so the dial fails instead of looping.
        val svc = service ?: return false
        return try {
            svc.protect(fd)
        } catch (e: Exception) {
            false
        }
    }

    override fun teardown() {
        val svc = service
        if (svc != null) {
            svc.teardownFromBridge()
        } else {
            // Service already gone; make sure it stays gone.
            val ctx = appContext ?: return
            try {
                ctx.stopService(Intent(ctx, RelaviaVpnService::class.java))
            } catch (e: Exception) {
                // Already stopped.
            }
        }
    }

    // --- connection owner ---------------------------------------

    override fun connectionOwnerUid(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        val ctx = appContext ?: return -1
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return -1
        return try {
            cm.getConnectionOwnerUid(
                ipProtocol,
                InetSocketAddress(sourceAddress, sourcePort),
                InetSocketAddress(destinationAddress, destinationPort),
            )
        } catch (e: Exception) {
            -1
        }
    }

    override fun packagesForUid(uid: Int): String {
        val ctx = appContext ?: return ""
        return try {
            ctx.packageManager.getPackagesForUid(uid)?.joinToString(",") ?: ""
        } catch (e: Exception) {
            ""
        }
    }

    // --- default interface monitor -------------------------------

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private val monitorLock = Any()

    override fun startInterfaceMonitor() {
        val ctx = appContext ?: throw IllegalStateException("no app context")
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
            ?: throw IllegalStateException("no connectivity manager")
        synchronized(monitorLock) {
            if (networkCallback != null) return
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = reportDefault(cm, network)
                override fun onLost(network: Network) {
                    forwardDefaultInterface("", -1, expensive = false, constrained = false)
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    reportDefault(cm, network)

                override fun onLinkPropertiesChanged(
                    network: Network,
                    properties: android.net.LinkProperties,
                ) = reportDefault(cm, network)
            }
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        }
    }

    override fun stopInterfaceMonitor() {
        val ctx = appContext ?: return
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return
        synchronized(monitorLock) {
            val callback = networkCallback ?: return
            networkCallback = null
            try {
                cm.unregisterNetworkCallback(callback)
            } catch (e: Exception) {
                // Already unregistered.
            }
        }
    }

    private fun reportDefault(cm: ConnectivityManager, network: Network) {
        val name = try {
            cm.getLinkProperties(network)?.interfaceName
        } catch (e: Exception) {
            null
        }
        val index = if (name != null) {
            try {
                java.net.NetworkInterface.getByName(name)?.index ?: -1
            } catch (e: Exception) {
                -1
            }
        } else {
            -1
        }
        val caps = try {
            cm.getNetworkCapabilities(network)
        } catch (e: Exception) {
            null
        }
        // Mapping mirrors upstream platform practice:
        // metered connection = expensive; loss of the
        // NOT_CONGESTED capability = constrained.
        val expensive = caps != null &&
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val constrained = caps != null &&
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED)
        forwardDefaultInterface(name ?: "", index, expensive, constrained)
    }

    private fun forwardDefaultInterface(name: String, index: Int, expensive: Boolean, constrained: Boolean) {
        try {
            Libboxbind.notifyDefaultInterface(name, index, expensive, constrained)
        } catch (e: UnsatisfiedLinkError) {
            // Unbound build.
        } catch (e: NoClassDefFoundError) {
            // Unbound build.
        } catch (e: Exception) {
            // Fire-and-forget: a missed update self-heals on the next event.
        }
    }

    // --- Wi-Fi -----------------------------------------------------

    @SuppressLint("MissingPermission")
    override fun wifiState(): String {
        // The shell deliberately does NOT hold ACCESS_WIFI_STATE
        // or location permissions (the manifest permission set is
        // frozen at five), so on current Android this returns ""
        // (libbox: no state) and SSID-based rules simply never
        // match. Implemented for real so a future permission
        // decision makes it work without a bridge change.
        val ctx = appContext ?: return ""
        return try {
            val wm = ctx.applicationContext.getSystemService(WifiManager::class.java) ?: return ""
            @Suppress("DEPRECATION")
            val info = wm.connectionInfo ?: return ""
            val ssid = info.ssid?.trim('"') ?: return ""
            if (ssid.isEmpty() || ssid == "<unknown ssid>") return ""
            ssid + "\n" + (info.bssid ?: "")
        } catch (e: Exception) {
            ""
        }
    }

    // --- notifications ------------------------------------------------

    override fun postNotification(identifier: String, title: String, body: String) {
        val ctx = appContext ?: throw IllegalStateException("no app context")
        RelaviaVpnService.ensureChannel(ctx)
        val notification = NotificationCompat.Builder(ctx, RelaviaVpnService.CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setOnlyAlertOnce(true)
            .build()
        val nm = ctx.getSystemService(NotificationManager::class.java)
            ?: throw IllegalStateException("no notification manager")
        nm.notify(notificationIdFor(identifier), notification)
    }

    override fun cancelNotification(identifier: String) {
        val ctx = appContext ?: return
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        nm.cancel(notificationIdFor(identifier))
    }

    private fun notificationIdFor(identifier: String): Int {
        // Keep clear of the service's own NOTIFICATION_ID (1).
        return 100 + (identifier.hashCode() and 0x3fffffff) % 10000
    }

    private const val SERVICE_TIMEOUT_SECONDS = 15L
    private const val CONSENT_TIMEOUT_SECONDS = 120L
}
