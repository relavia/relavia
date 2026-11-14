package org.relavia.client

import net.openvpn.ovpn3.ClientAPI_Config
import net.openvpn.ovpn3.ClientAPI_Event
import net.openvpn.ovpn3.ClientAPI_LogInfo
import net.openvpn.ovpn3.ClientAPI_OpenVPNClient
import net.openvpn.ovpn3.ClientAPI_ProvideCreds
import net.openvpn.ovpn3.DnsOptions
import org.relavia.libboxbind.Libboxbind

/**
 * The OpenVPN 3 session driver (docs/openvpn3安卓接线.md):
 * one [ClientAPI_OpenVPNClient] subclass — the core's client
 * object IS its own TunBuilder, so this single class receives
 * both the session events and the tunnel-construction
 * callbacks the server pushes.
 *
 * Threading: [runSession] blocks in the core's connect() on
 * the caller (the VPN service's worker thread). All callbacks
 * arrive on core threads. The TunBuilder accumulation state is
 * only touched from those callbacks, in core order.
 *
 * Credential hygiene: the profile text never carries the
 * password (Go's openvpn.RenderProfile guarantees it); the
 * credentials arrive as separate arguments and go straight
 * into ProvideCreds. Nothing here logs either.
 */
class Ovpn3Client(private val host: Ovpn3TunHost) : ClientAPI_OpenVPNClient() {

    /** Tunnel parameters accumulated from TunBuilder calls. */
    class TunSpec {
        var sessionName: String = "Relavia"
        var mtu: Int = 0
        var addresses = mutableListOf<String>() // "addr/prefix"
        var routes = mutableListOf<String>()    // "addr/prefix"
        var dnsServers = mutableListOf<String>()
        var rerouteIpv4: Boolean = false
        var rerouteIpv6: Boolean = false
        var remoteAddress: String = ""          // server address the core reports
        var remoteIpv6: Boolean = false
    }

    private val spec = TunSpec()

    @Volatile
    private var connected: Boolean = false

    fun isConnected(): Boolean = connected

    /**
     * Evaluate the profile, supply credentials, and connect.
     * Blocks until the session ends. Every outcome is reported
     * to Go through the event channel — including evaluation
     * failures, which never reach connect() but must still
     * complete the Go engine's pending start (as a fatal
     * PROFILE_ERROR event, classified config_rejected there).
     */
    fun runSession(profile: String, username: String, password: String) {
        val config = ClientAPI_Config()
        config.content = profile
        // Advertise and allow the non-AEAD data ciphers (the
        // CBC family) alongside the preferred AEAD ones. The
        // core's default (ConfigCommon in ovpncli.hpp) enables
        // only "preferred" algorithms — AES-GCM and
        // ChaCha20-Poly1305 — which also keeps CBC out of the
        // IV_CIPHERS line in our Peer Info. The public pool's
        // servers are SoftEther OpenVPN clones whose data
        // channel speaks only AES-128-CBC (it is what their
        // own exported profiles ask for, and what the official
        // client advertises first in IV_CIPHERS); a client
        // that does not advertise CBC can be left waiting for
        // a PUSH_REPLY that never comes. This switch is the
        // core's own documented compatibility knob, verified
        // on the loopback rig against a real SoftEther server
        // (docs/真机连接失败诊断-2026-11-14.md §8).
        config.enableNonPreferredDCAlgorithms = true
        val eval = eval_config(config)
        if (eval.error) {
            Libboxbind.notifyOvpn3Event("PROFILE_ERROR", eval.message ?: "profile rejected", true)
            return
        }
        if (username.isNotEmpty()) {
            val creds = ClientAPI_ProvideCreds()
            creds.username = username
            creds.password = password
            val st = provide_creds(creds)
            if (st.error) {
                Libboxbind.notifyOvpn3Event("PROFILE_ERROR", st.message ?: "credentials rejected", true)
                return
            }
        }
        val status = connect()
        if (!connected) {
            // The session ended without ever connecting. Leave
            // the core's transport byte counters in the service
            // log before anything else is torn down: they are
            // the cheapest discriminator the next diagnosis
            // gets — bytes_out == 0 means our packets never
            // left, bytes_in == 0 with bytes_out > 0 means the
            // server (or the path) never answered a single one.
            try {
                val stats = transport_stats()
                Libboxbind.notifyOvpn3Log(
                    "ovpn3 stats on failure: bytes_in=${stats.bytesIn} bytes_out=${stats.bytesOut}" +
                        " packets_in=${stats.packetsIn} packets_out=${stats.packetsOut}",
                )
            } catch (e: Exception) {
                Libboxbind.notifyOvpn3Log("ovpn3 stats on failure: unavailable (${e.message})")
            }
        }
        if (status.error && !connected) {
            // connect() returning an error before CONNECTED:
            // surface it as a fatal event so the pending Go
            // start resolves with the core's own words.
            Libboxbind.notifyOvpn3Event("CONNECTION_FAILED", status.message ?: "connect failed", true)
        }
    }

    // --- core event / log callbacks --------------------------

    override fun event(e: ClientAPI_Event) {
        if (e.name == "CONNECTED") {
            connected = true
        }
        if (e.name == "DISCONNECTED") {
            connected = false
        }
        Libboxbind.notifyOvpn3Event(e.name ?: "", e.info ?: "", e.fatal)
        host.onOvpn3Event(e.name ?: "")
    }

    override fun log(info: ClientAPI_LogInfo) {
        val text = info.text ?: return
        if (text.isNotBlank()) {
            Libboxbind.notifyOvpn3Log(text.trim())
        }
    }

    // --- socket protection -----------------------------------

    /**
     * The core's outbound sockets must bypass the tunnel it is
     * building, or the session loops into itself. Android's
     * answer is VpnService.protect, served by the host service.
     */
    override fun socket_protect(socket: Int, remote: String, ipv6: Boolean): Boolean {
        return host.protectOvpn3Socket(socket)
    }

    // --- TunBuilder callbacks ---------------------------------

    override fun tun_builder_new(): Boolean = true

    override fun tun_builder_set_remote_address(address: String, ipv6: Boolean): Boolean {
        // TunProp::configure_builder calls this unconditionally
        // once the server address is known and treats a false
        // return as fatal (tun_prop_error, TUN_SETUP_FAILED).
        // TunBuilderBase's default returns false, so without
        // this override every session that survived the
        // handshake died here — found on the loopback rig
        // against a real SoftEther server, where the core
        // logged "Session is ACTIVE", processed the push, and
        // then failed with "tun_builder_set_remote_address
        // failed" (docs/真机连接失败诊断-2026-11-14.md §8).
        // The address is recorded for the host; no route work
        // is needed for the transport itself, whose sockets
        // are already kept out of the tunnel by socket_protect
        // (VpnService.protect).
        spec.remoteAddress = address
        spec.remoteIpv6 = ipv6
        return true
    }

    override fun tun_builder_set_session_name(name: String): Boolean {
        spec.sessionName = name
        return true
    }

    override fun tun_builder_set_mtu(mtu: Int): Boolean {
        spec.mtu = mtu
        return true
    }

    override fun tun_builder_add_address(
        address: String,
        prefix_length: Int,
        gateway: String,
        ipv6: Boolean,
        net30: Boolean,
    ): Boolean {
        spec.addresses.add("$address/$prefix_length")
        return true
    }

    override fun tun_builder_add_route(
        address: String,
        prefix_length: Int,
        metric: Int,
        ipv6: Boolean,
    ): Boolean {
        spec.routes.add("$address/$prefix_length")
        return true
    }

    override fun tun_builder_exclude_route(
        address: String,
        prefix_length: Int,
        metric: Int,
        ipv6: Boolean,
    ): Boolean {
        // VpnService.Builder has no exclude-route before
        // API 33, and the Go side's default policy asks the
        // core for include routes on Android (route emulation
        // is a core-side Config option). Accepting and not
        // applying an exclusion we cannot express would be a
        // silent downgrade; refuse so the core falls back.
        return false
    }

    override fun tun_builder_reroute_gw(ipv4: Boolean, ipv6: Boolean, flags: Long): Boolean {
        spec.rerouteIpv4 = ipv4
        spec.rerouteIpv6 = ipv6
        return true
    }

    override fun tun_builder_set_dns_options(dns: DnsOptions): Boolean {
        try {
            val servers = dns.servers
            for ((_, server) in servers) {
                val addrs = server.addresses ?: continue
                for (i in 0 until addrs.size) {
                    addrs[i].address?.let { spec.dnsServers.add(it) }
                }
            }
        } catch (e: Exception) {
            // A DNS shape we cannot read must not kill the
            // tunnel; the session runs with the system DNS
            // posture the profile asked for minus this option.
            Libboxbind.notifyOvpn3Log("ovpn3: dns options unreadable: ${e.message}")
        }
        return true
    }

    override fun tun_builder_establish(): Int {
        return host.establishOvpn3Tun(spec)
    }

    override fun tun_builder_persist(): Boolean = false

    override fun tun_builder_teardown(disconnect: Boolean) {
        host.closeOvpn3Tun()
    }
}

/**
 * What [Ovpn3Client] needs from the hosting VpnService —
 * implemented by [RelaviaVpnService], which owns the platform
 * objects (Builder, protect, the interface PFD).
 */
interface Ovpn3TunHost {
    /** Build the interface from the accumulated spec; return its raw fd, or -1 on failure. */
    fun establishOvpn3Tun(spec: Ovpn3Client.TunSpec): Int

    /** Close the ovpn3-established interface, if any. Idempotent. */
    fun closeOvpn3Tun()

    /** VpnService.protect(fd) for the core's own sockets. */
    fun protectOvpn3Socket(fd: Int): Boolean

    /** Session event mirror (notification state, service self-stop decisions). */
    fun onOvpn3Event(name: String)
}
