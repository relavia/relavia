import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import net.openvpn.ovpn3.ClientAPI_Config;
import net.openvpn.ovpn3.ClientAPI_ConnectionInfo;
import net.openvpn.ovpn3.ClientAPI_EvalConfig;
import net.openvpn.ovpn3.ClientAPI_Event;
import net.openvpn.ovpn3.ClientAPI_LogInfo;
import net.openvpn.ovpn3.ClientAPI_OpenVPNClient;
import net.openvpn.ovpn3.ClientAPI_Status;
import net.openvpn.ovpn3.ClientAPI_TransportStats;
import net.openvpn.ovpn3.DnsOptions;

/**
 * Loopback handshake rig driver for the production OpenVPN 3
 * core (docs/真机连接失败诊断-2026-11-14.md §8): the JVM twin
 * of the Android Ovpn3Client. It drives the same SWIG core
 * the APK ships (same pinned source, same build glue in
 * android/openvpn3/CMakeLists.txt, host variant per
 * docs/openvpn3构建尖峰.md) with a profile rendered by the
 * production Go path (core/openvpn/rigprofile), against a
 * real server on loopback, and reports how far the control
 * channel got in machine-checkable RIG_* lines.
 *
 * The TunBuilder surface mirrors Ovpn3Client.kt override for
 * override — including its refusals (exclude_route returns
 * false, persist returns false) — with platform pieces
 * replaced by loopback equivalents: socket_protect approves
 * (there is no tunnel to loop into on the rig), and
 * tun_builder_establish returns the fd of one end of a
 * Unix-domain socket pair whose peer is drained by a thread,
 * so reads block and writes never stall: a stand-in TUN that
 * lets the session reach (and hold) CONNECTED without a
 * kernel device. A Unix-domain pair is used rather than a
 * loopback TCP pair because sandboxed CI networks may
 * transparently intercept outbound TCP — loopback included —
 * which silently strands a TCP pair's accept(); a Unix-domain
 * socket is local by construction.
 *
 * Assertion endpoint (by design, see the rig README in
 * run-rig.sh): control-channel completion — TLS handshake
 * finished, the server answered the control channel
 * (Session ACTIVE / PUSH_REPLY processed), the CONNECTED
 * event fired, and the negotiated data cipher matches the
 * profile (cross-checked against the server's own log by
 * the orchestrating script). Payload traffic through a real
 * TUN device is explicitly out of scope here, as it is in
 * the desktop process-adapter rig.
 */
public class Ovpn3LoopbackRig extends ClientAPI_OpenVPNClient {

    private final List<String> events = Collections.synchronizedList(new ArrayList<>());
    private final List<String> logs = Collections.synchronizedList(new ArrayList<>());
    private final CountDownLatch connectedLatch = new CountDownLatch(1);
    private final CountDownLatch disconnectedLatch = new CountDownLatch(1);
    private volatile boolean connected = false;
    private volatile String fatalInfo = "";

    // Accumulated tunnel spec (core order, like production).
    private final List<String> addresses = new ArrayList<>();
    private final List<String> routes = new ArrayList<>();
    private volatile int mtu = 0;
    private volatile String remoteAddress = "";

    // Fake TUN plumbing (kept referenced so nothing GCs shut).
    private ServerSocketChannel fakeTunListener;
    private SocketChannel fakeTunCoreSide;
    private SocketChannel fakeTunDrainSide;
    private Path fakeTunPath;

    // --- session events / logs --------------------------------

    @Override
    public void event(ClientAPI_Event e) {
        String name = e.getName() == null ? "" : e.getName();
        String info = e.getInfo() == null ? "" : e.getInfo();
        events.add(name + " fatal=" + e.getFatal() + " info=" + info);
        if ("CONNECTED".equals(name)) {
            connected = true;
            connectedLatch.countDown();
        }
        if ("DISCONNECTED".equals(name)) {
            disconnectedLatch.countDown();
        }
        if (e.getFatal() && fatalInfo.isEmpty()) {
            fatalInfo = name + ": " + info;
        }
    }

    @Override
    public void log(ClientAPI_LogInfo info) {
        String text = info.getText();
        if (text != null && !text.isBlank()) {
            logs.add(text.strip());
        }
    }

    // --- socket protection -------------------------------------

    @Override
    public boolean socket_protect(int socket, String remote, boolean ipv6) {
        // No platform VPN service exists on the rig; the core's
        // sockets cannot loop into a tunnel that does not exist.
        return true;
    }

    // --- TunBuilder (mirrors Ovpn3Client.kt) -------------------

    @Override
    public boolean tun_builder_new() {
        return true;
    }

    @Override
    public boolean tun_builder_set_remote_address(String address, boolean ipv6) {
        // TunProp::configure_builder calls this unconditionally
        // and treats a false return as fatal (tun_prop_error).
        // TunBuilderBase's default returns false, so a client
        // that does not override it — as the production
        // Ovpn3Client.kt originally did not — can never finish
        // TUN setup. Recorded here; the rig has no routes to
        // exclude the server from.
        remoteAddress = address;
        return true;
    }

    @Override
    public boolean tun_builder_set_session_name(String name) {
        return true;
    }

    @Override
    public boolean tun_builder_set_mtu(int mtu) {
        this.mtu = mtu;
        return true;
    }

    @Override
    public boolean tun_builder_add_address(String address, int prefixLength,
                                           String gateway, boolean ipv6, boolean net30) {
        addresses.add(address + "/" + prefixLength);
        return true;
    }

    @Override
    public boolean tun_builder_add_route(String address, int prefixLength,
                                         int metric, boolean ipv6) {
        routes.add(address + "/" + prefixLength);
        return true;
    }

    @Override
    public boolean tun_builder_exclude_route(String address, int prefixLength,
                                             int metric, boolean ipv6) {
        return false; // production parity (Ovpn3Client.kt)
    }

    @Override
    public boolean tun_builder_reroute_gw(boolean ipv4, boolean ipv6, long flags) {
        return true;
    }

    @Override
    public boolean tun_builder_set_dns_options(DnsOptions dns) {
        return true;
    }

    @Override
    public boolean tun_builder_persist() {
        return false; // production parity
    }

    @Override
    public void tun_builder_teardown(boolean disconnect) {
        closeFakeTun();
    }

    @Override
    public int tun_builder_establish() {
        try {
            fakeTunPath = Files.createTempFile("relavia-rig-tun", ".sock");
            Files.delete(fakeTunPath); // the channel bind needs a free path
            UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(fakeTunPath);
            fakeTunListener = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            fakeTunListener.bind(addr);
            fakeTunCoreSide = SocketChannel.open(StandardProtocolFamily.UNIX);
            fakeTunCoreSide.connect(addr);
            fakeTunDrainSide = fakeTunListener.accept();
            fakeTunListener.close();
            Thread drainer = new Thread(() -> {
                try {
                    ByteBuffer buf = ByteBuffer.allocate(65536);
                    while (fakeTunDrainSide.read(buf) >= 0) {
                        buf.clear(); // discard: the stand-in TUN sinks everything
                    }
                } catch (Exception ignored) {
                }
            });
            drainer.setDaemon(true);
            drainer.start();
            return extractFd(fakeTunCoreSide);
        } catch (Exception ex) {
            logs.add("rig: tun_builder_establish failed: " + ex);
            return -1;
        }
    }

    private void closeFakeTun() {
        for (java.io.Closeable c : new java.io.Closeable[]{fakeTunCoreSide, fakeTunDrainSide, fakeTunListener}) {
            try {
                if (c != null) {
                    c.close();
                }
            } catch (Exception ignored) {
            }
        }
        try {
            if (fakeTunPath != null) {
                Files.deleteIfExists(fakeTunPath);
            }
        } catch (Exception ignored) {
        }
    }

    /** Reflective fd extraction (test harness only; the JVM is
     *  launched with the matching --add-opens flags). */
    private static int extractFd(SocketChannel channel) throws Exception {
        Field fdField = channel.getClass().getDeclaredField("fd");
        fdField.setAccessible(true);
        FileDescriptor fd = (FileDescriptor) fdField.get(channel);
        Field fdInt = FileDescriptor.class.getDeclaredField("fd");
        fdInt.setAccessible(true);
        return fdInt.getInt(fd);
    }

    // --- driver -------------------------------------------------

    private static String argValue(String[] args, String name) {
        for (int i = 0; i + 1 < args.length; i++) {
            if (args[i].equals(name)) {
                return args[i + 1];
            }
        }
        return null;
    }

    private boolean eventSeen(String name) {
        synchronized (events) {
            for (String e : events) {
                if (e.startsWith(name + " ")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** First log line containing the prefix, value after it ("" when absent). */
    private String logValue(String prefix) {
        synchronized (logs) {
            for (String line : logs) {
                int at = line.indexOf(prefix);
                if (at >= 0) {
                    return line.substring(at + prefix.length()).trim();
                }
            }
        }
        return "";
    }

    private boolean logContains(String needle) {
        synchronized (logs) {
            for (String line : logs) {
                if (line.contains(needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        String lib = argValue(args, "--library");
        String profilePath = argValue(args, "--profile");
        String timeoutArg = argValue(args, "--timeout");
        // Production parity: Ovpn3Client.runSession enables
        // non-preferred DC algorithms, so the rig does too by
        // default; --aead-only-peer-info 1 reproduces the
        // pre-fix advertisement (AEAD-only IV_CIPHERS) for the
        // bisect record.
        boolean nonPreferredDC = !"1".equals(argValue(args, "--aead-only-peer-info"));
        if (lib == null || profilePath == null) {
            System.err.println("usage: Ovpn3LoopbackRig --library <libovpn3android.so> --profile <profile.ovpn> [--timeout <sec>] [--aead-only-peer-info 1]");
            System.exit(2);
        }
        int timeoutSec = timeoutArg == null ? 45 : Integer.parseInt(timeoutArg);

        System.load(Path.of(lib).toAbsolutePath().toString());
        String profile = Files.readString(Path.of(profilePath), StandardCharsets.UTF_8);

        Ovpn3LoopbackRig rig = new Ovpn3LoopbackRig();

        ClientAPI_Config config = new ClientAPI_Config();
        config.setContent(profile);
        if (nonPreferredDC) {
            // ClientAPI_Config inherits ConfigCommon's
            // enableNonPreferredDCAlgorithms (ovpncli.hpp):
            // with it false the core enables only AEAD data
            // ciphers and advertises IV_CIPHERS without CBC;
            // with it true the CBC family is enabled and
            // advertised first. Production enables it (see
            // Ovpn3Client.runSession); the rig mirrors that.
            config.setEnableNonPreferredDCAlgorithms(true);
        }
        ClientAPI_EvalConfig eval = rig.eval_config(config);
        if (eval.getError()) {
            System.out.println("RIG_EVAL_ERROR=" + eval.getMessage());
            System.out.println("RIG_RESULT=FAIL reason=profile_rejected_by_core");
            System.exit(1);
        }
        System.out.println("RIG_EVAL_OK=1");

        Thread worker = new Thread(() -> {
            ClientAPI_Status status = rig.connect();
            if (status.getError() && !rig.connected) {
                rig.events.add("CONNECT_RETURNED_ERROR fatal=true info=" + status.getMessage());
                if (rig.fatalInfo.isEmpty()) {
                    rig.fatalInfo = "connect(): " + status.getMessage();
                }
                rig.disconnectedLatch.countDown();
            }
        });
        worker.setDaemon(true);
        worker.start();

        boolean gotConnected = rig.connectedLatch.await(timeoutSec, TimeUnit.SECONDS);
        // Core 3.12 logs "TLS Handshake: peer certificate: ...";
        // 3.11-era cores log "SSL Handshake: ...". Match both.
        boolean tlsDone = rig.logContains("Handshake: peer certificate");
        boolean sessionActive = rig.logContains("Session is ACTIVE");
        // The core does not echo the PUSH_REPLY text to its log;
        // its processing is observable as the GET_CONFIG /
        // ASSIGN_IP events and the TunBuilder address calls.
        boolean pushSeen = gotConnected
                || rig.eventSeen("GET_CONFIG")
                || rig.eventSeen("ASSIGN_IP")
                || !rig.addresses.isEmpty();

        String vpnIp4 = "";
        String serverIp = "";
        if (gotConnected) {
            try {
                ClientAPI_ConnectionInfo ci = rig.connection_info();
                vpnIp4 = ci.getVpnIp4() == null ? "" : ci.getVpnIp4();
                serverIp = ci.getServerIp() == null ? "" : ci.getServerIp();
            } catch (Exception ignored) {
            }
        }
        long bytesIn = -1;
        long bytesOut = -1;
        try {
            ClientAPI_TransportStats stats = rig.transport_stats();
            bytesIn = stats.getBytesIn();
            bytesOut = stats.getBytesOut();
        } catch (Exception ignored) {
        }

        System.out.println("RIG_IV_CIPHERS=" + rig.logValue("IV_CIPHERS="));
        System.out.println("RIG_TLS_HANDSHAKE=" + (tlsDone ? 1 : 0));
        System.out.println("RIG_SESSION_ACTIVE=" + (sessionActive ? 1 : 0));
        System.out.println("RIG_PUSH_REPLY=" + (pushSeen ? 1 : 0));
        System.out.println("RIG_CONNECTED=" + (gotConnected ? 1 : 0));
        System.out.println("RIG_VPN_IP4=" + vpnIp4);
        System.out.println("RIG_SERVER_IP=" + serverIp);
        System.out.println("RIG_REMOTE_ADDRESS=" + rig.remoteAddress);
        System.out.println("RIG_TUN_ADDRESSES=" + String.join(",", rig.addresses));
        System.out.println("RIG_TUN_ROUTES=" + String.join(",", rig.routes));
        System.out.println("RIG_TUN_MTU=" + rig.mtu);
        System.out.println("RIG_BYTES_IN=" + bytesIn);
        System.out.println("RIG_BYTES_OUT=" + bytesOut);
        System.out.println("RIG_FATAL=" + rig.fatalInfo);
        System.out.println("--- core events ---");
        synchronized (rig.events) {
            for (String e : rig.events) {
                System.out.println("EVENT " + e);
            }
        }
        System.out.println("--- core log ---");
        synchronized (rig.logs) {
            for (String line : rig.logs) {
                System.out.println("LOG " + line);
            }
        }

        boolean controlChannelComplete = tlsDone && sessionActive && pushSeen;
        boolean pass = controlChannelComplete && gotConnected;
        System.out.println("RIG_CONTROL_CHANNEL=" + (controlChannelComplete ? 1 : 0));
        System.out.println("RIG_RESULT=" + (pass ? "PASS" : "FAIL"));

        try {
            rig.stop();
        } catch (Exception ignored) {
        }
        rig.disconnectedLatch.await(5, TimeUnit.SECONDS);
        System.exit(pass ? 0 : 1);
    }
}
