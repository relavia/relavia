package org.relavia.client

/**
 * The Kotlin <-> Go bridge surface (Step 10 architecture ruling,
 * docs/step10-Android客户端MVP.md).
 *
 * The native side of these functions is provided by the Go
 * runtime once it is bound into the APK (gomobile/libbox build).
 * That binding does not exist yet, so every entry point here is
 * wrapped defensively: a missing native side is caught and
 * reported as "not bound", and the shell degrades honestly
 * (bootstrap string resources, no tunnel) instead of crashing.
 *
 * Once the libbox AAR lands, the Go side implements:
 *  - localize(key): resolve a string from the trilingual packs
 *    in app/locales — the single source of truth for ALL shell
 *    text, including notifications (book 3.6, multilingual
 *    native). Keys used by the shell are the android.* keys.
 *  - onTunEstablished(fd): take ownership of the established
 *    TUN file descriptor and start the data plane.
 *  - onTunClosed(): the interface is gone; stop the data plane.
 */
object GoBridge {

    @JvmStatic
    private external fun localize(key: String): String?

    @JvmStatic
    private external fun onTunEstablished(fd: Int): Boolean

    @JvmStatic
    private external fun onTunClosed()

    /** True when the Go runtime answered at least once. */
    @Volatile
    var bound: Boolean = false
        private set

    /** Resolve [key] from the Go packs, or [fallback] when unbound. */
    fun text(key: String, fallback: String): String {
        return try {
            val v = localize(key)
            if (v != null) {
                bound = true
                v
            } else {
                fallback
            }
        } catch (e: UnsatisfiedLinkError) {
            fallback
        } catch (e: Exception) {
            fallback
        }
    }

    /** Hand the TUN fd to the Go data plane. False = not bound. */
    fun tunEstablished(fd: Int): Boolean {
        return try {
            val ok = onTunEstablished(fd)
            if (ok) bound = true
            ok
        } catch (e: UnsatisfiedLinkError) {
            false
        } catch (e: Exception) {
            false
        }
    }

    /** Tell the Go side the interface went away. Best effort. */
    fun tunClosed() {
        try {
            onTunClosed()
        } catch (e: UnsatisfiedLinkError) {
            // Not bound; nothing to stop.
        } catch (e: Exception) {
            // Best effort only; the fd close is authoritative.
        }
    }
}
