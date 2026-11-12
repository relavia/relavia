package org.relavia.client

import org.relavia.libboxbind.Libboxbind

/**
 * The Kotlin <-> Go bridge surface (libbox binding;
 * docs/libbox绑定.md).
 *
 * Step 10 shipped this file with hand-declared JNI `external
 * fun`s that no build could satisfy yet — an honest placeholder
 * that always answered "not bound". The gomobile AAR now
 * provides the real surface: the generated facade
 * [org.relavia.libboxbind.Libboxbind] (bound from the Go
 * package openproxy/app/libboxbind). This object is a defensive
 * wrapper over that facade:
 *
 *  - In the merged release APK the facade is present and every
 *    call reaches Go; [bound] flips true on first contact.
 *  - In a pure-Kotlin build WITHOUT the AAR (the shell can
 *    still be compiled alone for shell-only work), the facade
 *    class is absent: calls fail with linkage errors, which are
 *    caught here and reported as "not bound" — the shell then
 *    degrades to bootstrap resources and refuses to start a
 *    tunnel rather than blackholing traffic. That build is a
 *    development variant, never a release artifact (CI builds
 *    the shell only after the AAR exists).
 *
 * The call direction inverted versus the Step 10 placeholder:
 * the shell no longer hands a self-established fd "up" to Go.
 * Go's session drives the choreography and calls DOWN into the
 * shell through the ShellBridge interface (see
 * [ShellBridgeImpl]) whenever it needs the platform: consent,
 * TUN establishment, protect(), notifications.
 */
object GoBridge {

    /** True when the Go runtime answered at least once. */
    @Volatile
    var bound: Boolean = false
        private set

    fun markBound() {
        bound = true
    }

    /** Resolve [key] from the Go packs, or [fallback] when unbound/unknown. */
    fun text(key: String, fallback: String): String {
        return try {
            val v = Libboxbind.localize(key)
            if (!v.isNullOrEmpty()) {
                bound = true
                v
            } else {
                fallback
            }
        } catch (e: UnsatisfiedLinkError) {
            fallback
        } catch (e: NoClassDefFoundError) {
            fallback
        } catch (e: Exception) {
            fallback
        }
    }

    /**
     * Start the Go app session (connect the selected node).
     * Blocking — consent waits, interface establishment and the
     * box start all happen inside; call off the UI thread.
     * False = unbound or the session failed (see [sessionStatus]).
     */
    fun sessionStart(): Boolean {
        return try {
            Libboxbind.startSession()
            bound = true
            true
        } catch (e: UnsatisfiedLinkError) {
            false
        } catch (e: NoClassDefFoundError) {
            false
        } catch (e: Exception) {
            // A thrown start still proves the binding exists.
            bound = true
            false
        }
    }

    /** Stop the Go app session (choreographed disconnect). Blocking. */
    fun sessionStop() {
        try {
            Libboxbind.stopSession()
            bound = true
        } catch (e: UnsatisfiedLinkError) {
            // Not bound; nothing to stop.
        } catch (e: NoClassDefFoundError) {
            // Not bound; nothing to stop.
        } catch (e: Exception) {
            // Best effort; local teardown in the service is authoritative.
        }
    }

    /** "connected" / "error: ..." / "idle" / "unbound". */
    fun sessionStatus(): String {
        return try {
            Libboxbind.sessionStatus() ?: "unbound"
        } catch (e: UnsatisfiedLinkError) {
            "unbound"
        } catch (e: NoClassDefFoundError) {
            "unbound"
        } catch (e: Exception) {
            "unbound"
        }
    }

    /** Tell Go the system revoked the VPN interface. Best effort. */
    fun notifyTunRevoked() {
        try {
            Libboxbind.notifyTunRevoked()
        } catch (e: UnsatisfiedLinkError) {
            // Not bound; nothing to notify.
        } catch (e: NoClassDefFoundError) {
            // Not bound; nothing to notify.
        } catch (e: Exception) {
            // Best effort only; the local teardown is authoritative.
        }
    }
}
