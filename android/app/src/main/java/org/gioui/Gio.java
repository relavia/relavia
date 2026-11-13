// SPDX-License-Identifier: Unlicense OR MIT
//
// Vendored into the Relavia shell from gioui.org v0.10.3
// (app/Gio.java of the Go module — the same three files gogio
// copies into the projects it generates), so the Gradle build
// can host the product Gio UI in the merged APK
// (docs/android产品界面接入.md §2). Relavia patch, marked
// inline below: the native library loaded is the gomobile
// library "gojni" (the single Go runtime of the merged APK,
// which also carries Gio's JNI exports), not a gogio-built
// "gio" library. Everything else is byte-identical to
// upstream v0.10.3; re-vendor on a Gio version bump.

package org.gioui;

import android.content.ClipboardManager;
import android.content.ClipData;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.io.UnsupportedEncodingException;

public final class Gio {
	private static final Object initLock = new Object();
	private static boolean jniLoaded;
	private static final Handler handler = new Handler(Looper.getMainLooper());

	/**
	 * init loads and initializes the Go native library and runs
	 * the Go main function.
	 *
	 * It is exported for use by Android apps that need to run Go code
	 * outside the lifecycle of the Gio activity.
	 */
	public static synchronized void init(Context appCtx) {
		synchronized (initLock) {
			if (jniLoaded) {
				return;
			}
			String dataDir = appCtx.getFilesDir().getAbsolutePath();
			byte[] dataDirUTF8;
			try {
				dataDirUTF8 = dataDir.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
			// Relavia patch: single-runtime library (see file header).
			System.loadLibrary("gojni");
			runGoMain(dataDirUTF8, appCtx);
			jniLoaded = true;
		}
	}

	static private native void runGoMain(byte[] dataDir, Context context);

	static void writeClipboard(Context ctx, String s) {
		ClipboardManager m = (ClipboardManager)ctx.getSystemService(Context.CLIPBOARD_SERVICE);
		m.setPrimaryClip(ClipData.newPlainText(null, s));
	}

	static String readClipboard(Context ctx) {
		ClipboardManager m = (ClipboardManager)ctx.getSystemService(Context.CLIPBOARD_SERVICE);
		ClipData c = m.getPrimaryClip();
		if (c == null || c.getItemCount() < 1) {
			return null;
		}
		return c.getItemAt(0).coerceToText(ctx).toString();
	}

	static void wakeupMainThread() {
		handler.post(new Runnable() {
			@Override public void run() {
				scheduleMainFuncs();
			}
		});
	}

	static private native void scheduleMainFuncs();
}
