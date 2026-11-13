// SPDX-License-Identifier: Unlicense OR MIT
//
// Vendored into the Relavia shell from gioui.org v0.10.3
// (app/GioActivity.java of the Go module), so the Gradle
// build can host the product Gio UI in the merged APK
// (docs/android产品界面接入.md §2). Relavia patch, marked
// inline below: onCreate also requests the POST_NOTIFICATIONS
// runtime permission — the retired shell Activity used to own
// that request, and this Activity is the product's only
// launcher surface now. Everything else is byte-identical to
// upstream v0.10.3; re-vendor on a Gio version bump.

package org.gioui;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.view.ViewGroup;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

public final class GioActivity extends Activity {
	private GioView view;
	public FrameLayout layer;

	@Override public void onCreate(Bundle state) {
            super.onCreate(state);

            layer = new FrameLayout(this);
            view = new GioView(this);

            view.setLayoutParams(new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            ));
            view.setFocusable(true);
            view.setFocusableInTouchMode(true);

            layer.addView(view);
            setContentView(layer);
            onNewIntent(this.getIntent());

            // Relavia patch: POST_NOTIFICATIONS runtime request
            // (API 33+), previously owned by the retired shell
            // Activity. Without it the VPN foreground-service
            // notification and kernel notifications are hidden
            // by the system; the tunnel itself is unaffected.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 1002);
            }
	}

	@Override public void onDestroy() {
		view.destroy();
		super.onDestroy();
	}

	@Override public void onStart() {
		super.onStart();
		view.start();
	}

	@Override public void onStop() {
		view.stop();
		super.onStop();
	}

	@Override public void onPause() {
        super.onPause();
        view.pause();
	}

	@Override public void onResume() {
        super.onResume();
        view.resume();
	}

	@Override public void onConfigurationChanged(Configuration c) {
		super.onConfigurationChanged(c);
		view.configurationChanged();
	}

	@Override public void onLowMemory() {
		super.onLowMemory();
		GioView.onLowMemory();
	}

	@Override public void onBackPressed() {
		if (!view.backPressed())
			super.onBackPressed();
	}

	@Override protected void onNewIntent(Intent intent) {
		super.onNewIntent(intent);
		view.onIntentEvent(intent);
	}
}
