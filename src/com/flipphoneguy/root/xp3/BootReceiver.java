package com.flipphoneguy.root.xp3;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

import java.io.File;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        SharedPreferences prefs = context.getSharedPreferences("config", Context.MODE_PRIVATE);
        if (prefs.getBoolean("boot_enabled", true)) {
            try {
                File script = new File(context.getFilesDir(), "install.sh");
                if (script.exists()) {
                    Runtime.getRuntime().exec(
                        new String[]{"/system/bin/sh", script.getAbsolutePath()});
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
