package com.flipphoneguy.root.xp3;

import android.content.Context;
import android.content.pm.PackageManager;

import java.io.File;

public final class MdmRemover {

    private static final String VERIZON_MDM_PACKAGE = "com.verizon.mdm.basicphone";
    private static final String PREFS = "config";
    private static final String KEY_MDM_REMOVED = "mdm_removed";
    private static final String[] SU_PATHS = {"/system/bin/su", "/sbin/su"};

    public static boolean isVerizonDevice(Context ctx) {
        try {
            ctx.getPackageManager().getPackageInfo(VERIZON_MDM_PACKAGE, 0);
            return true;
        } catch (Exception e) {
            return isRemoved(ctx);
        }
    }

    public static boolean isRemoved(Context ctx) {
        if (ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_MDM_REMOVED, false))
            return true;
        try {
            int state = ctx.getPackageManager()
                .getApplicationEnabledSetting(VERIZON_MDM_PACKAGE);
            return state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                || state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER;
        } catch (Exception e) {
            return false;
        }
    }

    static String findSu() {
        for (String path : SU_PATHS)
            if (new File(path).exists()) return path;
        return null;
    }

    public static void remove(Context ctx) throws Exception {
        runScript(ctx, "remove");
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_MDM_REMOVED, true).apply();
    }

    public static void restore(Context ctx) throws Exception {
        runScript(ctx, "restore");
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_MDM_REMOVED, false).apply();
    }

    private static void runScript(Context ctx, String action) throws Exception {
        String su = findSu();
        if (su == null)
            throw new Exception("su binary not found");
        File script = new File(ctx.getFilesDir(), "mdm.sh");
        ProcessBuilder pb = new ProcessBuilder(
            su, "-c", "sh " + script.getAbsolutePath() + " " + action);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = ApkInstaller.readStream(proc.getInputStream());
        int exit = proc.waitFor();
        if (exit != 0)
            throw new Exception(output.trim());
    }
}
