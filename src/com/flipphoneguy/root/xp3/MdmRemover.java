package com.flipphoneguy.root.xp3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class MdmRemover {

    private static final String VERIZON_MDM_PACKAGE = "com.verizon.mdm.basicphone";
    private static final String BACKUP_DIR = "/data/system/mdm_removal_backup";

    private static final String EMPTY_DEVICE_OWNER_XML =
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<root>\n</root>\n";

    // The XP3800 is ARM32-only. Priv-app native libs are extracted by PackageManagerService
    // into <apkDir>/lib/<instruction-set>/ at package-scan time - not read from the APK zip
    // at runtime. Renaming the apk away and back (remove()/restore()) makes PackageManager
    // treat it as uninstalled/reinstalled, but by the time it rescans after our forced
    // reboot /system is already read-only again, so the re-extraction silently fails and
    // the app crashes with UnsatisfiedLinkError. We re-extract it ourselves instead.
    private static final String NATIVE_LIB_ABI = "armeabi-v7a";
    private static final String NATIVE_LIB_INSTRUCTION_SET = "arm";
    private static final String NATIVE_LIB_NAME = "libsqlcipher.so";

    public static void remove(File cacheDir) throws Exception {
        File ownerXml = new File(cacheDir, "device_owner_2.xml");
        File script = new File(cacheDir, "remove_verizon_mdm.sh");

        try (FileWriter fw = new FileWriter(ownerXml)) {
            fw.write(EMPTY_DEVICE_OWNER_XML);
        }

        String ownerXmlPath = shellQuote(ownerXml.getAbsolutePath());

        PrintWriter pw = new PrintWriter(new FileWriter(script));
        pw.println("#!/system/bin/sh");
        pw.println("set -e");
        pw.println("mount -o rw,remount /system");
        pw.println("mkdir -p " + BACKUP_DIR);
        pw.println("APK=$(pm path " + VERIZON_MDM_PACKAGE + " 2>/dev/null | sed 's/^package://')");
        pw.println("if [ -n \"$APK\" ]; then");
        pw.println("  echo \"$APK\" > " + BACKUP_DIR + "/apk_path.txt");
        pw.println("  mv \"$APK\" \"$APK.bak\"");
        pw.println("fi");
        pw.println("if [ ! -f " + BACKUP_DIR + "/device_owner_2.xml.orig ]; then");
        pw.println("  cp /system/etc/device_owner_2.xml " + BACKUP_DIR + "/device_owner_2.xml.orig");
        pw.println("fi");
        pw.println("if [ ! -f " + BACKUP_DIR + "/device_policies.xml.orig ] "
            + "&& [ -f /data/system/device_policies.xml ]; then");
        pw.println("  cp /data/system/device_policies.xml " + BACKUP_DIR + "/device_policies.xml.orig");
        pw.println("fi");
        pw.println("cp " + ownerXmlPath + " /system/etc/device_owner_2.xml");
        pw.println("cp " + ownerXmlPath + " /data/system/device_owner_2.xml");
        pw.println("rm -f /data/system/device_policies.xml");
        pw.println("mount -o ro,remount /system");
        pw.println("sync");
        pw.println("echo b > /proc/sysrq-trigger");
        pw.close();

        script.setExecutable(true, false);

        ProcessBuilder pb = new ProcessBuilder(
            "/system/bin/su", "-c", "sh " + script.getAbsolutePath());
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readStream(proc.getInputStream());
        int exit = proc.waitFor();

        script.delete();
        ownerXml.delete();

        if (exit != 0)
            throw new Exception("Removal failed: " + output.trim());
    }

    public static void restore(File cacheDir) throws Exception {
        File script = new File(cacheDir, "restore_verizon_mdm.sh");
        File nativeLib = new File(cacheDir, NATIVE_LIB_NAME);

        String apkPath = runRoot("cat " + BACKUP_DIR + "/apk_path.txt 2>/dev/null").trim();
        boolean haveNativeLib = !apkPath.isEmpty()
            && extractNativeLib(apkPath + ".bak", nativeLib);

        PrintWriter pw = new PrintWriter(new FileWriter(script));
        pw.println("#!/system/bin/sh");
        pw.println("BACKUP=" + BACKUP_DIR);
        pw.println("if [ ! -f \"$BACKUP/device_owner_2.xml.orig\" ]; then");
        pw.println("  echo 'No backup found - Verizon MDM was not previously removed on this device.'");
        pw.println("  exit 1");
        pw.println("fi");
        pw.println("set -e");
        pw.println("mount -o rw,remount /system");
        pw.println("if [ -f \"$BACKUP/apk_path.txt\" ]; then");
        pw.println("  APK=$(cat \"$BACKUP/apk_path.txt\")");
        pw.println("  if [ -f \"$APK.bak\" ]; then mv \"$APK.bak\" \"$APK\"; fi");
        if (haveNativeLib) {
            String libPath = shellQuote(nativeLib.getAbsolutePath());
            pw.println("  LIBDIR=$(dirname \"$APK\")/lib/" + NATIVE_LIB_INSTRUCTION_SET);
            pw.println("  mkdir -p \"$LIBDIR\"");
            pw.println("  cp " + libPath + " \"$LIBDIR/" + NATIVE_LIB_NAME + "\"");
            pw.println("  chmod 644 \"$LIBDIR/" + NATIVE_LIB_NAME + "\"");
            pw.println("  chmod 755 \"$LIBDIR\"");
        }
        pw.println("fi");
        pw.println("cp \"$BACKUP/device_owner_2.xml.orig\" /system/etc/device_owner_2.xml");
        pw.println("cp \"$BACKUP/device_owner_2.xml.orig\" /data/system/device_owner_2.xml");
        pw.println("if [ -f \"$BACKUP/device_policies.xml.orig\" ]; then");
        pw.println("  cp \"$BACKUP/device_policies.xml.orig\" /data/system/device_policies.xml");
        pw.println("fi");
        pw.println("mount -o ro,remount /system");
        pw.println("sync");
        pw.println("echo b > /proc/sysrq-trigger");
        pw.close();

        script.setExecutable(true, false);

        ProcessBuilder pb = new ProcessBuilder(
            "/system/bin/su", "-c", "sh " + script.getAbsolutePath());
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readStream(proc.getInputStream());
        int exit = proc.waitFor();

        script.delete();
        nativeLib.delete();

        if (exit != 0)
            throw new Exception("Restore failed: " + output.trim());
    }

    private static String runRoot(String cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/system/bin/su", "-c", cmd);
        Process proc = pb.start();
        String output = readStream(proc.getInputStream());
        proc.waitFor();
        return output;
    }

    // Priv-app apks are world-readable on /system, so this needs no root - it just pulls
    // the .so back out of the (still-renamed) apk's own zip before the shell script moves
    // it into place. Best-effort: returns false rather than throwing, so a missing/changed
    // zip entry doesn't block the device-owner restore itself.
    private static boolean extractNativeLib(String apkPath, File outFile) {
        ZipFile zip = null;
        try {
            zip = new ZipFile(apkPath);
            ZipEntry entry = zip.getEntry("lib/" + NATIVE_LIB_ABI + "/" + NATIVE_LIB_NAME);
            if (entry == null) return false;

            InputStream in = zip.getInputStream(entry);
            FileOutputStream out = new FileOutputStream(outFile);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1)
                out.write(buf, 0, n);
            out.close();
            in.close();
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            if (zip != null) {
                try { zip.close(); } catch (IOException ignored) { }
            }
        }
    }

    private static String readStream(InputStream is) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null)
            sb.append(line).append('\n');
        reader.close();
        return sb.toString();
    }

    private static String shellQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }
}
