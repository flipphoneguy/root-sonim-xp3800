package com.flipphoneguy.root.xp3;

import android.content.Context;
import android.net.Uri;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ApkInstaller {

    public static class LatestRelease {
        public String tag;
        public String apkUrl;
    }

    // --- GitHub release check (for self-update) ---

    public static LatestRelease checkLatest(String repo) throws Exception {
        String body = fetchApi(
            "https://api.github.com/repos/" + repo + "/releases/latest");

        Matcher tagM = Pattern.compile(
            "\"tag_name\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
        Matcher urlM = Pattern.compile(
            "\"browser_download_url\"\\s*:\\s*\"([^\"]+\\.apk)\"").matcher(body);

        LatestRelease release = new LatestRelease();
        if (tagM.find()) release.tag = tagM.group(1);
        if (urlM.find()) release.apkUrl = urlM.group(1);
        return release;
    }

    public static int compareVersions(String a, String b) {
        String cleanA = a == null ? "" : a.replaceFirst("^[vV]", "");
        String cleanB = b == null ? "" : b.replaceFirst("^[vV]", "");
        String[] partsA = cleanA.split("\\.");
        String[] partsB = cleanB.split("\\.");
        int len = Math.max(partsA.length, partsB.length);
        for (int i = 0; i < len; i++) {
            int va = i < partsA.length ? parseIntSafe(partsA[i]) : 0;
            int vb = i < partsB.length ? parseIntSafe(partsB[i]) : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    public static File download(Context ctx, String apkUrl) throws Exception {
        File out = new File(ctx.getCacheDir(), "update.apk");
        HttpURLConnection conn = (HttpURLConnection)
            new URL(apkUrl).openConnection();
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);
        conn.setInstanceFollowRedirects(true);

        try (InputStream in = new BufferedInputStream(conn.getInputStream());
             FileOutputStream fos = new FileOutputStream(out)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) fos.write(buf, 0, n);
        } finally {
            conn.disconnect();
        }
        return out;
    }

    // --- Root install (for self-update) ---

    public static void installRoot(File apk) throws Exception {
        String tmp = "/data/local/tmp/update.apk";
        String cmd = "cp " + shellQuote(apk.getAbsolutePath()) + " " + shellQuote(tmp)
            + " && chmod 644 " + shellQuote(tmp)
            + " && pm install -r " + shellQuote(tmp)
            + " && rm -f " + shellQuote(tmp);

        ProcessBuilder pb = new ProcessBuilder("/system/bin/su", "-c", cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readStream(proc.getInputStream());
        int exit = proc.waitFor();

        apk.delete();

        if (exit != 0 || !output.contains("Success"))
            throw new Exception("pm install failed: " + output.trim());
    }

    // --- Install from URI (for APK button & intent handler) ---

    public static String installFromUri(Context ctx, Uri uri) {
        File tempFile = null;
        try {
            tempFile = new File(ctx.getCacheDir(), "install_pkg");
            String dst = tempFile.getAbsolutePath();

            if ("file".equals(uri.getScheme())) {
                rootCopy(uri.getPath(), dst);
            } else {
                boolean copied = false;
                String path = resolveContentPath(ctx, uri);
                if (path != null) {
                    try { rootCopy(path, dst); copied = true; }
                    catch (Exception ignored) {}
                }
                if (!copied) {
                    InputStream in = ctx.getContentResolver().openInputStream(uri);
                    if (in == null) throw new Exception("Cannot open file");
                    try (FileOutputStream out = new FileOutputStream(tempFile)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                    } finally {
                        in.close();
                    }
                }
            }

            if (isXapk(uri, ctx, tempFile)) {
                installXapkRoot(ctx, tempFile);
            } else {
                installSingleApkRoot(tempFile);
            }
            return null;
        } catch (Exception e) {
            return "Install failed: " + e.getMessage();
        } finally {
            if (tempFile != null) tempFile.delete();
        }
    }

    private static void rootCopy(String src, String dst) throws Exception {
        String cmd = "cp " + shellQuote(src) + " " + shellQuote(dst)
            + " && chmod 644 " + shellQuote(dst);
        ProcessBuilder pb = new ProcessBuilder("/system/bin/su", "-c", cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readStream(proc.getInputStream());
        if (proc.waitFor() != 0)
            throw new Exception("Root copy failed: " + output.trim());
    }

    private static String resolveContentPath(Context ctx, Uri uri) {
        try (android.database.Cursor c = ctx.getContentResolver().query(
                uri, new String[]{"_data"}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String path = c.getString(0);
                if (path != null && !path.isEmpty()) return path;
            }
        } catch (Exception ignored) {}
        return null;
    }

    // --- Single APK root install ---

    private static void installSingleApkRoot(File apk) throws Exception {
        String tmp = "/data/local/tmp/install.apk";
        String cmd = "cp " + shellQuote(apk.getAbsolutePath()) + " " + shellQuote(tmp)
            + " && chmod 644 " + shellQuote(tmp)
            + " && pm install -r " + shellQuote(tmp)
            + " && rm -f " + shellQuote(tmp);

        ProcessBuilder pb = new ProcessBuilder("/system/bin/su", "-c", cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readStream(proc.getInputStream());
        int exit = proc.waitFor();

        if (exit != 0 || !output.contains("Success"))
            throw new Exception("pm install failed: " + output.trim());
    }

    // --- XAPK (split APK) root install ---

    private static void installXapkRoot(Context ctx, File xapkFile) throws Exception {
        File tmpDir = new File(ctx.getCacheDir(), "xapk_tmp");
        tmpDir.mkdirs();
        ZipFile zip = null;

        try {
            zip = new ZipFile(xapkFile);
            List<File> apks = new ArrayList<File>();
            long totalSize = 0;

            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory()
                        && entry.getName().toLowerCase().endsWith(".apk")) {
                    File outFile = new File(tmpDir, new File(entry.getName()).getName());
                    try (InputStream in = zip.getInputStream(entry);
                         FileOutputStream out = new FileOutputStream(outFile)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                    }
                    apks.add(outFile);
                    totalSize += outFile.length();
                }
            }

            if (apks.isEmpty())
                throw new Exception("No APK files found in XAPK");

            if (apks.size() == 1) {
                installSingleApkRoot(apks.get(0));
                return;
            }

            File script = new File(ctx.getCacheDir(), "xapk_install.sh");
            PrintWriter pw = new PrintWriter(new FileWriter(script));
            pw.println("#!/system/bin/sh");
            pw.println("set -e");
            pw.println("DEST=/data/local/tmp/xapk");
            pw.println("mkdir -p $DEST");

            for (File apk : apks) {
                String src = shellQuote(apk.getAbsolutePath());
                String name = shellQuote(apk.getName());
                pw.println("cp " + src + " $DEST/" + name);
                pw.println("chmod 644 $DEST/" + name);
            }

            pw.println("CREATE_OUT=$(pm install-create -S " + totalSize + ")");
            pw.println("SESSION=$(echo \"$CREATE_OUT\" | grep -o '\\[.*\\]' | tr -d '[]')");

            for (File apk : apks) {
                String name = shellQuote(apk.getName());
                pw.println("pm install-write -S " + apk.length()
                    + " $SESSION " + name
                    + " $DEST/" + name);
            }

            pw.println("pm install-commit $SESSION");
            pw.println("rm -rf $DEST");
            pw.close();

            script.setExecutable(true, false);

            ProcessBuilder pb = new ProcessBuilder(
                "/system/bin/su", "-c", "sh " + script.getAbsolutePath());
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            String output = readStream(proc.getInputStream());
            int exit = proc.waitFor();

            script.delete();

            if (exit != 0)
                throw new Exception("XAPK install failed: " + output.trim());

        } finally {
            if (zip != null) {
                try { zip.close(); } catch (IOException ignored) {}
            }
            if (tmpDir.exists()) {
                File[] files = tmpDir.listFiles();
                if (files != null) {
                    for (File f : files) f.delete();
                }
                tmpDir.delete();
            }
        }
    }

    // --- XAPK detection ---

    private static boolean isXapk(Uri uri, Context ctx, File file) {
        String uriStr = uri.toString().toLowerCase();
        if (uriStr.endsWith(".xapk") || uriStr.endsWith(".zip")) return true;
        String type = ctx.getContentResolver().getType(uri);
        if ("application/vnd.android.package-archive".equals(type)) return false;
        try {
            ZipFile zf = new ZipFile(file);
            Enumeration<? extends ZipEntry> entries = zf.entries();
            boolean hasApk = false;
            while (entries.hasMoreElements()) {
                if (entries.nextElement().getName().toLowerCase().endsWith(".apk")) {
                    hasApk = true;
                    break;
                }
            }
            zf.close();
            return hasApk;
        } catch (Exception e) {
            return false;
        }
    }

    // --- Helpers ---

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

    private static String fetchApi(String apiUrl) throws IOException {
        HttpURLConnection c = (HttpURLConnection)
            new URL(apiUrl).openConnection();
        c.setRequestProperty("User-Agent", "RootManager/1.0");
        c.setRequestProperty("Accept", "application/vnd.github+json");
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setInstanceFollowRedirects(true);
        try {
            int code = c.getResponseCode();
            if (code != 200)
                throw new IOException("GitHub API HTTP " + code);
            InputStream in = c.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            in.close();
            return bos.toString("UTF-8");
        } finally {
            c.disconnect();
        }
    }

    private static int parseIntSafe(String s) {
        try { return Integer.parseInt(s.trim()); }
        catch (NumberFormatException e) { return 0; }
    }
}
