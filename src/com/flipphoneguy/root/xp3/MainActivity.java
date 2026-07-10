package com.flipphoneguy.root.xp3;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final int REQUEST_PICK_APK = 1001;
    private static final int FILTER_USER = 0;
    private static final int FILTER_SYSTEM = 1;
    private static final int FILTER_ALL = 2;

    private TextView statusText;
    private Button btnRemoveMdm;
    private Button btnRestoreMdm;
    private TextView mdmStatus;
    private EditText searchBox;
    private LinearLayout appListContainer;
    private TextView appsEmpty;
    private Button filterUserBtn, filterSystemBtn, filterAllBtn;
    private int appliedMode = -1;
    private int currentFilter = FILTER_USER;
    private String searchQuery = "";

    private File blacklistFile;
    private HashSet<String> deniedApps;
    private List<AppItem> allApps;
    private List<AppItem> visibleApps;
    private PackageManager pm;

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(ThemeHelper.wrap(newBase));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        appliedMode = ThemeHelper.getMode(this);
        setContentView(R.layout.activity_main);

        pm = getPackageManager();
        statusText = (TextView) findViewById(R.id.statusText);
        btnRemoveMdm = (Button) findViewById(R.id.btn_remove_mdm);
        btnRestoreMdm = (Button) findViewById(R.id.btn_restore_mdm);
        mdmStatus = (TextView) findViewById(R.id.mdm_status);
        searchBox = (EditText) findViewById(R.id.searchBox);
        appListContainer = (LinearLayout) findViewById(R.id.app_list_container);
        appsEmpty = (TextView) findViewById(R.id.apps_empty);
        filterUserBtn = (Button) findViewById(R.id.filter_user);
        filterSystemBtn = (Button) findViewById(R.id.filter_system);
        filterAllBtn = (Button) findViewById(R.id.filter_all);

        blacklistFile = new File(getFilesDir(), "blacklist.txt");
        deniedApps = new HashSet<String>();
        allApps = new ArrayList<AppItem>();
        visibleApps = new ArrayList<AppItem>();

        copyAssets();

        findViewById(R.id.status_card).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                toggleRoot();
            }
        });

        findViewById(R.id.btn_install_apk).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                openFilePicker();
            }
        });

        btnRemoveMdm.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                confirmRemoveMdm();
            }
        });

        btnRestoreMdm.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                confirmRestoreMdm();
            }
        });

        findViewById(R.id.btn_info).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, InfoActivity.class));
            }
        });

        filterUserBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { setFilter(FILTER_USER); }
        });
        filterSystemBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { setFilter(FILTER_SYSTEM); }
        });
        filterAllBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { setFilter(FILTER_ALL); }
        });

        searchBox.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                searchQuery = s.toString().toLowerCase(Locale.getDefault());
                applyFilter();
            }
            public void afterTextChanged(Editable s) {}
        });

        loadBlacklist();
        updateFilterButtonStyles();
        updateStatus();
        loadApps();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (appliedMode != ThemeHelper.getMode(this)) {
            recreate();
        }
        updateStatus();
    }

    // --- Root status ---

    private void updateStatus() {
        if (isRootInstalled()) {
            statusText.setText(R.string.status_installed);
            statusText.setTextColor(0xFF00C853);
        } else {
            statusText.setText(R.string.status_not_installed);
            statusText.setTextColor(0xFFFF1744);
        }
    }

    private boolean isRootInstalled() {
        return new File("/system/bin/su").exists();
    }

    private void toggleRoot() {
        if (isRootInstalled()) {
            runScript("uninstall.sh");
        } else {
            runScript("install.sh");
        }
        updateStatus();
    }

    private void runScript(String scriptName) {
        try {
            File script = new File(getFilesDir(), scriptName);
            File logFile = new File(getFilesDir(), "launch_error.log");

            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", script.getAbsolutePath());
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);

            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.newLine();
            }
            writer.close();
            reader.close();

            int exitCode = p.waitFor();
            if (exitCode == 0) {
                Toast.makeText(this, "Success", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "Failed: Code " + exitCode, Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    // --- Assets ---

    private void copyAssets() {
        copyFile("su");
        copyFile("install.sh");
        copyFile("uninstall.sh");
    }

    private void copyFile(String filename) {
        try {
            InputStream in = getAssets().open(filename);
            File outFile = new File(getFilesDir(), filename);
            if (outFile.exists() && outFile.length() == in.available()) {
                setExecutable(outFile);
                in.close();
                return;
            }
            OutputStream out = new FileOutputStream(outFile);
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.flush();
            out.close();
            in.close();
            setExecutable(outFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void setExecutable(File f) {
        f.setReadable(true, false);
        f.setExecutable(true, false);
    }

    // --- File picker for APK/XAPK ---

    private void openFilePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
            "application/vnd.android.package-archive",
            "application/zip",
            "application/octet-stream"
        });
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(
            Intent.createChooser(intent, getString(R.string.pick_file)),
            REQUEST_PICK_APK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_PICK_APK && resultCode == RESULT_OK
                && data != null && data.getData() != null) {
            installPackage(data.getData());
        }
    }

    private void installPackage(final Uri uri) {
        if (!isRootInstalled()) {
            Toast.makeText(this, R.string.no_root, Toast.LENGTH_LONG).show();
            return;
        }

        Toast.makeText(this, R.string.installing, Toast.LENGTH_SHORT).show();

        new Thread(new Runnable() {
            @Override public void run() {
                final String result = ApkInstaller.installFromUri(MainActivity.this, uri);
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        if (result == null) {
                            Toast.makeText(MainActivity.this,
                                R.string.install_success, Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(MainActivity.this,
                                result, Toast.LENGTH_LONG).show();
                        }
                    }
                });
            }
        }).start();
    }

    // --- Remove Verizon MDM ---

    private void setMdmStatus(final String text) {
        mdmStatus.setVisibility(View.VISIBLE);
        mdmStatus.setText(text);
    }

    private void confirmRemoveMdm() {
        new AlertDialog.Builder(this)
            .setTitle(R.string.remove_mdm_confirm_title)
            .setMessage(R.string.remove_mdm_confirm_body)
            .setPositiveButton(R.string.btn_yes, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    removeMdm();
                }
            })
            .setNegativeButton(R.string.btn_no, null)
            .show();
    }

    private void removeMdm() {
        btnRemoveMdm.setEnabled(false);
        btnRestoreMdm.setEnabled(false);
        setMdmStatus(getString(R.string.remove_mdm_working));

        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    MdmRemover.remove(getCacheDir());
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            setMdmStatus(getString(R.string.remove_mdm_failed,
                                e.getMessage()));
                            btnRemoveMdm.setEnabled(true);
                            btnRestoreMdm.setEnabled(true);
                        }
                    });
                }
            }
        }).start();
    }

    private void confirmRestoreMdm() {
        new AlertDialog.Builder(this)
            .setTitle(R.string.restore_mdm_confirm_title)
            .setMessage(R.string.restore_mdm_confirm_body)
            .setPositiveButton(R.string.btn_yes, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    restoreMdm();
                }
            })
            .setNegativeButton(R.string.btn_no, null)
            .show();
    }

    private void restoreMdm() {
        btnRemoveMdm.setEnabled(false);
        btnRestoreMdm.setEnabled(false);
        setMdmStatus(getString(R.string.restore_mdm_working));

        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    MdmRemover.restore(getCacheDir());
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            setMdmStatus(getString(R.string.restore_mdm_failed,
                                e.getMessage()));
                            btnRemoveMdm.setEnabled(true);
                            btnRestoreMdm.setEnabled(true);
                        }
                    });
                }
            }
        }).start();
    }

    // --- Blacklist filter & render ---

    private void setFilter(int filter) {
        if (currentFilter == filter) return;
        currentFilter = filter;
        updateFilterButtonStyles();
        applyFilter();
    }

    private void updateFilterButtonStyles() {
        filterUserBtn.setTypeface(null,
            currentFilter == FILTER_USER ? Typeface.BOLD : Typeface.NORMAL);
        filterSystemBtn.setTypeface(null,
            currentFilter == FILTER_SYSTEM ? Typeface.BOLD : Typeface.NORMAL);
        filterAllBtn.setTypeface(null,
            currentFilter == FILTER_ALL ? Typeface.BOLD : Typeface.NORMAL);
    }

    private void loadApps() {
        List<ApplicationInfo> apps = pm.getInstalledApplications(0);
        Collections.sort(apps, new Comparator<ApplicationInfo>() {
            @Override public int compare(ApplicationInfo a, ApplicationInfo b) {
                return a.loadLabel(pm).toString()
                    .compareToIgnoreCase(b.loadLabel(pm).toString());
            }
        });
        allApps.clear();
        for (ApplicationInfo app : apps) {
            allApps.add(new AppItem(
                app.loadLabel(pm).toString(),
                app.packageName,
                (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0));
        }
        applyFilter();
    }

    private void applyFilter() {
        visibleApps.clear();
        for (AppItem app : allApps) {
            if (currentFilter == FILTER_USER && app.isSystem) continue;
            if (currentFilter == FILTER_SYSTEM && !app.isSystem) continue;

            if (!searchQuery.isEmpty()) {
                if (!app.label.toLowerCase(Locale.getDefault()).contains(searchQuery)
                        && !app.packageName.toLowerCase(Locale.getDefault()).contains(searchQuery)) {
                    continue;
                }
            }
            visibleApps.add(app);
        }
        renderAppList();
    }

    private void renderAppList() {
        appListContainer.removeAllViews();
        if (visibleApps.isEmpty()) {
            appsEmpty.setText(R.string.apps_empty);
            appsEmpty.setVisibility(View.VISIBLE);
            appListContainer.setVisibility(View.GONE);
            return;
        }
        appsEmpty.setVisibility(View.GONE);
        appListContainer.setVisibility(View.VISIBLE);

        for (final AppItem app : visibleApps) {
            CheckBox cb = new CheckBox(this);
            cb.setText(app.label);
            cb.setTextSize(13);
            cb.setTextColor(getResources().getColor(R.color.text_primary));
            cb.setMinHeight((int) (36 * getResources().getDisplayMetrics().density));
            cb.setPadding(4, 2, 4, 2);
            cb.setFocusable(true);
            cb.setChecked(deniedApps.contains(app.packageName));
            cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked) {
                        deniedApps.add(app.packageName);
                    } else {
                        deniedApps.remove(app.packageName);
                    }
                    saveBlacklist();
                }
            });
            appListContainer.addView(cb);
        }
    }

    // --- Blacklist persistence ---

    private void loadBlacklist() {
        if (!blacklistFile.exists()) return;
        try {
            BufferedReader br = new BufferedReader(new FileReader(blacklistFile));
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.trim().isEmpty()) deniedApps.add(line.trim());
            }
            br.close();
        } catch (Exception e) { /* ignore */ }
    }

    private void saveBlacklist() {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(blacklistFile));
            for (String pkg : deniedApps) {
                bw.write(pkg);
                bw.newLine();
            }
            bw.close();
        } catch (Exception e) {
            Toast.makeText(this, "Error saving blacklist", Toast.LENGTH_SHORT).show();
        }
    }

    // --- App item ---

    private static class AppItem {
        String label;
        String packageName;
        boolean isSystem;
        AppItem(String l, String p, boolean s) { label = l; packageName = p; isSystem = s; }
    }
}
