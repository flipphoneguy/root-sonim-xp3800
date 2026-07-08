package com.flipphoneguy.root.xp3;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;

import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;

public class InfoActivity extends Activity {

    private Button btnUpdate;
    private TextView updateStatus;

    private static final String[] THEME_LABELS = new String[3];

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(ThemeHelper.wrap(newBase));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_info);

        THEME_LABELS[ThemeHelper.MODE_SYSTEM] = getString(R.string.theme_system);
        THEME_LABELS[ThemeHelper.MODE_LIGHT] = getString(R.string.theme_light);
        THEME_LABELS[ThemeHelper.MODE_DARK] = getString(R.string.theme_dark);

        ((TextView) findViewById(R.id.info_app_name)).setText(BuildConfig.APP_NAME);
        ((TextView) findViewById(R.id.info_version)).setText("v" + BuildConfig.VERSION_NAME);

        findViewById(R.id.btn_back).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { finish(); }
        });

        // Update
        btnUpdate = (Button) findViewById(R.id.btn_check_update);
        updateStatus = (TextView) findViewById(R.id.update_status);
        btnUpdate.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { checkForUpdate(); }
        });

        // Links
        final String repoName = BuildConfig.REPO.contains("/")
            ? BuildConfig.REPO.split("/")[1] : BuildConfig.REPO;

        findViewById(R.id.btn_github_profile).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                openUrl(BuildConfig.GITHUB_PROFILE);
            }
        });

        findViewById(R.id.btn_app_repo).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                openUrl(BuildConfig.GITHUB_PROFILE + "/" + repoName);
            }
        });

        // Diagnostics
        findViewById(R.id.btn_view_log).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { viewInstallLog(); }
        });
        findViewById(R.id.btn_reinstall_verbose).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { confirmReinstallVerbose(); }
        });

        // Theme
        final Button btnTheme = (Button) findViewById(R.id.btn_theme);
        btnTheme.setText(THEME_LABELS[ThemeHelper.getMode(this)]);
        btnTheme.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                int next = (ThemeHelper.getMode(InfoActivity.this) + 1) % 3;
                ThemeHelper.setMode(InfoActivity.this, next);
                recreate();
            }
        });
    }

    private void openUrl(String url) {
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
    }

    private void setStatus(final String text) {
        updateStatus.setVisibility(View.VISIBLE);
        updateStatus.setText(text);
    }

    private void checkForUpdate() {
        btnUpdate.setEnabled(false);
        setStatus(getString(R.string.update_checking));

        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final ApkInstaller.LatestRelease release =
                        ApkInstaller.checkLatest(BuildConfig.REPO);

                    if (release == null || release.apkUrl == null) {
                        runOnUiThread(new Runnable() {
                            @Override public void run() {
                                setStatus(getString(R.string.update_no_release));
                                btnUpdate.setEnabled(true);
                            }
                        });
                        return;
                    }

                    int cmp = ApkInstaller.compareVersions(
                        release.tag, BuildConfig.VERSION_NAME);

                    if (cmp <= 0) {
                        runOnUiThread(new Runnable() {
                            @Override public void run() {
                                setStatus(getString(R.string.update_up_to_date,
                                    BuildConfig.VERSION_NAME));
                                btnUpdate.setEnabled(true);
                            }
                        });
                        return;
                    }

                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            setStatus(getString(R.string.update_downloading,
                                release.tag));
                        }
                    });

                    final File apk = ApkInstaller.download(
                        InfoActivity.this, release.apkUrl);

                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            showUpdateDialog(apk, release.tag);
                        }
                    });

                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            setStatus(getString(R.string.update_download_failed,
                                e.getMessage()));
                            btnUpdate.setEnabled(true);
                        }
                    });
                }
            }
        }).start();
    }

    private void showUpdateDialog(final File apk, final String tag) {
        setStatus(getString(R.string.update_ready, tag));
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.update_ready, tag))
            .setMessage(getString(R.string.update_confirm_body, tag))
            .setPositiveButton(R.string.btn_yes, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    installUpdate(apk);
                }
            })
            .setNegativeButton(R.string.btn_no, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    apk.delete();
                    btnUpdate.setEnabled(true);
                }
            })
            .setOnCancelListener(new DialogInterface.OnCancelListener() {
                @Override public void onCancel(DialogInterface d) {
                    apk.delete();
                    btnUpdate.setEnabled(true);
                }
            })
            .show();
    }

    private void viewInstallLog() {
        File logFile = new File(getFilesDir(), "install.log");
        if (!logFile.exists()) {
            Toast.makeText(this, R.string.log_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            BufferedReader br = new BufferedReader(new FileReader(logFile));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
            br.close();
            final String logText = sb.toString();

            LinearLayout root = new LinearLayout(this);
            root.setOrientation(LinearLayout.VERTICAL);

            TextView tv = new TextView(this);
            tv.setText(logText);
            tv.setTextSize(11);
            tv.setTypeface(android.graphics.Typeface.MONOSPACE);
            tv.setPadding(24, 16, 24, 16);

            ScrollView sv = new ScrollView(this);
            sv.setFocusable(true);
            sv.setFocusableInTouchMode(true);
            sv.addView(tv);
            root.addView(sv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

            LinearLayout buttons = new LinearLayout(this);
            buttons.setOrientation(LinearLayout.HORIZONTAL);
            buttons.setPadding(12, 8, 12, 8);
            buttons.setGravity(android.view.Gravity.END);

            Button btnCopy = new Button(this);
            btnCopy.setText(R.string.btn_copy);
            btnCopy.setFocusable(true);
            Button btnClose = new Button(this);
            btnClose.setText(R.string.btn_close);
            btnClose.setFocusable(true);

            btnCopy.setId(android.R.id.button1);
            btnClose.setId(android.R.id.button2);

            buttons.addView(btnCopy);
            buttons.addView(btnClose);
            root.addView(buttons);

            final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.log_title)
                .setView(root)
                .create();

            btnCopy.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("install_log", logText));
                    Toast.makeText(InfoActivity.this, R.string.log_copied, Toast.LENGTH_SHORT).show();
                }
            });
            btnClose.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { dialog.dismiss(); }
            });

            dialog.show();
        } catch (Exception e) {
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void confirmReinstallVerbose() {
        new AlertDialog.Builder(this)
            .setTitle(R.string.reinstall_confirm_title)
            .setMessage(R.string.reinstall_confirm)
            .setPositiveButton(R.string.btn_yes, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    reinstallVerbose();
                }
            })
            .setNegativeButton(R.string.btn_no, null)
            .show();
    }

    private void reinstallVerbose() {
        Toast.makeText(this, R.string.reinstalling_verbose, Toast.LENGTH_SHORT).show();
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    File script = new File(getFilesDir(), "install.sh");
                    ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", script.getAbsolutePath(), "-v");
                    pb.directory(getFilesDir());
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    File logFile = new File(getFilesDir(), "launch_error.log");
                    BufferedWriter writer = new BufferedWriter(new FileWriter(logFile));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        writer.write(line);
                        writer.newLine();
                    }
                    writer.close();
                    reader.close();
                    final int exitCode = p.waitFor();
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            if (exitCode == 0) {
                                Toast.makeText(InfoActivity.this, R.string.install_success, Toast.LENGTH_SHORT).show();
                            } else {
                                Toast.makeText(InfoActivity.this, "Failed: Code " + exitCode, Toast.LENGTH_LONG).show();
                            }
                            viewInstallLog();
                        }
                    });
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            Toast.makeText(InfoActivity.this, "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
                        }
                    });
                }
            }
        }).start();
    }

    private void installUpdate(final File apk) {
        setStatus(getString(R.string.update_installing));
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    ApkInstaller.installRoot(apk);
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            setStatus(getString(R.string.update_success));
                            Toast.makeText(InfoActivity.this,
                                R.string.update_success, Toast.LENGTH_SHORT).show();
                            btnUpdate.setEnabled(true);
                        }
                    });
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            setStatus(getString(R.string.update_install_failed,
                                e.getMessage()));
                            btnUpdate.setEnabled(true);
                        }
                    });
                }
            }
        }).start();
    }
}
