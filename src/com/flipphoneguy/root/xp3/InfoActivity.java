package com.flipphoneguy.root.xp3;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

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

        // Boot setting
        final SharedPreferences prefs = getSharedPreferences("config", MODE_PRIVATE);
        CheckBox checkBoot = (CheckBox) findViewById(R.id.check_boot);
        checkBoot.setChecked(prefs.getBoolean("boot_enabled", true));
        checkBoot.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("boot_enabled", isChecked).apply();
            }
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
