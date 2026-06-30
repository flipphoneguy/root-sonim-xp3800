package com.flipphoneguy.root.xp3;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Toast;

import java.io.File;

public class InstallActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        Uri data = intent.getData();

        if (data == null && Intent.ACTION_SEND.equals(intent.getAction())) {
            data = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        }

        if (data == null) {
            finish();
            return;
        }

        if (!new File("/sbin/su").exists()) {
            Toast.makeText(this, R.string.no_root, Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        final Uri uri = data;
        new AlertDialog.Builder(this)
            .setTitle(R.string.install_confirm_title)
            .setMessage(R.string.install_confirm_body)
            .setPositiveButton(R.string.btn_yes, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    doInstall(uri);
                }
            })
            .setNegativeButton(R.string.btn_no, new DialogInterface.OnClickListener() {
                @Override public void onClick(DialogInterface dialog, int which) {
                    finish();
                }
            })
            .setOnCancelListener(new DialogInterface.OnCancelListener() {
                @Override public void onCancel(DialogInterface dialog) {
                    finish();
                }
            })
            .show();
    }

    private void doInstall(final Uri uri) {
        Toast.makeText(this, R.string.installing, Toast.LENGTH_SHORT).show();

        new Thread(new Runnable() {
            @Override public void run() {
                final String result = ApkInstaller.installFromUri(
                    InstallActivity.this, uri);
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        if (result == null) {
                            Toast.makeText(InstallActivity.this,
                                R.string.install_success, Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(InstallActivity.this,
                                result, Toast.LENGTH_LONG).show();
                        }
                        finish();
                    }
                });
            }
        }).start();
    }
}
