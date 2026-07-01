package com.flipphoneguy.root.xp3;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

public class InstallActivity extends Activity {

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(ThemeHelper.wrap(newBase));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_install);

        Intent intent = getIntent();
        Uri data = intent.getData();

        if (data == null && Intent.ACTION_SEND.equals(intent.getAction())) {
            data = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        }

        if (data == null) {
            finish();
            return;
        }

        if (!new File("/system/bin/su").exists()) {
            Toast.makeText(this, R.string.no_root, Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        final Uri uri = data;
        final TextView statusText = (TextView) findViewById(R.id.install_status);
        final LinearLayout buttons = (LinearLayout) findViewById(R.id.install_buttons);

        findViewById(R.id.btn_cancel).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                finish();
            }
        });

        findViewById(R.id.btn_install).setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                buttons.setVisibility(View.GONE);
                statusText.setText(R.string.installing);
                statusText.setVisibility(View.VISIBLE);
                doInstall(uri, statusText);
            }
        });

        findViewById(R.id.btn_install).requestFocus();
    }

    private void doInstall(final Uri uri, final TextView statusText) {
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
