package com.flipphoneguy.root;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.TextView;
import android.widget.Toast;
import java.io.*;

public class MainActivity extends Activity {

    private TextView statusText;
    private Button btnToggle;
    private Button btnBlacklist;
    private CheckBox checkAuto;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = (TextView) findViewById(R.id.statusText);
        btnToggle = (Button) findViewById(R.id.btnToggleRoot);
        btnBlacklist = (Button) findViewById(R.id.btnBlacklist);
        checkAuto = (CheckBox) findViewById(R.id.checkAutoStart);
        prefs = getSharedPreferences("config", MODE_PRIVATE);

        // Always check assets on launch to ensure they are up to date
        // and permissions are set correctly.
        copyAssets();

        checkAuto.setChecked(prefs.getBoolean("boot_enabled", true));

        checkAuto.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("boot_enabled", isChecked).commit();
            }
        });

        btnToggle.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (isRootInstalled()) {
                    runScript("uninstall.sh");
                } else {
                    runScript("install.sh");
                }
                updateStatus();
            }
        });

        btnBlacklist.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, BlacklistActivity.class));
            }
        });

        updateStatus();
    }

    private void updateStatus() {
        if (isRootInstalled()) {
            statusText.setText("Status: INSTALLED");
            statusText.setTextColor(0xFF00FF00); // Green
            btnToggle.setText("Uninstall Root");
        } else {
            statusText.setText("Status: NOT INSTALLED");
            statusText.setTextColor(0xFFFF0000); // Red
            btnToggle.setText("Install Root");
        }
    }

    private boolean isRootInstalled() {
        return new File("/sbin/su").exists();
    }

    private void runScript(String scriptName) {
        try {
            File script = new File(getFilesDir(), scriptName);
            File logFile = new File(getFilesDir(), "launch_error.log");
            
            // FIX 1: Use String array for safer execution
            String[] cmd = { "/system/bin/sh", script.getAbsolutePath() };
            
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.directory(getFilesDir());
            // FIX 2: Merge stderr into stdout so we capture EVERYTHING
            pb.redirectErrorStream(true);
            
            Process p = pb.start();
            
            // FIX 3: Read the output to the log file immediately
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
                 Toast.makeText(this, "Failed: Code " + exitCode + ". Check launch_error.log", Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, "Java Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void copyAssets() {
        copyFile("su");
        copyFile("nsenter");
        copyFile("install.sh");
        copyFile("uninstall.sh");
    }

    private void copyFile(String filename) {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = getAssets().open(filename);
            File outFile = new File(getFilesDir(), filename);
            // Only copy if size differs or doesn't exist to save IO
            if (outFile.exists() && outFile.length() == in.available()) {
                 // Even if exists, ensure executable
                 setExecutable(outFile);
                 return;
            }
            
            out = new FileOutputStream(outFile);
            byte[] buffer = new byte[1024];
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
        try {
            // FIX 4: WaitFor() ensures chmod finishes before we try to run it
            Runtime.getRuntime().exec("chmod 755 " + f.getAbsolutePath()).waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}