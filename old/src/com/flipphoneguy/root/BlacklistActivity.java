package com.flipphoneguy.root;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;
import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

public class BlacklistActivity extends Activity {

    private ListView listView;
    private EditText searchBox;
    private File blacklistFile;
    private HashSet<String> deniedApps;
    private List<AppItem> allApps;
    private ArrayAdapter<AppItem> adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_blacklist);

        listView = (ListView) findViewById(R.id.appList);
        searchBox = (EditText) findViewById(R.id.searchBox);
        blacklistFile = new File(getFilesDir(), "blacklist.txt");
        deniedApps = new HashSet<String>();
        allApps = new ArrayList<AppItem>();

        loadBlacklist();
        loadInstalledApps();

        adapter = new ArrayAdapter<AppItem>(this,
                android.R.layout.simple_list_item_multiple_choice, new ArrayList<AppItem>(allApps));
        
        listView.setAdapter(adapter);
        updateChecks(); // Set initial checkmarks

        // Handle Clicks
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                AppItem item = adapter.getItem(position);
                if (listView.isItemChecked(position)) {
                    deniedApps.add(item.packageName);
                } else {
                    deniedApps.remove(item.packageName);
                }
                saveBlacklist();
            }
        });

        // Handle Search
        searchBox.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                adapter.clear();
                String query = s.toString().toLowerCase();
                for (AppItem app : allApps) {
                    if (app.label.toLowerCase().contains(query) || app.packageName.toLowerCase().contains(query)) {
                        adapter.add(app);
                    }
                }
                updateChecks(); // Re-apply checks to filtered list
            }
            public void afterTextChanged(Editable s) {}
        });
    }

    // Helper to re-check items that are in the denied set
    private void updateChecks() {
        for (int i = 0; i < adapter.getCount(); i++) {
            AppItem item = adapter.getItem(i);
            if (deniedApps.contains(item.packageName)) {
                listView.setItemChecked(i, true);
            } else {
                listView.setItemChecked(i, false);
            }
        }
    }

    private void loadBlacklist() {
        if (!blacklistFile.exists()) return;
        try {
            BufferedReader br = new BufferedReader(new FileReader(blacklistFile));
            String line;
            while ((line = br.readLine()) != null) {
                if(!line.trim().isEmpty()) deniedApps.add(line.trim());
            }
            br.close();
        } catch (Exception e) {}
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
            Toast.makeText(this, "Error saving", Toast.LENGTH_SHORT).show();
        }
    }

    private void loadInstalledApps() {
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> apps = pm.getInstalledApplications(0);
        for (ApplicationInfo app : apps) {
            allApps.add(new AppItem(app.loadLabel(pm).toString(), app.packageName));
        }
        Collections.sort(allApps);
    }

    private static class AppItem implements Comparable<AppItem> {
        String label;
        String packageName;
        AppItem(String l, String p) { label = l; packageName = p; }
        public String toString() { return label; }
        public int compareTo(AppItem other) { return label.compareToIgnoreCase(other.label); }
    }
}