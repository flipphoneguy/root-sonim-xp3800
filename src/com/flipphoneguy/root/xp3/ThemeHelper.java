package com.flipphoneguy.root.xp3;

import android.content.Context;
import android.content.res.Configuration;

public class ThemeHelper {

    public static final int MODE_SYSTEM = 0;
    public static final int MODE_LIGHT = 1;
    public static final int MODE_DARK = 2;

    private static final String PREFS = "theme_prefs";
    private static final String KEY_MODE = "theme_mode";

    public static int getMode(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt(KEY_MODE, MODE_SYSTEM);
    }

    public static void setMode(Context context, int mode) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putInt(KEY_MODE, mode).apply();
    }

    public static Context wrap(Context context) {
        int mode = getMode(context);
        if (mode == MODE_SYSTEM) return context;

        int nightFlag = (mode == MODE_DARK)
            ? Configuration.UI_MODE_NIGHT_YES
            : Configuration.UI_MODE_NIGHT_NO;

        Configuration config = new Configuration(context.getResources().getConfiguration());
        config.uiMode = (config.uiMode & ~Configuration.UI_MODE_NIGHT_MASK) | nightFlag;
        return context.createConfigurationContext(config);
    }
}
