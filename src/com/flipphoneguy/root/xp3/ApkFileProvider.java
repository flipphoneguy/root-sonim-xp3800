package com.flipphoneguy.root.xp3;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileNotFoundException;

public class ApkFileProvider extends ContentProvider {

    private static final String APK_NAME = "update.apk";

    public static Uri getUri(Context ctx, File file) {
        return new Uri.Builder()
            .scheme("content")
            .authority(ctx.getPackageName() + ".fileprovider")
            .path(APK_NAME)
            .build();
    }

    @Override
    public boolean onCreate() { return true; }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode)
            throws FileNotFoundException {
        File file = new File(getContext().getCacheDir(), APK_NAME);
        if (!file.exists()) throw new FileNotFoundException(APK_NAME);
        return ParcelFileDescriptor.open(file,
            ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public String getType(Uri uri) {
        return "application/vnd.android.package-archive";
    }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel,
            String[] selArgs, String sort) { return null; }

    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }

    @Override
    public int delete(Uri uri, String sel, String[] selArgs) { return 0; }

    @Override
    public int update(Uri uri, ContentValues values, String sel,
            String[] selArgs) { return 0; }
}
