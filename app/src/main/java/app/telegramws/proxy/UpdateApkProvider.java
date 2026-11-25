package app.telegramws.proxy;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;

public final class UpdateApkProvider extends ContentProvider {
    static final String APK_TYPE = "application/vnd.android.package-archive";

    static Uri uri(Context context) {
        return new Uri.Builder().scheme("content").authority(context.getPackageName() + ".updates")
            .appendPath("update.apk").build();
    }

    @Override public boolean onCreate() { return true; }
    @Override public String getType(Uri uri) { return APK_TYPE; }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File apk = UpdateApk.file(getContext());
        if (!"r".equals(mode) || !uri.equals(uri(getContext())) || !apk.isFile()) {
            throw new FileNotFoundException("APK недоступен");
        }
        return ParcelFileDescriptor.open(apk, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        String[] columns = projection == null ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}
            : projection;
        MatrixCursor result = new MatrixCursor(columns, 1);
        File apk = UpdateApk.file(getContext());
        if (uri.equals(uri(getContext())) && apk.isFile()) {
            MatrixCursor.RowBuilder row = result.newRow();
            for (String column : columns) {
                row.add(switch (column) {
                    case OpenableColumns.DISPLAY_NAME -> apk.getName();
                    case OpenableColumns.SIZE -> apk.length();
                    default -> null;
                });
            }
        }
        return result;
    }

    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
