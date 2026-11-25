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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public final class DiagnosticReport extends ContentProvider {
    private static final String FILE_PATTERN = "telegram-ws-diagnostics-[0-9]+-[a-f0-9-]{36}\\.txt";

    static File save(Context context, String text) throws IOException {
        File directory = directory(context);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("Не удалось создать каталог отчётов");
        }
        long now = System.currentTimeMillis();
        File[] oldReports = directory.listFiles((dir, name) -> name.matches(FILE_PATTERN));
        if (oldReports != null) {
            for (File old : oldReports) {
                if (now - old.lastModified() > TimeUnit.DAYS.toMillis(2)) {
                    Files.deleteIfExists(old.toPath());
                }
            }
        }
        File report = new File(directory, "telegram-ws-diagnostics-" + now + "-" + UUID.randomUUID() + ".txt");
        Files.write(report.toPath(), text.getBytes(StandardCharsets.UTF_8));
        return report;
    }

    static Uri uri(Context context, File report) {
        return new Uri.Builder().scheme("content").authority(context.getPackageName() + ".diagnostics")
            .appendPath(report.getName()).build();
    }

    private static File directory(Context context) {
        return new File(context.getCacheDir(), "diagnostic-reports");
    }

    private File find(Uri uri) throws FileNotFoundException {
        List<String> path = uri.getPathSegments();
        if (path.size() != 1 || !path.get(0).matches(FILE_PATTERN)) {
            throw new FileNotFoundException("Неверный путь к отчёту");
        }
        File file = new File(directory(getContext()), path.get(0));
        if (!file.isFile()) throw new FileNotFoundException("Отчёт недоступен");
        return file;
    }

    @Override public boolean onCreate() { return true; }

    @Override public String getType(Uri uri) { return "text/plain"; }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Отчёт доступен только для чтения");
        return ParcelFileDescriptor.open(find(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        String[] columns = projection == null ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}
            : projection;
        MatrixCursor result = new MatrixCursor(columns, 1);
        try {
            File report = find(uri);
            MatrixCursor.RowBuilder row = result.newRow();
            for (String column : columns) {
                row.add(switch (column) {
                    case OpenableColumns.DISPLAY_NAME -> report.getName();
                    case OpenableColumns.SIZE -> report.length();
                    default -> null;
                });
            }
        } catch (FileNotFoundException ignored) {
            // A report removed from the cache has no row.
        }
        return result;
    }

    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
