package app.telegramws.proxy;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;

final class UpdateApk {
    static final long MAX_BYTES = 32L * 1024 * 1024;
    private static final long TRANSFER_TIMEOUT = TimeUnit.MINUTES.toNanos(2);
    private static volatile State state = new State(null, false, false);
    private static boolean unannounced;

    record State(ReleaseUpdates.Available release, boolean running, boolean ready) {}

    static State status() {
        return state;
    }

    static synchronized State takeResult() {
        if (!unannounced) return null;
        unannounced = false;
        return state;
    }

    static synchronized void download(Context context, ReleaseUpdates.Available release) {
        if (state.running || !release.canDownload()) return;
        var app = context.getApplicationContext();
        unannounced = false;
        state = new State(release, true, false);
        new Thread(() -> {
            boolean ready = false;
            try {
                File destination = file(app);
                File temporary = File.createTempFile("update-", ".apk", destination.getParentFile());
                try {
                    transfer(release, temporary);
                    verifyPackage(app, temporary, release.version());
                    Files.move(temporary.toPath(), destination.toPath(),
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } finally {
                    Files.deleteIfExists(temporary.toPath());
                }
                ready = true;
            } catch (IOException | PackageManager.NameNotFoundException | SecurityException ignored) {
                // Offer a retry or the browser from the update dialog.
            }
            synchronized (UpdateApk.class) {
                state = new State(release, false, ready);
                unannounced = true;
            }
        }, "telegram-ws-update-download").start();
    }

    static File file(Context context) {
        return new File(context.getCacheDir(), "telegram-ws-update.apk");
    }

    static boolean allowedRedirect(URL url) {
        String host = url.getHost();
        return "https".equals(url.getProtocol()) && url.getUserInfo() == null
            && (url.getPort() == -1 || url.getPort() == 443)
            && ("release-assets.githubusercontent.com".equalsIgnoreCase(host)
                || "objects.githubusercontent.com".equalsIgnoreCase(host)
                || "github-releases.githubusercontent.com".equalsIgnoreCase(host));
    }

    static void transfer(ReleaseUpdates.Available release, File output) throws IOException {
        if (!release.canDownload()) throw new IOException("Missing APK metadata");
        URL url = new URL(release.downloadUrl());
        for (int hop = 0; hop < 4; hop++) {
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(8000);
            connection.setReadTimeout(12000);
            connection.setRequestProperty("User-Agent", "TelegramWS-Android");
            connection.setRequestProperty("Accept-Encoding", "identity");
            try {
                int status = connection.getResponseCode();
                if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                    String location = connection.getHeaderField("Location");
                    if (location == null) throw new IOException("Missing asset redirect");
                    url = new URL(url, location);
                    if (!allowedRedirect(url)) throw new IOException("Unexpected asset host");
                    continue;
                }
                if (status != 200) throw new IOException("APK unavailable");
                try (var input = connection.getInputStream(); var bytes = Files.newOutputStream(output.toPath())) {
                    copyVerified(input, bytes, release);
                }
                return;
            } finally {
                connection.disconnect();
            }
        }
        throw new IOException("Too many asset redirects");
    }

    static void copyVerified(InputStream input, OutputStream output, ReleaseUpdates.Available release)
        throws IOException {
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException error) {
            throw new IOException(error);
        }
        long started = System.nanoTime();
        long size = 0;
        byte[] buffer = new byte[32 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            size += count;
            if (size > release.apkSize() || System.nanoTime() - started > TRANSFER_TIMEOUT) {
                throw new IOException("APK transfer limit exceeded");
            }
            sha256.update(buffer, 0, count);
            output.write(buffer, 0, count);
        }
        if (size != release.apkSize() || !("sha256:" + hex(sha256.digest())).equals(release.digest())) {
            throw new IOException("APK integrity check failed");
        }
    }

    private static String hex(byte[] digest) {
        final String digits = "0123456789abcdef";
        StringBuilder value = new StringBuilder(digest.length * 2);
        for (byte part : digest) {
            value.append(digits.charAt((part & 0xff) >>> 4)).append(digits.charAt(part & 0x0f));
        }
        return value.toString();
    }

    static void verifyPackage(Context context, File file, String version)
        throws IOException, PackageManager.NameNotFoundException {
        var packages = context.getPackageManager();
        int flags = Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
        PackageInfo installed = packages.getPackageInfo(context.getPackageName(), flags);
        PackageInfo candidate = packages.getPackageArchiveInfo(file.getAbsolutePath(), flags);
        if (candidate == null || !installed.packageName.equals(candidate.packageName)
            || !version.equals(candidate.versionName) || versionCode(candidate) <= versionCode(installed)) {
            throw new IOException("Unexpected APK package or version");
        }
        Signature[] current = signers(installed);
        Signature[] incoming = signers(candidate);
        if (current == null || current.length == 0 || !Arrays.equals(current, incoming)) {
            throw new IOException("Unexpected APK signer");
        }
    }

    private static long versionCode(PackageInfo info) {
        return Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
    }

    private static Signature[] signers(PackageInfo info) {
        return Build.VERSION.SDK_INT >= 28
            ? (info.signingInfo == null ? null : info.signingInfo.getApkContentsSigners()) : info.signatures;
    }
}
