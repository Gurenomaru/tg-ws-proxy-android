package app.telegramws.proxy;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class ReleaseUpdates {
    private static final String REPOSITORY = "Gurenomaru/tg-ws-proxy-android";
    private static final String API = "https://api.github.com/repos/" + REPOSITORY + "/releases/latest";
    private static final String RELEASE_TAG = "https://github.com/" + REPOSITORY + "/releases/tag/";
    private static final long MIN_INTERVAL = TimeUnit.HOURS.toMillis(24);
    private static final int RESPONSE_LIMIT = 128 * 1024;
    private static final Pattern VERSION = Pattern.compile("(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})");
    private static volatile State state = new State(0, false, false, null);

    record Available(String version, String releaseUrl) {}
    record State(int id, boolean running, boolean failed, Available available) {}

    static State status() {
        return state;
    }

    static synchronized boolean check(Context context, boolean manual) {
        if (state.running) {
            return false;
        }
        var preferences = context.getSharedPreferences("release_updates", Context.MODE_PRIVATE);
        long now = System.currentTimeMillis();
        long last = preferences.getLong("lastCheck", 0);
        if (!manual && last <= now && now - last < MIN_INTERVAL) {
            return false;
        }
        preferences.edit().putLong("lastCheck", now).apply();
        int id = state.id + 1;
        state = new State(id, true, false, null);
        new Thread(() -> {
            try {
                state = new State(id, false, false, fetch());
            } catch (IOException | JSONException ignored) {
                state = new State(id, false, true, null);
            }
        }, "telegram-ws-release-check").start();
        return true;
    }

    private static Available fetch() throws IOException, JSONException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(API).openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(4500);
        connection.setReadTimeout(4500);
        connection.setRequestProperty("Accept", "application/vnd.github+json");
        connection.setRequestProperty("User-Agent", "TelegramWS-Android");
        try {
            int status = connection.getResponseCode();
            if (status == 404) return null;
            if (status != 200) throw new IOException("GitHub Releases unavailable");
            try (var input = connection.getInputStream(); var bytes = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (bytes.size() + count > RESPONSE_LIMIT) {
                        throw new IOException("Release response too large");
                    }
                    bytes.write(buffer, 0, count);
                }
                String body = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
                return parse(new JSONObject(body), BuildConfig.VERSION_NAME);
            }
        } finally {
            connection.disconnect();
        }
    }

    static Available parse(JSONObject release, String installed) {
        if (release.optBoolean("draft", true) || release.optBoolean("prerelease", true)) return null;
        String tag = release.optString("tag_name");
        if (!tag.startsWith("v")) return null;
        String version = tag.substring(1);
        if (!isNewer(version, installed)) return null;
        JSONArray assets = release.optJSONArray("assets");
        if (assets == null) return null;
        String name = "telegram-ws-android-" + tag + ".apk";
        for (int index = 0; index < assets.length(); index++) {
            JSONObject asset = assets.optJSONObject(index);
            if (asset != null && name.equals(asset.optString("name")) && "uploaded".equals(asset.optString("state"))) {
                return new Available(version, RELEASE_TAG + tag);
            }
        }
        return null;
    }

    static boolean isNewer(String available, String installed) {
        var newer = VERSION.matcher(available);
        var current = VERSION.matcher(installed);
        if (!newer.matches() || !current.matches()) return false;
        for (int group = 1; group <= 3; group++) {
            int comparison = Integer.compare(Integer.parseInt(newer.group(group)), Integer.parseInt(current.group(group)));
            if (comparison != 0) return comparison > 0;
        }
        return false;
    }
}
