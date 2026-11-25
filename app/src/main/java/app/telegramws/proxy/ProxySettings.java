package app.telegramws.proxy;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.IOException;
import java.net.IDN;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.json.JSONException;

final class ProxySettings {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private final SharedPreferences values;

    ProxySettings(Context context) {
        values = context.getSharedPreferences("proxy", Context.MODE_PRIVATE);
    }

    Routes.Config load() {
        String secret = values.getString("secret", "");
        if (secret.isEmpty()) {
            byte[] bytes = new byte[16];
            new SecureRandom().nextBytes(bytes);
            char[] hex = new char[32];
            for (int i = 0; i < bytes.length; i++) {
                hex[i * 2] = HEX[(bytes[i] & 0xff) >>> 4];
                hex[i * 2 + 1] = HEX[bytes[i] & 0x0f];
            }
            secret = new String(hex);
            values.edit().putString("secret", secret).apply();
        }
        return new Routes.Config(port(), secret, parseIps(ips()),
            values.getString("cloudflare", ""), values.getString("worker", ""),
            values.getBoolean("community", false), values.getBoolean("tcp", true),
            loadSocks(), values.getBoolean("socksFirst", false), values.getBoolean("communityPlain", false));
    }

    int port() {
        return values.getInt("port", 1443);
    }

    private Socks5.Endpoint loadSocks() {
        String address = values.getString("socksAddress", "");
        if (address.isEmpty()) {
            return null;
        }
        try {
            SocksCredentials.Login login = SocksCredentials.read(values);
            return Socks5.parse(address, login.user(), login.password());
        } catch (GeneralSecurityException | IOException | JSONException | IllegalArgumentException | IllegalStateException e) {
            return null;
        }
    }

    String ips() {
        return Routes.upgradedIps(values.getString("overrides", Routes.DEFAULT_IPS));
    }

    void save(String port, String ips, String cloudflare, String worker, boolean community, boolean tcp,
              String socksAddress, String socksUser, String socksPassword, boolean socksFirst,
              boolean communityPlain) {
        int parsedPort;
        try {
            parsedPort = Integer.parseInt(port.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Укажите порт от 1024 до 65535");
        }
        if (parsedPort < 1024 || parsedPort > 65535) {
            throw new IllegalArgumentException("Укажите порт от 1024 до 65535");
        }
        parseIps(ips);
        String cfHost = domain(cloudflare);
        String workerHost = domain(worker);
        Socks5.Endpoint socks = Socks5.parse(socksAddress, socksUser, socksPassword);
        if (socks != null && socks.port() == parsedPort
            && (socks.host().equalsIgnoreCase("localhost") || socks.host().startsWith("127."))) {
            throw new IllegalArgumentException("У SOCKS5 должен быть свой порт");
        }
        SharedPreferences.Editor edit = values.edit();
        try {
            SocksCredentials.write(edit, socksUser, socksPassword);
        } catch (GeneralSecurityException | IOException | IllegalStateException e) {
            throw new IllegalArgumentException("Не удалось защитить учётные данные SOCKS5");
        }
        edit.putString("socksAddress", socks == null ? "" : socks.address())
            .putInt("port", parsedPort).putString("overrides", ips.trim())
            .putString("cloudflare", cfHost).putString("worker", workerHost)
            .putBoolean("community", community).putBoolean("tcp", tcp)
            .putBoolean("communityPlain", communityPlain)
            .putBoolean("socksFirst", socks != null && socksFirst).apply();
    }

    static byte[] key(String hex) {
        byte[] key = new byte[16];
        for (int i = 0; i < key.length; i++) {
            int offset = i * 2;
            key[i] = (byte) ((Character.digit(hex.charAt(offset), 16) << 4)
                | Character.digit(hex.charAt(offset + 1), 16));
        }
        return key;
    }

    private static String domain(String value) {
        if (value.trim().isEmpty()) {
            return "";
        }
        try {
            String ascii = IDN.toASCII(value.trim(), IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (ascii.length() <= 245 && ascii.matches("[a-z0-9-]+(\\.[a-z0-9-]+)*\\.[a-z][a-z0-9-]+")) {
                return ascii;
            }
        } catch (IllegalArgumentException ignored) {
            // Treat invalid IDN labels the same way as invalid ASCII hostnames.
        }
        throw new IllegalArgumentException("Укажите домен без https://, порта и пути");
    }

    private static Map<Integer, String> parseIps(String value) {
        Map<Integer, String> result = new LinkedHashMap<>();
        for (String entry : value.trim().split("\\s+")) {
            if (entry.isEmpty()) {
                continue;
            }
            String[] parts = entry.split(":", -1);
            if (parts.length != 2 || !parts[0].matches("[1-5]|203") || !ipv4(parts[1])) {
                throw new IllegalArgumentException("Укажите DC и IPv4 в формате 2:149.154.167.220");
            }
            if (result.put(Integer.parseInt(parts[0]), parts[1]) != null) {
                throw new IllegalArgumentException("Каждый датацентр можно указать один раз");
            }
        }
        return Collections.unmodifiableMap(result);
    }

    private static boolean ipv4(String value) {
        String[] pieces = value.split("\\.", -1);
        if (pieces.length != 4) {
            return false;
        }
        for (String piece : pieces) {
            if (!piece.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(piece) > 255) {
                return false;
            }
        }
        return true;
    }
}
