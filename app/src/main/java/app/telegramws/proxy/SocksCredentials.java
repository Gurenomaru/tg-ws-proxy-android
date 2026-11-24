package app.telegramws.proxy;

import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONArray;
import org.json.JSONException;

final class SocksCredentials {
    private static final String STORE = "AndroidKeyStore";
    private static final String ALIAS = "proxy.socks.v1";
    private static final String FIELD = "socksCredentials";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    record Login(String user, String password) {}

    static Login read(SharedPreferences prefs) throws GeneralSecurityException, IOException, JSONException {
        String stored = prefs.getString(FIELD, "");
        if (!stored.isEmpty()) {
            byte[] data = Base64.getDecoder().decode(stored);
            if (data.length < IV_BYTES + TAG_BITS / 8) {
                throw new GeneralSecurityException("Invalid credential envelope");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(TAG_BITS, data, 0, IV_BYTES));
            byte[] clear = cipher.doFinal(data, IV_BYTES, data.length - IV_BYTES);
            JSONArray pair = new JSONArray(new String(clear, StandardCharsets.UTF_8));
            return new Login(pair.getString(0), pair.getString(1));
        }

        Login legacy = new Login(prefs.getString("socksUser", ""), prefs.getString("socksPassword", ""));
        if (!legacy.user().isEmpty() || !legacy.password().isEmpty()) {
            SharedPreferences.Editor edit = prefs.edit();
            write(edit, legacy.user(), legacy.password());
            edit.apply();
        }
        return legacy;
    }

    static void write(SharedPreferences.Editor edit, String user, String password)
        throws GeneralSecurityException, IOException {
        edit.remove("socksUser").remove("socksPassword");
        if (user.isEmpty() && password.isEmpty()) {
            edit.remove(FIELD);
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key(true));
        byte[] iv = cipher.getIV();
        if (iv.length != IV_BYTES) {
            throw new GeneralSecurityException("Unexpected GCM IV length");
        }
        String pair = new JSONArray().put(user).put(password).toString();
        byte[] encrypted = cipher.doFinal(pair.getBytes(StandardCharsets.UTF_8));
        byte[] envelope = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, envelope, 0, iv.length);
        System.arraycopy(encrypted, 0, envelope, iv.length, encrypted.length);
        edit.putString(FIELD, Base64.getEncoder().encodeToString(envelope));
    }

    private static synchronized SecretKey key(boolean create) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(STORE);
        store.load(null);
        if (store.getKey(ALIAS, null) instanceof SecretKey existing) {
            return existing;
        }
        if (!create) {
            throw new GeneralSecurityException("Credential key missing");
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
        generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build());
        return generator.generateKey();
    }
}
