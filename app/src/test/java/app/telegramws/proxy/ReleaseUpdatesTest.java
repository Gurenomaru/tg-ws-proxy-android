package app.telegramws.proxy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class ReleaseUpdatesTest {
    @Test
    public void stableVersionComparisonUsesNumericParts() {
        assertTrue(ReleaseUpdates.isNewer("0.2.10", "0.2.6"));
        assertTrue(ReleaseUpdates.isNewer("1.0.0", "0.9.9"));
        assertFalse(ReleaseUpdates.isNewer("0.2.5", "0.2.6"));
        assertFalse(ReleaseUpdates.isNewer("0.2.6", "0.2.6"));
        assertFalse(ReleaseUpdates.isNewer("0.2.7-beta.1", "0.2.6"));
        assertFalse(ReleaseUpdates.isNewer("../../download", "0.2.6"));
    }

    @Test
    public void requiresExactApkSizeAndSha256BeforeInstallation() throws IOException {
        var release = new ReleaseUpdates.Available("0.2.10", 3,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        var output = new ByteArrayOutputStream();
        byte[] valid = "abc".getBytes(StandardCharsets.US_ASCII);
        assertTrue(release.canDownload());
        UpdateApk.copyVerified(new ByteArrayInputStream(valid), output, release);
        assertArrayEquals(valid, output.toByteArray());
        for (String invalid : new String[]{"abd", "ab", "abcd"}) {
            var input = new ByteArrayInputStream(invalid.getBytes(StandardCharsets.US_ASCII));
            assertThrows(IOException.class, () -> UpdateApk.copyVerified(input, new ByteArrayOutputStream(), release));
        }
        assertFalse(new ReleaseUpdates.Available("0.2.10", 3, "").canDownload());
        assertFalse(new ReleaseUpdates.Available("0.2.10", UpdateApk.MAX_BYTES + 1, release.digest()).canDownload());
    }

    @Test
    public void restrictsAssetRedirectsToTheExpectedHttpsHosts() throws IOException {
        assertTrue(UpdateApk.allowedRedirect(new URL("https://release-assets.githubusercontent.com/example")));
        for (String invalid : new String[]{"http://release-assets.githubusercontent.com/example",
                "https://release-assets.githubusercontent.com.example.org/example",
                "https://user@release-assets.githubusercontent.com/example",
                "https://release-assets.githubusercontent.com:444/example"}) {
            assertFalse(UpdateApk.allowedRedirect(new URL(invalid)));
        }
    }
}
