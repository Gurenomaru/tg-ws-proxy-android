package app.telegramws.proxy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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
}
