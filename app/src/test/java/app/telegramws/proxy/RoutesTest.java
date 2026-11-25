package app.telegramws.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.List;
import org.junit.Test;

public final class RoutesTest {
    @Test
    public void upgradesOnlyTheOldPreset() {
        assertEquals(Routes.DEFAULT_IPS, Routes.upgradedIps(Routes.LEGACY_DEFAULT_IPS));
        assertEquals(Routes.DEFAULT_IPS, Routes.upgradedIps(Routes.LEGACY_DEFAULT_IPS.replace("\n", "\r\n")));
        assertEquals("", Routes.upgradedIps(""));
        assertEquals("4:149.154.167.220", Routes.upgradedIps("4:149.154.167.220"));
        assertEquals("203:91.105.192.100", Routes.upgradedIps("203:91.105.192.100"));
    }

    @Test
    public void triesMediaHostFirstButPreservesCdnNumberInTheRelay() {
        Routes.Config config = new Routes.Config(1443, "", Collections.singletonMap(203, "149.154.167.220"),
            "", "", false, true, null, false, false, false);
        Routes.Dc cdn = Routes.Dc.fromWire((short) -203);
        List<Routes.Stage> stages = Routes.candidates(cdn, config);
        List<Routes.Target> direct = stages.get(0).targets();
        assertEquals("kws2-1.web.telegram.org", direct.get(0).host());
        assertEquals("149.154.167.220", direct.get(0).address());
        assertEquals("/apiws", direct.get(0).path());
        assertTrue(direct.stream().anyMatch(route -> route.host().equals("kws2.web.telegram.org")));
        assertEquals(-203, cdn.relayId());
        assertEquals("91.105.192.100", stages.get(1).targets().get(0).address());
        assertTrue(Routes.DEFAULT_IPS.contains("203:149.154.167.220"));
    }

    @Test
    public void explicitMobileModePrefersPlainCommunityWebSocket() {
        Routes.Config mobile = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", false, true, null, false, true, false);
        var dc = Routes.Dc.fromWire((short) -4);
        var routes = Routes.candidates(dc, mobile);
        var target = routes.get(0).targets().get(0);
        assertEquals("kws4.pclead.co.uk", target.host());
        assertEquals(80, target.port());
        assertEquals("/apiws", target.path());
        assertEquals(443, routes.get(1).targets().get(0).port());
        var fallback = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", true, false, null, false, false, false);
        var secure = Routes.candidates(dc, fallback);
        assertEquals(443, secure.get(1).targets().get(0).port());
    }
    @Test
    public void automaticFallbackUsesPlainOnlyAfterDirectAndSecureThenReusesWorkingRoute() {
        Routes.Config auto = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", false, true, null, false, false, true);
        var dc = Routes.Dc.fromWire((short) 2);
        var fresh = Routes.ordered(dc, auto, null);
        assertEquals("WSS Telegram IPv6", fresh.get(0).targets().get(0).label());
        assertEquals(443, fresh.get(2).targets().get(0).port());
        var relay = fresh.get(3).targets().get(0);
        assertEquals(80, relay.port());
        var remembered = Routes.ordered(dc, auto, relay);
        assertEquals(Collections.singletonList(relay), remembered.get(0).targets());
        assertEquals(1, remembered.stream().flatMap(stage -> stage.targets().stream()).filter(relay::equals).count());
    }
}
