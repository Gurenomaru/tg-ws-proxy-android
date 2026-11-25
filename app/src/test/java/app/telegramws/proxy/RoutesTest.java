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
        var fresh = Routes.ordered(dc, auto, RouteHealth.Kind.WIFI, null);
        assertEquals("WSS Telegram IPv6", fresh.get(0).targets().get(0).label());
        assertEquals(443, fresh.get(2).targets().get(0).port());
        var relay = fresh.get(3).targets().get(0);
        assertEquals(80, relay.port());
        var remembered = Routes.ordered(dc, auto, RouteHealth.Kind.WIFI, relay);
        assertEquals(Collections.singletonList(relay), remembered.get(0).targets());
        assertEquals(1, remembered.stream().flatMap(stage -> stage.targets().stream()).filter(relay::equals).count());
    }
    @Test
    public void automaticMobileStartsWithTheSameRoutesAsManualMobileMode() {
        Routes.Config auto = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", false, true, null, false, false, true);
        Routes.Config manual = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", false, true, null, false, true, false);
        for (short dcId : new short[]{2, -2, -4, 203}) {
            var dc = Routes.Dc.fromWire(dcId);
            var direct = Routes.candidates(dc, auto).get(0).targets().get(0);
            var manualFirst = Routes.candidates(dc, manual).get(0);
            var automatic = Routes.ordered(dc, auto, RouteHealth.Kind.CELLULAR, direct);
            assertEquals(manualFirst, automatic.get(0));
            assertEquals(80, automatic.get(0).targets().get(0).port());
            assertTrue(automatic.get(1).targets().contains(direct));
            assertEquals(1, automatic.stream().filter(stage -> stage.equals(manualFirst)).count());
        }
    }

    @Test
    public void mobilePreferencePreservesOptInAndExplicitProxySettings() {
        var dc = Routes.Dc.fromWire((short) 2);
        Routes.Config declined = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", false, true, null, false, false, false);
        assertEquals(Routes.candidates(dc, declined),
            Routes.ordered(dc, declined, RouteHealth.Kind.CELLULAR, null));
        Routes.Config configured = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "worker.example.org", false, true, null, false, false, true);
        assertEquals(Routes.candidates(dc, configured),
            Routes.ordered(dc, configured, RouteHealth.Kind.CELLULAR, null));
        Routes.Config socksFirst = new Routes.Config(1443, "", Collections.emptyMap(),
            "", "", false, true, Socks5.parse("127.0.0.1:1080", "", ""), true, false, true);
        var ordered = Routes.ordered(dc, socksFirst, RouteHealth.Kind.CELLULAR, null);
        assertTrue(ordered.get(0).targets().get(0).socks());
        assertEquals(80, ordered.get(1).targets().get(0).port());
    }
}
