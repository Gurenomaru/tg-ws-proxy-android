package app.telegramws.proxy;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class RustProxyEngine implements ProxyRuntime {
    static {
        System.loadLibrary("telegramws_core");
    }

    private static final int[] DCS = {1, 2, 3, 4, 5, 203, 10001, 10002, 10003};

    private final long handle;
    private final int port;

    RustProxyEngine(Routes.Config config, byte[] secret, ProxyTraffic traffic) throws IOException {
        port = config.port();
        handle = nativeBind(port, secret, configJson(config), new Events(traffic));
    }

    @Override public int port() {
        return port;
    }

    @Override public void serve() throws IOException {
        nativeServe(handle);
    }

    @Override public void networkChanged(RouteHealth.Kind kind) {
        nativeNetworkChanged(handle, kind == RouteHealth.Kind.CELLULAR);
    }

    @Override public void close() {
        nativeClose(handle);
    }

    private static String configJson(Routes.Config config) throws IOException {
        try {
            JSONObject data = new JSONObject()
                .put("automatic", config.communityAuto())
                .put("routes", routePlans(config, RouteHealth.Kind.OTHER))
                .put("mobileRoutes", routePlans(config, RouteHealth.Kind.CELLULAR));
            Socks5.Endpoint socks = config.socks();
            if (socks != null) {
                data.put("socks", new JSONObject().put("host", socks.host()).put("port", socks.port())
                    .put("user", socks.user()).put("password", socks.password()));
            }
            return data.toString();
        } catch (JSONException e) {
            throw new IOException("Не удалось передать настройки Rust", e);
        }
    }

    private static JSONObject routePlans(Routes.Config config, RouteHealth.Kind network) throws JSONException {
        JSONObject plans = new JSONObject();
        for (int dc : DCS) {
            plans.put(Integer.toString(dc), routeGroups(config, network, (short) dc));
            plans.put(Integer.toString(-dc), routeGroups(config, network, (short) -dc));
        }
        return plans;
    }

    private static JSONArray routeGroups(Routes.Config config, RouteHealth.Kind network, short index)
        throws JSONException {
        Routes.Dc dc = Routes.Dc.fromWire(index);
        List<List<Routes.Stage>> groups = config.communityAuto() ? Routes.automaticGroups(dc, config, network)
            : Routes.ordered(dc, config, network, null).stream().map(Collections::singletonList)
                .collect(java.util.stream.Collectors.toList());
        JSONArray result = new JSONArray();
        for (List<Routes.Stage> group : groups) {
            JSONArray stages = new JSONArray();
            for (Routes.Stage stage : group) {
                JSONArray targets = new JSONArray();
                for (Routes.Target target : stage.targets()) {
                    targets.put(new JSONObject().put("host", target.host()).put("address", target.address())
                        .put("path", target.path()).put("sni", target.sni()).put("label", target.label())
                        .put("socks", target.socks()).put("port", target.port()).put("family", target.family().name()));
                }
                stages.put(new JSONObject().put("targets", targets).put("limit", stage.attemptLimit())
                    .put("publicRelay", stage.publicRelay()));
            }
            result.put(stages);
        }
        return result;
    }

    static final class Events {
        private static final ProxyTraffic.Event[] COUNTERS = ProxyTraffic.Event.values();
        private final ProxyTraffic traffic;

        Events(ProxyTraffic traffic) {
            this.traffic = traffic;
        }

        public void log(String text) {
            ProxyStatus.log(text);
        }

        public boolean isProbe(int port) {
            return ProxyProbe.isLocalProbe(port);
        }

        public void record(boolean probe, int event) {
            traffic.record(probe, COUNTERS[event]);
        }
    }

    private static native long nativeBind(int port, byte[] secret, String config, Events events) throws IOException;
    private static native void nativeServe(long handle) throws IOException;
    private static native void nativeClose(long handle);
    private static native void nativeNetworkChanged(long handle, boolean cellular);
}
