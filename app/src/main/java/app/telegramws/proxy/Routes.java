package app.telegramws.proxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

final class Routes {
    static final String LEGACY_DEFAULT_IPS = "2:149.154.167.220\n4:149.154.167.220";
    static final String DEFAULT_IPS = LEGACY_DEFAULT_IPS + "\n203:149.154.167.220";
    private static final int COMMUNITY_ATTEMPTS = 4;

    static String upgradedIps(String stored) {
        return LEGACY_DEFAULT_IPS.equals(stored.trim().replace("\r\n", "\n")) ? DEFAULT_IPS : stored;
    }
    // Published in Flowseal's fallback list. These are opt-in third-party relays.
    static final List<String> COMMUNITY = Arrays.asList(
        "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
        "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
        "sorokodin.co.uk", "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk",
        "nebally.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "fixtelega.co.uk",
        "sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk", "nothingthere.co.uk"
    );
    record Dc(int number, boolean media, boolean test) {
        static Dc fromWire(short signed) {
            int number = Math.abs((int) signed);
            boolean test = number >= 10000;
            return new Dc(test ? number - 10000 : number, signed < 0, test);
        }

        short relayId() {
            return (short) (media ? -number : number);
        }

        String label() {
            return "DC" + number + (media ? " media" : "") + (test ? " test" : "");
        }
    }

    enum Family { SYSTEM, IPV4, IPV6 }

    record Target(String host, String address, String path, String sni, String label, boolean socks,
                  int port, Family family) {
        Target(String host, String address, String path, String sni, String label, boolean socks, int port) {
            this(host, address, path, sni, label, socks, port, Family.SYSTEM);
        }
        Target(String host, String address, String path, String sni, String label) {
            this(host, address, path, sni, label, false, 443);
        }

        Target(String host, String address, String path, String sni, String label, boolean socks) {
            this(host, address, path, sni, label, socks, 443);
        }

        String description() {
            if (socks || label.startsWith("Cloudflare")) {
                return label;
            }
            return label + " · " + host + (sni == null ? "" : " · TLS " + sni);
        }

        boolean webSocket() {
            return path != null;
        }
    }

    record Config(int port, String secret, Map<Integer, String> overrides, String cloudflare,
                  String worker, boolean community, boolean tcp, Socks5.Endpoint socks, boolean socksFirst,
                  boolean communityPlain, boolean communityAuto) {}

    record Stage(List<Target> targets, int attemptLimit) {
        Stage(List<Target> targets) {
            this(targets, targets.size());
        }

        Stage(Target target) {
            this(Collections.singletonList(target));
        }
    }

    static List<Stage> candidates(Dc dc, Config config) {
        List<Stage> stages = new ArrayList<>();
        String tcp = tcpAddress(dc);
        if (tcp == null) {
            return stages;
        }
        String path = dc.test ? "/apiws_test" : "/apiws";
        int webDc = dc.number == 203 ? 2 : dc.number;
        String host = "kws" + webDc + ".web.telegram.org";
        String mediaHost = "kws" + webDc + "-1.web.telegram.org";
        List<Target> telegram = new ArrayList<>();
        String override = config.overrides.get(dc.number);
        if (override != null) {
            if (dc.media) {
                telegram.add(new Target(mediaHost, override, path, "web.telegram.org", "WSS Telegram"));
            }
            telegram.add(new Target(host, override, path, "web.telegram.org", "WSS Telegram"));
            telegram.add(new Target(host, override, path, "telegram.org", "WSS Telegram"));
            telegram.add(new Target(host, override, path, "sprinthost.ru", "WSS Telegram"));
            telegram.add(new Target(host, override, path, null, "WSS Telegram"));
        }
        if (dc.media) {
            addDnsRoutes(telegram, mediaHost, path);
        }
        addDnsRoutes(telegram, host, path);
        stages.add(new Stage(telegram));
        if (config.socks != null) {
            Target viaSocks = new Target(tcp, tcp, null, null, "TCP через SOCKS5", true);
            stages.add(config.socksFirst ? 0 : 1, new Stage(viaSocks));
        }
        if (config.communityPlain && !dc.test) {
            int relayPosition = config.socks != null && config.socksFirst ? 1 : 0;
            stages.add(relayPosition, community(dc, 80));
        }
        if (!config.worker.isEmpty()) {
            stages.add(new Stage(new Target(config.worker, config.worker,
                "/apiws?dst=" + tcp + "&dc=" + dc.number, null, "Cloudflare Worker")));
        }
        if (!dc.test) {
            if (!config.cloudflare.isEmpty()) {
                stages.add(new Stage(cloudflare(dc, config.cloudflare, 443)));
            }
            if (config.community) {
                stages.add(community(dc, 443));
            }
        }
        if (config.tcp) {
            Target ipv4 = new Target(tcp, tcp, null, null, "TCP Telegram");
            String ipv6 = ipv6Address(dc);
            stages.add(ipv6 == null ? new Stage(ipv4) : new Stage(Arrays.asList(ipv4,
                new Target(ipv6, ipv6, null, null, "TCP Telegram IPv6"))));
        }
        if (config.communityAuto && !dc.test) {
            if (!config.community) {
                stages.add(community(dc, 443));
            }
            if (!config.communityPlain) {
                stages.add(community(dc, 80));
            }
        }
        return stages;
    }

    static List<Stage> ordered(Dc dc, Config config, Target preferred) {
        List<Stage> stages = candidates(dc, config);
        if (!config.communityAuto || preferred == null) {
            return stages;
        }
        int first = config.socks != null && config.socksFirst ? 1 : 0;
        if (config.communityPlain && !dc.test) {
            first++;
        }
        for (int i = first + 1; i < stages.size(); i++) {
            Stage stage = stages.get(i);
            if (!stage.targets.contains(preferred)) {
                continue;
            }
            List<Target> rest = new ArrayList<>(stage.targets);
            rest.remove(preferred);
            if (rest.isEmpty()) {
                stages.remove(i);
            } else {
                stages.set(i, new Stage(rest, Math.min(stage.attemptLimit, rest.size())));
            }
            stages.add(first, new Stage(preferred));
            break;
        }
        return stages;
    }

    private static void addDnsRoutes(List<Target> targets, String host, String path) {
        targets.add(new Target(host, host, path, null, "WSS Telegram IPv6", false, 443, Family.IPV6));
        targets.add(new Target(host, host, path, null, "WSS Telegram IPv4", false, 443, Family.IPV4));
    }

    static String ipv6Address(Dc dc) {
        if (dc.test) {
            return null;
        }
        return switch (dc.number) {
            case 1 -> "2001:b28:f23d:f001::a";
            case 2 -> "2001:67c:4e8:f002::a";
            case 3 -> "2001:b28:f23d:f003::a";
            case 4 -> "2001:67c:4e8:f004::a";
            case 5 -> "2001:b28:f23f:f005::a";
            default -> null;
        };
    }

    static String tcpAddress(Dc dc) {
        if (dc.test) {
            return switch (dc.number) {
                case 1 -> "149.154.175.10";
                case 2 -> "149.154.167.40";
                case 3 -> "149.154.175.117";
                default -> null;
            };
        }
        return switch (dc.number) {
            case 1 -> "149.154.175.50";
            case 2 -> "149.154.167.51";
            case 3 -> "149.154.175.100";
            case 4 -> "149.154.167.91";
            case 5 -> "149.154.171.5";
            case 203 -> "91.105.192.100";
            default -> null;
        };
    }

    private static Stage community(Dc dc, int port) {
        List<Target> relays = new ArrayList<>();
        for (String domain : COMMUNITY) {
            relays.add(cloudflare(dc, domain, port));
        }
        return new Stage(relays, COMMUNITY_ATTEMPTS);
    }

    private static Target cloudflare(Dc dc, String domain, int port) {
        String host = "kws" + dc.number + "." + domain;
        String label = port == 80 ? "Cloudflare WS · порт 80" : "Cloudflare WSS";
        return new Target(host, host, "/apiws", null, label, false, port);
    }
}
