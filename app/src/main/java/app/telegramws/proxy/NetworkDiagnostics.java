package app.telegramws.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;

final class NetworkDiagnostics {
    private static final int TIMEOUT_MS = 2800;
    private static final int PARALLELISM = 12;
    private static final short[] IMPORTANT_DCS = {2, -2, -4, 203};
    private static final String[] ALIASES = {"pluto", "venus", "aurora", "vesta", "flora"};
    private static volatile State state = new State(0, false, null);

    record State(int id, boolean running, File report) {}

    private record Check(String name, Routes.Target destination, short dc, String relay) {
        Check(String name, Routes.Target destination, short dc) {
            this(name, destination, dc, null);
        }
    }

    private record Outcome(String text, boolean success) {}

    static State status() {
        return state;
    }

    static synchronized void start(Context context, boolean includeCommunity) {
        if (state.running) {
            return;
        }
        Context application = context.getApplicationContext();
        int id = state.id + 1;
        state = new State(id, true, null);
        new Thread(() -> {
            File report = null;
            try {
                report = writeReport(application, includeCommunity);
            } catch (IOException | RuntimeException ignored) {
                // The screen reports an unavailable file without logging private details.
            } finally {
                state = new State(id, false, report);
            }
        }, "telegram-ws-diagnostics").start();
    }

    static File writeReport(Context context, boolean includeCommunity) throws IOException {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        Network network = manager.getActiveNetwork();
        Routes.Config config = new ProxySettings(context).load();
        var header = new StringBuilder("Telegram WS — расширенная диагностика\n")
            .append("Версия: ").append(BuildConfig.VERSION_NAME)
            .append(" (").append(BuildConfig.VERSION_CODE).append(")\n")
            .append("Android API: ").append(Build.VERSION.SDK_INT)
            .append("\nВремя UTC: ").append(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MINUTES))
            .append("\nСеть на старте: ").append(networkSummary(manager, network))
            .append("\nНастройки: публичные WSS=").append(config.community())
            .append(", Flowseal WS:80=").append(config.communityPlain())
            .append(", авторезерв Flowseal=").append(config.communityAuto())
            .append(", прямой TCP=").append(config.tcp())
            .append(", Cloudflare=").append(!config.cloudflare().isEmpty())
            .append(", Worker=").append(!config.worker().isEmpty())
            .append(", SOCKS5=").append(config.socks() != null)
            .append("\nПубличные домены в диагностике: ").append(includeCommunity)
            .append("\nНа каждое имя проверяется первый полученный адрес каждого семейства.\n")
            .append("MTProto OK означает проверенный ответ на служебный запрос без входа в аккаунт.\n");
        BackgroundPolicy.appendTo(context, header);
        ProxyTraffic traffic = ProxyStatus.traffic();
        long networkChanges = traffic.networkChanges();
        header.append("\nПрокси до сетевых проверок\n");
        ProxyStatus.appendTraffic(header);
        if (network == null) {
            return DiagnosticReport.save(context, header.append("\nАктивная сеть отсутствует.\n").toString());
        }

        var pool = Executors.newFixedThreadPool(PARALLELISM);
        try {
            appendChecks(header, "Контроль и прямые маршруты", pool, network, directChecks(), 65);
            List<Check> configured = configuredChecks(config);
            if (!configured.isEmpty()) {
                appendChecks(header, "Настроенные маршруты", pool, network, configured, 20);
            }
            if (includeCommunity) {
                var relays = communityChecks();
                var results = appendChecks(header, "Публичные домены Flowseal, DC2", pool, network, relays, 60);
                var candidates = new ArrayList<Check>();
                for (int i = 0; i < relays.size() && candidates.size() < 8; i++) {
                    Check relay = relays.get(i);
                    if (results.get(i).success) {
                        for (short dc : IMPORTANT_DCS) {
                            candidates.add(relayCheck(relay.relay, relay.destination.port(), dc));
                        }
                    }
                }
                if (!candidates.isEmpty()) {
                    appendChecks(header, "Повторный запрос, медиа и CDN", pool, network, candidates, 25);
                }
            }
            appendLocalProxy(header, pool, config);
        } finally {
            pool.shutdownNow();
        }
        header.append("\nПрокси после сетевых проверок\n");
        ProxyStatus.appendTraffic(header);
        Network endNetwork = manager.getActiveNetwork();
        boolean networkChanged = !Objects.equals(network, endNetwork) || traffic.networkChanges() != networkChanges;
        header.append("\nСеть при завершении: ").append(networkSummary(manager, endNetwork))
            .append("\nИзменения сети, замеченные приложением во время теста: ").append(networkChanged);
        if (networkChanged) {
            header.append("\nДля сравнения запустите тест снова на одной сети.");
        }
        return DiagnosticReport.save(context, header.append('\n').toString());
    }

    private static List<Check> directChecks() {
        var checks = new ArrayList<Check>();
        checks.add(check("HTTPS example.com", "example.com", "example.com", 443, null, null, (short) 0));
        checks.add(check("HTTPS www.cloudflare.com", "www.cloudflare.com", "www.cloudflare.com",
            443, null, null, (short) 0));
        for (int number = 1; number <= ALIASES.length; number++) {
            String alias = ALIASES[number - 1] + ".web.telegram.org";
            String host = "kws" + number + ".web.telegram.org";
            checks.add(check("WSS TDLib " + alias, alias, alias, 443, "/apiws", null, (short) number));
            checks.add(check("WSS Telegram " + host, host, host, 443, "/apiws", null, (short) number));
        }
        for (short media : new short[]{-2, -4}) {
            String host = "kws" + Math.abs(media) + "-1.web.telegram.org";
            String alias = ALIASES[Math.abs(media) - 1] + "-1.web.telegram.org";
            checks.add(check("WSS медиа " + host, host, host, 443, "/apiws", null, media));
            checks.add(check("WSS медиа " + alias, alias, alias, 443, "/apiws", null, media));
        }
        checks.add(check("WSS CDN203 через DC2", "kws2.web.telegram.org", "kws2.web.telegram.org",
            443, "/apiws", null, (short) 203));
        for (short dc : new short[]{1, 2, 3, 4, 5, 203}) {
            Routes.Dc decoded = Routes.Dc.fromWire(dc);
            String ipv4 = Routes.tcpAddress(decoded);
            String ipv6 = Routes.ipv6Address(decoded);
            for (int port : new int[]{443, 80, 5222}) {
                checks.add(check("TCP DC" + dc + " " + ipv4, ipv4, null, port, null, null, dc));
                if (ipv6 != null) {
                    checks.add(check("TCP DC" + dc + " " + ipv6, ipv6, null, port, null, null, dc));
                }
            }
        }
        String extraDc2 = "95.161.76.100";
        for (int port : new int[]{443, 80, 5222}) {
            checks.add(check("TCP DC2 " + extraDc2, extraDc2, null, port, null, null, (short) 2));
        }
        for (short dc : new short[]{2, -4}) {
            String ip = Routes.tcpAddress(Routes.Dc.fromWire(dc));
            checks.add(check("WS Telegram DC" + dc + " " + ip, ip, ip, 80, "/apiws", null, dc));
        }
        String fixed = "149.154.167.220";
        for (String name : new String[]{"web.telegram.org", "telegram.org", "sprinthost.ru"}) {
            checks.add(check("Штатный IPv4, TLS " + name, fixed, "kws2.web.telegram.org",
                443, "/apiws", name, (short) 2));
        }
        return checks;
    }

    private static List<Check> configuredChecks(Routes.Config config) {
        var checks = new ArrayList<Check>();
        for (short dc : IMPORTANT_DCS) {
            if (!config.cloudflare().isEmpty()) {
                String host = "kws" + Math.abs(dc) + "." + config.cloudflare();
                checks.add(check("Настроенный Cloudflare DC" + dc, host, host, 443, "/apiws", null, dc));
            }
            if (!config.worker().isEmpty()) {
                String address = Routes.tcpAddress(Routes.Dc.fromWire(dc));
                String path = "/apiws?dst=" + address + "&dc=" + Math.abs(dc);
                checks.add(check("Настроенный Worker DC" + dc, config.worker(), config.worker(), 443, path, null, dc));
            }
        }
        return checks;
    }

    private static List<Check> communityChecks() {
        var checks = new ArrayList<Check>();
        for (String domain : Routes.COMMUNITY) {
            checks.add(relayCheck(domain, 443, (short) 2));
            checks.add(relayCheck(domain, 80, (short) 2));
        }
        for (String domain : Routes.COMMUNITY.subList(0, 3)) {
            checks.add(relayCheck(domain, 8443, (short) 2));
        }
        return checks;
    }

    private static Check relayCheck(String domain, int port, short dc) {
        String host = "kws" + Math.abs(dc) + "." + domain;
        return new Check("Flowseal DC" + dc + " " + domain, target(host, host, port, "/apiws", null), dc, domain);
    }

    private static Check check(String name, String address, String host, int port, String path, String sni, short dc) {
        return new Check(name, target(address, host, port, path, sni), dc);
    }

    private static Routes.Target target(String address, String host, int port, String path, String sni) {
        return new Routes.Target(host, address, path, sni, "Диагностика", false, port);
    }

    private static List<Outcome> appendChecks(StringBuilder report, String title,
        java.util.concurrent.ExecutorService pool, Network network, List<Check> checks, int seconds)
        throws IOException {
        var jobs = new ArrayList<Callable<Outcome>>();
        for (Check check : checks) {
            jobs.add(() -> inspect(network, check));
        }
        report.append("\n").append(title).append("\n");
        var outcomes = new ArrayList<Outcome>();
        try {
            var futures = pool.invokeAll(jobs, seconds, TimeUnit.SECONDS);
            int successes = 0;
            for (int i = 0; i < futures.size(); i++) {
                var future = futures.get(i);
                Outcome outcome;
                if (future.isCancelled()) {
                    outcome = new Outcome(checks.get(i).name + " · лимит времени группы", false);
                } else {
                    try {
                        outcome = future.get();
                    } catch (ExecutionException e) {
                        outcome = new Outcome(checks.get(i).name + " · ошибка теста", false);
                    }
                }
                outcomes.add(outcome);
                report.append(outcome.text).append('\n');
                if (outcome.success) successes++;
            }
            report.append("Ответили: ").append(successes).append(" из ").append(checks.size()).append('\n');
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Диагностика прервана", e);
        }
        return outcomes;
    }

    private static Outcome inspect(Network network, Check check) {
        Routes.Target target = check.destination;
        var line = new StringBuilder(check.name).append(':').append(target.port());
        InetAddress[] addresses;
        try {
            addresses = network.getAllByName(target.address());
        } catch (IOException e) {
            return new Outcome(line.append(" · DNS ").append(error(e)).toString(), false);
        }
        boolean literal = target.address().contains(":") || target.address().matches("[0-9.]+");
        long ipv4 = Arrays.stream(addresses).filter(Inet4Address.class::isInstance).count();
        if (!literal) {
            line.append(" · DNS A=").append(ipv4).append(" AAAA=").append(addresses.length - ipv4);
        }
        boolean success = false;
        for (Class<? extends InetAddress> family : Arrays.asList(Inet4Address.class, Inet6Address.class)) {
            var address = Arrays.stream(addresses).filter(family::isInstance).findFirst();
            if (address.isPresent()) {
                success |= attempt(network, check, address.get(), line);
            }
        }
        return new Outcome(line.toString(), success);
    }

    private static boolean attempt(Network network, Check check, InetAddress address, StringBuilder line) {
        Routes.Target target = check.destination;
        line.append(" | IPv").append(address instanceof Inet4Address ? '4' : '6');
        String phase = "TCP";
        long started = System.nanoTime();
        try (Socket raw = network.getSocketFactory().createSocket()) {
            raw.setSoTimeout(TIMEOUT_MS);
            raw.connect(new InetSocketAddress(address, target.port()), TIMEOUT_MS);
            line.append(" TCP OK ").append(elapsed(started)).append(" мс");
            if (target.host() == null) {
                phase = "MTProto";
                ProxyProbe.verifyRaw(raw, check.dc);
            } else if (target.port() == 80) {
                phase = "WS";
                WebSocketWire ws = new WebSocketWire(raw, target);
                line.append(" WS 101");
                phase = "MTProto";
                ProxyProbe.verifyWebSocket(ws, check.dc);
            } else {
                phase = "TLS";
                long tlsStart = System.nanoTime();
                try (var tls = WebSocketWire.openTls(raw, target)) {
                    line.append(" TLS OK ").append(elapsed(tlsStart)).append(" мс")
                        .append(' ').append(tls.getSession().getProtocol());
                    if (!target.webSocket()) return true;
                    phase = "WSS";
                    var ws = new WebSocketWire(tls, target);
                    line.append(" WSS 101");
                    phase = "MTProto";
                    ProxyProbe.verifyWebSocket(ws, check.dc);
                }
            }
            line.append(" MTProto OK ").append(elapsed(started)).append(" мс всего");
            return true;
        } catch (IOException e) {
            line.append(' ').append(phase).append(' ').append(error(e))
                .append(" (").append(elapsed(started)).append(" мс всего)");
            return false;
        }
    }

    private static void appendLocalProxy(StringBuilder report, java.util.concurrent.ExecutorService pool,
        Routes.Config config) throws IOException {
        report.append("\nЛокальный прокси\n");
        if (ProxyStatus.snapshot().phase() != ProxyStatus.Phase.RUNNING) {
            report.append("На момент проверки прокси выключен.\n");
            return;
        }
        byte[] key = ProxySettings.key(config.secret());
        var checks = new ArrayList<Callable<String>>();
        for (short dc : IMPORTANT_DCS) {
            checks.add(() -> {
                try {
                    return "DC" + dc + " MTProto OK " + ProxyProbe.check(config.port(), key, dc) + " мс";
                } catch (IOException e) {
                    return "DC" + dc + " · " + error(e);
                }
            });
        }
        try {
            var results = pool.invokeAll(checks, 20, TimeUnit.SECONDS);
            for (int i = 0; i < results.size(); i++) {
                var future = results.get(i);
                report.append(future.isCancelled() ? "DC" + IMPORTANT_DCS[i] + " · лимит времени" : future.get())
                    .append('\n');
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Диагностика прервана", e);
        } catch (ExecutionException e) {
            report.append("Ошибка локальной проверки.\n");
        }
    }

    private static String networkSummary(ConnectivityManager manager, Network network) {
        if (network == null) return "отсутствует";
        NetworkCapabilities caps = manager.getNetworkCapabilities(network);
        LinkProperties links = manager.getLinkProperties(network);
        String transport = "другая";
        if (caps != null) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transport = "VPN";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transport = "Wi-Fi";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transport = "мобильная";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transport = "Ethernet";
        }
        return transport + ", проверена Android=" + (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            + ", IPv4=" + (links != null && links.getLinkAddresses().stream().anyMatch(l -> l.getAddress() instanceof Inet4Address))
            + ", IPv6=" + (links != null && links.getLinkAddresses().stream().anyMatch(l -> l.getAddress() instanceof Inet6Address))
            + ", NAT64=" + (links != null && Build.VERSION.SDK_INT >= 30 && links.getNat64Prefix() != null)
            + ", Private DNS=" + (links != null && Build.VERSION.SDK_INT >= 28 && links.isPrivateDnsActive());
    }

    private static String error(IOException failure) {
        if (failure instanceof SocketTimeoutException) return "тайм-аут";
        if (failure instanceof UnknownHostException) return "нет адреса";
        if (failure instanceof SSLException) return "ошибка TLS";
        if (failure instanceof ConnectException) return "отказ соединения";
        if (failure instanceof NoRouteToHostException) return "нет маршрута";
        if (failure instanceof EOFException) return "соединение закрыто";
        String message = failure.getMessage();
        if (message != null && message.matches("WebSocket HTTP [0-9]{3}")) {
            return message.substring("WebSocket ".length());
        }
        return "ошибка обмена";
    }

    private static long elapsed(long started) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
    }
}
