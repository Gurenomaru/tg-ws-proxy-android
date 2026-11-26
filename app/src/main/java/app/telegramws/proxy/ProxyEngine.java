package app.telegramws.proxy;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.LongConsumer;
import javax.net.ssl.SSLException;

final class ProxyEngine implements Closeable {
    private static final int CLIENT_LIMIT = 24;
    private static final int CONNECT_TIMEOUT = 3500;
    private static final long ROUTE_HEAD_START = TimeUnit.MILLISECONDS.toNanos(220);
    private static final long VERIFIED_HEAD_START = TimeUnit.MILLISECONDS.toNanos(900);
    private static final long PUBLIC_SCAN_BUDGET = TimeUnit.MILLISECONDS.toNanos(2500);
    private static final long DIRECT_SCAN_BUDGET = TimeUnit.MILLISECONDS.toNanos(1600);
    private static final long COMPARISON_WINDOW = TimeUnit.MILLISECONDS.toNanos(180);
    private static final long LIVE_ROUTE_BUDGET = TimeUnit.MILLISECONDS.toNanos(1000);
    private static final long AUTO_DIAL_BUDGET = TimeUnit.MILLISECONDS.toNanos(1600);
    private static final long AUTO_SELECTION_BUDGET = TimeUnit.MILLISECONDS.toNanos(6500);
    private static final long SCAN_TTL = TimeUnit.MINUTES.toNanos(5);
    private static final long FAILED_SCAN_TTL = TimeUnit.SECONDS.toNanos(30);
    private static final int FIRST_REPLY_TIMEOUT = 6000;
    private final Routes.Config config;
    private final byte[] secret;
    private final Consumer<String> log;
    private final ProxyTraffic traffic;
    private final RelayWatchdog.Timing watchdogTiming;
    private final ServerSocket listener;
    private final ExecutorService clients = Executors.newFixedThreadPool(CLIENT_LIMIT);
    private final ExecutorService reverse = Executors.newFixedThreadPool(CLIENT_LIMIT);
    private final ExecutorService dialing = new ThreadPoolExecutor(24, 24, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(96));
    private final ThreadPoolExecutor measurements = new ThreadPoolExecutor(24, 24, 20, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(64));
    private final ScheduledThreadPoolExecutor deadlines = new ScheduledThreadPoolExecutor(1);
    private final Object networkLock = new Object();
    private final Set<Session> sessions = ConcurrentHashMap.newKeySet();
    private final Semaphore capacity = new Semaphore(CLIENT_LIMIT);
    private final RouteHealth.ByNetwork routeHistory = new RouteHealth.ByNetwork();
    private RouteHealth routes = new RouteHealth();
    private final AtomicInteger rotation = new AtomicInteger();
    private volatile boolean stopped;

    ProxyEngine(Routes.Config config, byte[] secret, Consumer<String> log, ProxyTraffic traffic) throws IOException {
        this(config, secret, log, traffic, RelayWatchdog.DEFAULT);
    }

    ProxyEngine(Routes.Config config, byte[] secret, Consumer<String> log, ProxyTraffic traffic,
                RelayWatchdog.Timing watchdogTiming) throws IOException {
        this.traffic = traffic;
        this.watchdogTiming = watchdogTiming;
        this.config = config;
        this.secret = secret;
        this.log = log;
        deadlines.setRemoveOnCancelPolicy(true);
        measurements.allowCoreThreadTimeOut(true);
        listener = new ServerSocket();
        try {
            listener.bind(new InetSocketAddress("127.0.0.1", config.port()), 32);
        } catch (IOException e) {
            quietlyClose(listener);
            throw e;
        }
    }

    int port() {
        return listener.getLocalPort();
    }

    void serve() throws IOException {
        while (!stopped) {
            Socket socket = listener.accept();
            boolean probe = ProxyProbe.isLocalProbe(socket.getPort());
            traffic.record(probe, ProxyTraffic.Event.OPENED);
            if (!capacity.tryAcquire()) {
                traffic.record(probe, ProxyTraffic.Event.LIMIT);
                quietlyClose(socket);
                continue;
            }
            Session session;
            synchronized (networkLock) {
                if (stopped) {
                    quietlyClose(socket);
                    capacity.release();
                    return;
                }
                session = new Session(socket, routes, probe);
                sessions.add(session);
            }
            try {
                clients.execute(() -> handle(session));
            } catch (RejectedExecutionException e) {
                release(session);
            }
        }
    }

    private void handle(Session session) {
        Routes.Dc dc = null;
        try {
            Socket client = session.client;
            client.setTcpNoDelay(true);
            client.setSoTimeout(7000);
            InputStream input = client.getInputStream();
            byte[] header = MtProto.readExact(input, MtProto.HEADER_SIZE);
            MtProto.Hello hello;
            try {
                hello = MtProto.accept(header, secret);
            } catch (IOException error) {
                traffic.record(session.probe, ProxyTraffic.Event.INVALID);
                throw error;
            }
            traffic.record(session.probe, ProxyTraffic.Event.ACCEPTED);
            Routes.Dc targetDc = Routes.Dc.fromWire(hello.dc());
            dc = targetDc;
            client.setSoTimeout(0);

            long selectionStarted = System.nanoTime();
            Connected connected = selectRoute(session, dc);
            long selectionMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - selectionStarted);
            if (connected == null) {
                if (!session.isClosed()) {
                    traffic.record(session.probe, ProxyTraffic.Event.NO_ROUTE);
                    if (session.routes.reportNoRoute(dc, System.nanoTime())) {
                        log.accept(dc.label() + " · нет доступного маршрута");
                    }
                }
                return;
            }

            MtProto.Outbound relay = MtProto.initiate(hello.mode(), dc.relayId(), null);
            if (connected.webSocket == null) {
                connected.socket.getOutputStream().write(relay.header());
            } else {
                connected.webSocket.send(relay.header());
            }

            log.accept(dc.label() + " · " + connected.target.description() + " · выбор " + selectionMillis + " мс");
            Socket upstream = connected.socket;
            RelayWatchdog watchdog = new RelayWatchdog(deadlines, dialing,
                connected.webSocket == null ? null : connected.webSocket::ping,
                since -> recoverStalledSession(session, targetDc, connected, since), watchdogTiming);
            if (!session.watch(watchdog)) {
                return;
            }
            reverse.execute(() -> readUpstream(session, connected, targetDc, hello, relay, watchdog));
            Runnable timeout = () -> {
                if (recordUnanswered(session, targetDc, connected)) {
                    log.accept(targetDc.label() + " · " + connected.target.label() + " · нет первого ответа");
                    quietlyClose(session);
                }
            };
            byte[] buffer = new byte[32 * 1024];
            while (!stopped) {
                if (connected.webSocket != null) {
                    byte[] packet = MtProto.readPacket(input, hello.incoming(), hello.mode());
                    if (session.watchReply(deadlines, timeout)) {
                        traffic.record(session.probe, ProxyTraffic.Event.REQUEST);
                    }
                    watchdog.sent();
                    connected.webSocket.send(relay.sending().update(packet));
                } else {
                    int count = input.read(buffer);
                    if (count == -1) {
                        upstream.shutdownOutput();
                        session.awaitDownstream();
                        break;
                    }
                    if (session.watchReply(deadlines, timeout)) {
                        traffic.record(session.probe, ProxyTraffic.Event.REQUEST);
                    }
                    watchdog.sent();
                    byte[] clear = hello.incoming().update(buffer, 0, count);
                    upstream.getOutputStream().write(relay.sending().update(clear));
                }
            }
        } catch (EOFException | SocketException | RejectedExecutionException ignored) {
            // Either side can close a connection without sending a final MTProto packet.
        } catch (IOException e) {
            if (!stopped) {
                log.accept((dc == null ? "Подключение" : dc.label()) + " · " + connectionError(e));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            release(session);
        }
    }

    private void readUpstream(Session session, Connected connected, Routes.Dc dc,
                              MtProto.Hello hello, MtProto.Outbound relay, RelayWatchdog watchdog) {
        try {
            OutputStream output = session.client.getOutputStream();
            InputStream input = connected.socket.getInputStream();
            byte[] buffer = new byte[32 * 1024];
            LongConsumer pong = watchdog::pong;
            while (!stopped) {
                int count = connected.webSocket == null ? input.read(buffer) : connected.webSocket.receive(buffer, pong);
                if (count == -1) {
                    return;
                }
                watchdog.received();
                byte[] clear = relay.receiving().update(buffer, 0, count);
                output.write(hello.outgoing().update(clear));
                if (session.receivedReply()) {
                    traffic.record(session.probe, ProxyTraffic.Event.REPLY);
                    session.routes.succeeded(dc, connected.target);
                }
            }
        } catch (IOException e) {
            if (connected.webSocket != null && !session.isClosed() && !(e instanceof SocketException)) {
                log.accept(dc.label() + " · WSS · " + connectionError(e));
            }
        } finally {
            recordUnanswered(session, dc, connected);
            quietlyClose(session);
        }
    }

    private void recoverStalledSession(Session session, Routes.Dc dc, Connected connected, long since) {
        synchronized (session) {
            if (session.isClosed()) {
                return;
            }
            session.routes.failed(dc, connected.target, since, System.nanoTime(), config.communityAuto());
            traffic.record(session.probe, ProxyTraffic.Event.STALL);
            session.close();
        }
        log.accept(dc.label() + " · " + connected.target.label() + " · зависшее соединение закрыто");
    }

    private boolean recordUnanswered(Session session, Routes.Dc dc, Connected connected) {
        if (!session.unanswered()) {
            return false;
        }
        traffic.record(session.probe, ProxyTraffic.Event.NO_REPLY);
        session.routes.failed(dc, connected.target, session.started, System.nanoTime(), config.communityAuto());
        return true;
    }

    private Connected selectRoute(Session session, Routes.Dc dc) throws InterruptedException {
        if (config.communityAuto()) {
            return selectAutomaticRoute(session, dc);
        }

        // Some servers can forward Telegram traffic even when the synthetic request gets no reply.
        Routes.Target previous = session.routes.preferred(dc);
        for (Routes.Stage stage : Routes.ordered(dc, config, session.routes.kind, previous)) {
            if (session.isClosed()) {
                return null;
            }
            List<Routes.Target> choices = new ArrayList<>(stage.targets());
            long now = System.nanoTime();
            choices.removeIf(target -> !session.routes.ready(dc, target, now));
            int limit = stage.attemptLimit();
            if (choices.size() > limit) {
                Collections.rotate(choices, -Math.floorMod(rotation.getAndAdd(limit), choices.size()));
            }
            if (choices.remove(previous)) {
                choices.add(0, previous);
            }
            if (choices.isEmpty()) {
                continue;
            }
            Connected picked = race(session, dc, choices.subList(0, Math.min(limit, choices.size())));
            if (picked == null && !session.isClosed()) {
                long retryAt = System.nanoTime();
                for (Routes.Target target : choices) {
                    if (target.sni() != null && session.routes.ready(dc, target, retryAt)) {
                        picked = race(session, dc, Collections.singletonList(target));
                        break;
                    }
                }
            }
            if (picked != null) {
                return picked;
            }
        }
        return null;
    }

    private Connected selectAutomaticRoute(Session session, Routes.Dc dc) throws InterruptedException {
        List<List<Routes.Stage>> groups = Routes.automaticGroups(dc, config, session.routes.kind);
        long now = System.nanoTime();
        long deadline = now + AUTO_SELECTION_BUDGET;
        Routes.Target live = session.routes.preferredOnCurrentNetwork(dc);
        if (live != null && session.routes.ready(dc, live, now)) {
            Connected picked = race(session, dc, Collections.singletonList(live), now + LIVE_ROUTE_BUDGET);
            if (picked != null) {
                return picked;
            }
        }

        for (List<Routes.Stage> group : groups) {
            RouteHealth.Ranking cached = session.routes.scan(dc, group).ranking;
            if (cached.fresh(System.nanoTime())) {
                Connected picked = connectRanked(session, dc, cached.targets(), deadline);
                if (picked != null) {
                    return picked;
                }
            }
        }
        for (List<Routes.Stage> group : groups) {
            List<Routes.Target> ranked = measuredRoutes(session, dc, group, deadline);
            Connected picked = connectRanked(session, dc, ranked, deadline);
            if (picked != null) {
                return picked;
            }
        }

        // Some servers can forward Telegram traffic even when an unauthenticated probe fails.
        for (List<Routes.Stage> group : groups) {
            if (session.isClosed() || System.nanoTime() - deadline >= 0) {
                return null;
            }
            Routes.Target previous = session.routes.preferred(dc);
            List<Routes.Target> choices = sampleRoutes(session, dc, group, previous);
            if (!choices.isEmpty()) {
                long attemptDeadline = Math.min(deadline, System.nanoTime() + AUTO_DIAL_BUDGET);
                Connected picked = race(session, dc, choices, attemptDeadline);
                if (picked != null) {
                    return picked;
                }
            }
        }
        return null;
    }

    private Connected connectRanked(Session session, Routes.Dc dc, List<Routes.Target> ranked, long deadline)
        throws InterruptedException {
        long now = System.nanoTime();
        if (ranked.isEmpty() || session.isClosed() || now - deadline >= 0) {
            return null;
        }
        List<Routes.Target> available = new ArrayList<>(ranked);
        available.removeIf(target -> !session.routes.ready(dc, target, now));
        if (available.isEmpty()) {
            return null;
        }
        long attemptDeadline = Math.min(deadline, now + AUTO_DIAL_BUDGET);
        return race(session, dc, available, attemptDeadline, ROUTE_HEAD_START);
    }

    private List<Routes.Target> measuredRoutes(Session session, Routes.Dc dc, List<Routes.Stage> group, long deadline)
        throws InterruptedException {
        RouteHealth.GroupScan scan = session.routes.scan(dc, group);
        synchronized (scan) {
            long now = System.nanoTime();
            RouteHealth.Ranking cached = scan.ranking;
            if (session.isClosed() || now - deadline >= 0) {
                return Collections.emptyList();
            }
            if (cached.fresh(now) && (cached.targets().isEmpty()
                || cached.targets().stream().anyMatch(target -> session.routes.ready(dc, target, now)))) {
                return cached.targets();
            }
            Routes.Target previous = cached.targets().isEmpty() ? session.routes.preferred(dc) : cached.targets().get(0);
            List<Routes.Target> choices = sampleRoutes(session, dc, group, previous);
            long budget = group.get(0).publicRelay() ? PUBLIC_SCAN_BUDGET : DIRECT_SCAN_BUDGET;
            long scanDeadline = Math.min(deadline, now + budget);
            List<Routes.Target> ranked = rankRoutes(dc, choices, session, scanDeadline);
            if (!session.isClosed() && (!ranked.isEmpty() || deadline - now >= budget)) {
                scan.ranking = new RouteHealth.Ranking(ranked,
                    System.nanoTime() + (ranked.isEmpty() ? FAILED_SCAN_TTL : SCAN_TTL));
            }
            return ranked;
        }
    }

    private List<Routes.Target> sampleRoutes(Session session, Routes.Dc dc, List<Routes.Stage> group,
                                              Routes.Target previous) {
        List<Routes.Target> choices = new ArrayList<>();
        long now = System.nanoTime();
        for (Routes.Stage stage : group) {
            List<Routes.Target> available = new ArrayList<>(stage.targets());
            available.removeIf(target -> !session.routes.ready(dc, target, now));
            int limit = stage.attemptLimit();
            if (available.size() > limit) {
                Collections.rotate(available, -Math.floorMod(rotation.getAndAdd(limit), available.size()));
            }
            if (available.remove(previous)) {
                available.add(0, previous);
            }
            choices.addAll(available.subList(0, Math.min(limit, available.size())));
        }
        if (choices.remove(previous)) {
            choices.add(0, previous);
        }
        return choices;
    }

    private List<Routes.Target> rankRoutes(Routes.Dc dc, List<Routes.Target> candidates, Session session, long deadline)
        throws InterruptedException {
        ExecutorCompletionService<RouteTiming> results = new ExecutorCompletionService<>(measurements);
        List<Future<RouteTiming>> pending = new ArrayList<>();
        List<Socket> sockets = new ArrayList<>();
        List<RouteTiming> timings = new ArrayList<>();
        try {
            for (Routes.Target target : candidates) {
                Socket socket = new Socket(Proxy.NO_PROXY);
                if (!session.add(socket)) {
                    quietlyClose(socket);
                    return Collections.emptyList();
                }
                sockets.add(socket);
                try {
                    pending.add(results.submit(() -> {
                        long started = System.nanoTime();
                        Connected connected = dial(target, socket);
                        socket.setSoTimeout((int) TimeUnit.NANOSECONDS.toMillis(PUBLIC_SCAN_BUDGET));
                        if (connected.webSocket == null) {
                            ProxyProbe.verifyRaw(socket, dc.relayId());
                        } else {
                            ProxyProbe.verifyWebSocket(connected.webSocket, dc.relayId());
                        }
                        return new RouteTiming(target, System.nanoTime() - started);
                    }));
                } catch (RejectedExecutionException ignored) {
                    // A busy proxy can still try the routes it already measured.
                }
            }

            long comparisonDeadline = deadline;
            for (int i = 0; i < pending.size() && !session.isClosed(); i++) {
                long remaining = Math.max(0, comparisonDeadline - System.nanoTime());
                Future<RouteTiming> result = results.poll(remaining, TimeUnit.NANOSECONDS);
                if (result == null) {
                    break;
                }
                try {
                    timings.add(result.get());
                    if (timings.size() == 1) {
                        comparisonDeadline = Math.min(deadline, System.nanoTime() + COMPARISON_WINDOW);
                    }
                } catch (ExecutionException ignored) {
                    // Only routes with a verified MTProto reply qualify for the ranking.
                }
            }
        } finally {
            pending.forEach(future -> future.cancel(true));
            for (Socket socket : sockets) {
                session.remove(socket);
                quietlyClose(socket);
            }
        }
        return orderedByResponse(timings, candidates);
    }

    static List<Routes.Target> orderedByResponse(List<RouteTiming> timings, List<Routes.Target> candidates) {
        List<RouteTiming> ordered = new ArrayList<>(timings);
        ordered.sort(Comparator.comparingLong(RouteTiming::elapsedNanos)
            .thenComparingInt(timing -> candidates.indexOf(timing.target)));
        List<Routes.Target> targets = new ArrayList<>(ordered.size());
        for (RouteTiming timing : ordered) {
            targets.add(timing.target);
        }
        return Collections.unmodifiableList(targets);
    }

    record RouteTiming(Routes.Target target, long elapsedNanos) {}

    private Connected race(Session session, Routes.Dc dc, List<Routes.Target> targets)
        throws InterruptedException {
        return race(session, dc, targets, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CONNECT_TIMEOUT + 550));
    }

    private Connected race(Session session, Routes.Dc dc, List<Routes.Target> targets, long deadline)
        throws InterruptedException {
        long headStart = config.communityAuto() && targets.get(0).equals(session.routes.preferred(dc))
            ? VERIFIED_HEAD_START : ROUTE_HEAD_START;
        return race(session, dc, targets, deadline, headStart);
    }

    private Connected race(Session session, Routes.Dc dc, List<Routes.Target> targets, long deadline, long headStart)
        throws InterruptedException {
        ExecutorCompletionService<Connected> results = new ExecutorCompletionService<>(dialing);
        Map<Future<Connected>, PendingAttempt> attempts = new HashMap<>();
        List<Socket> sockets = new ArrayList<>();
        Connected winner = null;
        List<String> errors = new ArrayList<>();
        long nextLaunch = System.nanoTime();
        int launched = 0;
        int completed = 0;
        try {
            while (!session.isClosed()) {
                long now = System.nanoTime();
                if (now - deadline >= 0) {
                    errors.add("тайм-аут");
                    if (config.communityAuto()) {
                        for (var entry : attempts.entrySet()) {
                            if (!entry.getKey().isDone()) {
                                PendingAttempt attempt = entry.getValue();
                                session.routes.failed(dc, attempt.target, attempt.started, now, true);
                            }
                        }
                    }
                    break;
                }
                boolean hasAlternatives = launched < targets.size();
                if (hasAlternatives && (now - nextLaunch >= 0 || launched == completed)) {
                    Routes.Target target = targets.get(launched++);
                    Socket socket = new Socket(Proxy.NO_PROXY);
                    sockets.add(socket);
                    if (!session.add(socket)) {
                        return null;
                    }
                    try {
                        attempts.put(results.submit(() -> dial(target, socket)), new PendingAttempt(target, now));
                    } catch (RejectedExecutionException ignored) {
                        // Other attempts in this race can still succeed if the dial queue is full.
                        completed++;
                        session.remove(socket);
                        quietlyClose(socket);
                    }
                    nextLaunch = launched == 1 ? now + headStart : now;
                    continue;
                }
                if (launched == completed) {
                    break;
                }
                long wakeAt = hasAlternatives ? nextLaunch : deadline;
                Future<Connected> result = results.poll(Math.max(0, wakeAt - now), TimeUnit.NANOSECONDS);
                if (result == null) {
                    continue;
                }
                completed++;
                try {
                    winner = result.get();
                    return winner;
                } catch (ExecutionException e) {
                    if (!session.isClosed()) {
                        PendingAttempt failed = attempts.get(result);
                        session.routes.failed(dc, failed.target, failed.started, System.nanoTime(), config.communityAuto());
                        Throwable cause = e.getCause();
                        errors.add(connectionError(cause));
                    }
                    nextLaunch = System.nanoTime();
                }
            }
            if (!session.isClosed() && !errors.isEmpty()) {
                log.accept(dc.label() + " · " + targets.get(0).label() + " · " + String.join(" / ", errors));
            }
        } finally {
            for (Future<Connected> future : attempts.keySet()) {
                future.cancel(true);
            }
            for (Socket socket : sockets) {
                if (winner == null || winner.socket != socket) {
                    session.remove(socket);
                    quietlyClose(socket);
                }
            }
        }
        return null;
    }

    private static String connectionError(Throwable error) {
        if (error instanceof SocketTimeoutException) {
            return "тайм-аут";
        }
        if (error instanceof UnknownHostException) {
            return "адрес не разрешён";
        }
        if (error instanceof SSLException) {
            return "ошибка TLS";
        }
        if (error instanceof ConnectException) {
            return "подключение отклонено";
        }
        if (error instanceof EOFException) {
            return "соединение закрыто";
        }
        return "ошибка обмена";
    }

    private Connected dial(Routes.Target target, Socket socket) throws IOException {
        socket.setTcpNoDelay(true);
        socket.setKeepAlive(true);
        socket.setSoTimeout(CONNECT_TIMEOUT);
        if (target.socks()) {
            Socks5.Endpoint endpoint = config.socks();
            socket.connect(new InetSocketAddress(endpoint.host(), endpoint.port()), CONNECT_TIMEOUT);
            Socks5.connect(socket, endpoint, InetAddress.getByName(target.address()), 443);
        } else {
            socket.connect(destination(target), CONNECT_TIMEOUT);
        }
        WebSocketWire ws = target.webSocket() ? WebSocketWire.connect(socket, target) : null;
        socket.setSoTimeout(0);
        return new Connected(target, socket, ws);
    }

    private static InetSocketAddress destination(Routes.Target target) throws UnknownHostException {
        if (target.family() == Routes.Family.SYSTEM) {
            return new InetSocketAddress(target.address(), target.port());
        }
        boolean ipv6 = target.family() == Routes.Family.IPV6;
        for (InetAddress address : InetAddress.getAllByName(target.address())) {
            if ((address instanceof Inet6Address) == ipv6) {
                return new InetSocketAddress(address, target.port());
            }
        }
        throw new UnknownHostException("Нет адреса нужного семейства");
    }

    void networkChanged() {
        networkChanged(RouteHealth.Kind.OTHER);
    }

    void networkChanged(RouteHealth.Kind kind) {
        List<Session> stale;
        synchronized (networkLock) {
            routes = config.communityAuto() ? routeHistory.select(kind) : new RouteHealth();
            rotation.set(0);
            stale = new ArrayList<>(sessions);
        }
        stale.forEach(ProxyEngine::quietlyClose);
    }

    private void release(Session session) {
        quietlyClose(session);
        if (sessions.remove(session)) {
            capacity.release();
        }
    }

    @Override
    public void close() {
        synchronized (networkLock) {
            if (stopped) {
                return;
            }
            stopped = true;
        }
        quietlyClose(listener);
        sessions.forEach(ProxyEngine::quietlyClose);
        clients.shutdownNow();
        reverse.shutdownNow();
        dialing.shutdownNow();
        measurements.shutdownNow();
        deadlines.shutdownNow();
    }

    private static void quietlyClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
            // The connection is already closing.
        }
    }

    private record Connected(Routes.Target target, Socket socket, WebSocketWire webSocket) {}

    private record PendingAttempt(Routes.Target target, long started) {}

    private static final class Session implements Closeable {
        final Socket client;
        final RouteHealth routes;
        final boolean probe;
        final long started = System.nanoTime();
        private final List<Socket> upstreams = new ArrayList<>();
        private ScheduledFuture<?> replyDeadline;
        private RelayWatchdog watchdog;
        private boolean forwarded;
        private boolean replied;
        private boolean failureRecorded;
        private boolean closed;

        Session(Socket client, RouteHealth routes, boolean probe) {
            this.client = client;
            this.routes = routes;
            this.probe = probe;
        }

        synchronized boolean isClosed() {
            return closed;
        }

        synchronized boolean watch(RelayWatchdog next) {
            if (closed) {
                next.close();
                return false;
            }
            watchdog = next;
            return true;
        }

        synchronized boolean watchReply(ScheduledThreadPoolExecutor deadlines, Runnable timeout) {
            if (closed || forwarded || replied) {
                return false;
            }
            forwarded = true;
            replyDeadline = deadlines.schedule(timeout, FIRST_REPLY_TIMEOUT, TimeUnit.MILLISECONDS);
            return true;
        }

        synchronized boolean receivedReply() {
            if (closed || !forwarded || replied || failureRecorded) {
                return false;
            }
            replied = true;
            cancelDeadline();
            return true;
        }

        synchronized boolean unanswered() {
            if (closed || !forwarded || replied || failureRecorded) {
                return false;
            }
            failureRecorded = true;
            cancelDeadline();
            return true;
        }

        private void cancelDeadline() {
            if (replyDeadline != null) {
                replyDeadline.cancel(false);
                replyDeadline = null;
            }
        }

        synchronized boolean add(Socket socket) {
            if (closed) {
                return false;
            }
            upstreams.add(socket);
            return true;
        }

        synchronized void remove(Socket socket) {
            upstreams.remove(socket);
        }

        synchronized void awaitDownstream() throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (!closed && System.nanoTime() < deadline) {
                TimeUnit.NANOSECONDS.timedWait(this, Math.max(1, deadline - System.nanoTime()));
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            cancelDeadline();
            if (watchdog != null) {
                watchdog.close();
            }
            quietlyClose(client);
            upstreams.forEach(ProxyEngine::quietlyClose);
            upstreams.clear();
            notifyAll();
        }
    }
}
