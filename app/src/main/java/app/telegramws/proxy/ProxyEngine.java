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
import java.util.HashMap;
import java.util.HashSet;
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
import javax.net.ssl.SSLException;

final class ProxyEngine implements Closeable {
    private static final int CLIENT_LIMIT = 24;
    private static final int CONNECT_TIMEOUT = 3500;
    private static final int ROUTE_HEAD_START_MS = 220;
    private static final int FIRST_REPLY_TIMEOUT = 6000;
    private final Routes.Config config;
    private final byte[] secret;
    private final Consumer<String> log;
    private final ServerSocket listener;
    private final ExecutorService clients = Executors.newFixedThreadPool(CLIENT_LIMIT);
    private final ExecutorService reverse = Executors.newFixedThreadPool(CLIENT_LIMIT);
    private final ExecutorService dialing = new ThreadPoolExecutor(24, 24, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(96));
    private final ScheduledThreadPoolExecutor deadlines = new ScheduledThreadPoolExecutor(1);
    private final Object networkLock = new Object();
    private final Set<Session> sessions = ConcurrentHashMap.newKeySet();
    private final Semaphore capacity = new Semaphore(CLIENT_LIMIT);
    private final RouteHealth.ByNetwork routeHistory = new RouteHealth.ByNetwork();
    private RouteHealth routes = new RouteHealth();
    private final AtomicInteger rotation = new AtomicInteger();
    private volatile boolean stopped;

    ProxyEngine(Routes.Config config, byte[] secret, Consumer<String> log) throws IOException {
        this.config = config;
        this.secret = secret;
        this.log = log;
        deadlines.setRemoveOnCancelPolicy(true);
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
            if (!capacity.tryAcquire()) {
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
                session = new Session(socket, routes);
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
            MtProto.Hello hello = MtProto.accept(MtProto.readExact(input, MtProto.HEADER_SIZE), secret);
            Routes.Dc targetDc = Routes.Dc.fromWire(hello.dc());
            dc = targetDc;
            client.setSoTimeout(0);

            long selectionStarted = System.nanoTime();
            Connected connected = selectRoute(session, dc);
            long selectionMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - selectionStarted);
            if (connected == null) {
                if (!session.isClosed() && session.routes.reportNoRoute(dc, System.nanoTime())) {
                    log.accept(dc.label() + " · нет доступного маршрута");
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
            reverse.execute(() -> readUpstream(session, connected, targetDc, hello, relay));
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
                    session.watchReply(deadlines, timeout);
                    connected.webSocket.send(relay.sending().update(packet));
                } else {
                    int count = input.read(buffer);
                    if (count == -1) {
                        upstream.shutdownOutput();
                        session.awaitDownstream();
                        break;
                    }
                    session.watchReply(deadlines, timeout);
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
                              MtProto.Hello hello, MtProto.Outbound relay) {
        try {
            OutputStream output = session.client.getOutputStream();
            InputStream input = connected.socket.getInputStream();
            byte[] buffer = new byte[32 * 1024];
            while (!stopped) {
                int count = connected.webSocket == null ? input.read(buffer) : connected.webSocket.receive(buffer);
                if (count == -1) {
                    return;
                }
                byte[] clear = relay.receiving().update(buffer, 0, count);
                if (session.receivedReply()) {
                    session.routes.succeeded(dc, connected.target);
                }
                output.write(hello.outgoing().update(clear));
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

    private boolean recordUnanswered(Session session, Routes.Dc dc, Connected connected) {
        if (!session.unanswered()) {
            return false;
        }
        session.routes.failed(dc, connected.target, System.nanoTime(), config.communityAuto());
        return true;
    }

    private Connected selectRoute(Session session, Routes.Dc dc) throws InterruptedException {
        Routes.Target previous = session.routes.preferred(dc);
        Set<Routes.Target> attempted = Collections.emptySet();
        if (session.routes.kind == RouteHealth.Kind.CELLULAR && Routes.useMobileRace(dc, config)) {
            attempted = new HashSet<>();
            if (previous != null && session.routes.ready(dc, previous, System.nanoTime())) {
                attempted.add(previous);
                Connected saved = raceScheduled(session, dc,
                    Collections.singletonList(new Routes.Attempt(previous, 0)), 2500, previous.label());
                if (saved != null || session.isClosed()) {
                    return saved;
                }
                if (previous.equals(session.routes.preferred(dc))) {
                    session.routes.failed(dc, previous, System.nanoTime(), true);
                }
            }
            List<Routes.Attempt> mobile = Routes.mobileAttempts(Routes.candidates(dc, config), rotation.getAndAdd(2));
            Set<Routes.Target> alreadyTried = attempted;
            mobile.removeIf(choice -> alreadyTried.contains(choice.target())
                || !session.routes.ready(dc, choice.target(), System.nanoTime()));
            if (!mobile.isEmpty()) {
                mobile.forEach(choice -> alreadyTried.add(choice.target()));
                Connected quick = raceScheduled(session, dc, mobile, CONNECT_TIMEOUT + 1350, "Подбор маршрута 4G");
                if (quick != null || session.isClosed()) {
                    return quick;
                }
            }
        }
        for (Routes.Stage stage : Routes.ordered(dc, config, previous)) {
            if (session.isClosed()) {
                return null;
            }
            List<Routes.Target> choices = new ArrayList<>(stage.targets());
            long now = System.nanoTime();
            choices.removeAll(attempted);
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
            if (picked == null && !config.communityAuto() && !session.isClosed()) {
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

    private Connected race(Session session, Routes.Dc dc, List<Routes.Target> targets)
        throws InterruptedException {
        List<Routes.Attempt> schedule = new ArrayList<>(targets.size());
        for (int index = 0; index < targets.size(); index++) {
            schedule.add(new Routes.Attempt(targets.get(index), index == 0 ? 0 : ROUTE_HEAD_START_MS));
        }
        return raceScheduled(session, dc, schedule, CONNECT_TIMEOUT + 550, targets.get(0).label());
    }

    private Connected raceScheduled(Session session, Routes.Dc dc, List<Routes.Attempt> schedule,
                                    int budgetMs, String label) throws InterruptedException {
        ExecutorCompletionService<Connected> results = new ExecutorCompletionService<>(dialing);
        Map<Future<Connected>, Routes.Target> attempts = new HashMap<>();
        List<Socket> sockets = new ArrayList<>();
        Connected winner = null;
        List<String> errors = new ArrayList<>();
        long started = System.nanoTime();
        long deadline = started + TimeUnit.MILLISECONDS.toNanos(budgetMs);
        int launched = 0;
        int completed = 0;
        try {
            while (!session.isClosed()) {
                long now = System.nanoTime();
                if (now - deadline >= 0) {
                    errors.add("тайм-аут");
                    break;
                }
                boolean hasAlternatives = launched < schedule.size();
                long nextLaunch = hasAlternatives
                    ? started + TimeUnit.MILLISECONDS.toNanos(schedule.get(launched).waitMillis()) : deadline;
                if (hasAlternatives && (now - nextLaunch >= 0 || launched == completed)) {
                    Routes.Target target = schedule.get(launched++).target();
                    Socket socket = new Socket(Proxy.NO_PROXY);
                    sockets.add(socket);
                    if (!session.add(socket)) {
                        return null;
                    }
                    try {
                        attempts.put(results.submit(() -> dial(target, socket)), target);
                    } catch (RejectedExecutionException ignored) {
                        // Other attempts in this race can still succeed if the dial queue is full.
                        completed++;
                        session.remove(socket);
                        quietlyClose(socket);
                    }
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
                        session.routes.failed(dc, attempts.get(result), System.nanoTime(), config.communityAuto());
                        Throwable cause = e.getCause();
                        errors.add(connectionError(cause));
                    }
                }
            }
            if (!session.isClosed() && !errors.isEmpty()) {
                log.accept(dc.label() + " · " + label + " · " + String.join(" / ", errors));
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

    private static final class Session implements Closeable {
        final Socket client;
        final RouteHealth routes;
        private final List<Socket> upstreams = new ArrayList<>();
        private ScheduledFuture<?> replyDeadline;
        private boolean forwarded;
        private boolean replied;
        private boolean failureRecorded;
        private boolean closed;

        Session(Socket client, RouteHealth routes) {
            this.client = client;
            this.routes = routes;
        }

        synchronized boolean isClosed() {
            return closed;
        }

        synchronized void watchReply(ScheduledThreadPoolExecutor deadlines, Runnable timeout) {
            if (!closed && !forwarded && !replied) {
                forwarded = true;
                replyDeadline = deadlines.schedule(timeout, FIRST_REPLY_TIMEOUT, TimeUnit.MILLISECONDS);
            }
        }

        synchronized boolean receivedReply() {
            if (closed || replied || failureRecorded) {
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
            quietlyClose(client);
            upstreams.forEach(ProxyEngine::quietlyClose);
            upstreams.clear();
            notifyAll();
        }
    }
}
