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
    private static final long ROUTE_HEAD_START = TimeUnit.MILLISECONDS.toNanos(220);
    private static final long VERIFIED_HEAD_START = TimeUnit.MILLISECONDS.toNanos(900);
    private static final int FIRST_REPLY_TIMEOUT = 6000;
    private final Routes.Config config;
    private final byte[] secret;
    private final Consumer<String> log;
    private final ProxyTraffic traffic;
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

    ProxyEngine(Routes.Config config, byte[] secret, Consumer<String> log, ProxyTraffic traffic) throws IOException {
        this.traffic = traffic;
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
            reverse.execute(() -> readUpstream(session, connected, targetDc, hello, relay));
            Runnable firstRequest = () -> traffic.record(session.probe, ProxyTraffic.Event.REQUEST);
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
                        firstRequest.run();
                    }
                    connected.webSocket.send(relay.sending().update(packet));
                } else {
                    int count = input.read(buffer);
                    if (count == -1) {
                        upstream.shutdownOutput();
                        session.awaitDownstream();
                        break;
                    }
                    if (session.watchReply(deadlines, timeout)) {
                        firstRequest.run();
                    }
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

    private boolean recordUnanswered(Session session, Routes.Dc dc, Connected connected) {
        if (!session.unanswered()) {
            return false;
        }
        traffic.record(session.probe, ProxyTraffic.Event.NO_REPLY);
        session.routes.failed(dc, connected.target, session.started, System.nanoTime(), config.communityAuto());
        return true;
    }

    private Connected selectRoute(Session session, Routes.Dc dc) throws InterruptedException {
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
        ExecutorCompletionService<Connected> results = new ExecutorCompletionService<>(dialing);
        Map<Future<Connected>, PendingAttempt> attempts = new HashMap<>();
        List<Socket> sockets = new ArrayList<>();
        Connected winner = null;
        List<String> errors = new ArrayList<>();
        long headStart = config.communityAuto() && targets.get(0).equals(session.routes.preferred(dc))
            ? VERIFIED_HEAD_START : ROUTE_HEAD_START;
        long nextLaunch = System.nanoTime();
        long deadline = nextLaunch + TimeUnit.MILLISECONDS.toNanos(CONNECT_TIMEOUT + 550);
        int launched = 0;
        int completed = 0;
        try {
            while (!session.isClosed()) {
                long now = System.nanoTime();
                if (now - deadline >= 0) {
                    errors.add("тайм-аут");
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
            quietlyClose(client);
            upstreams.forEach(ProxyEngine::quietlyClose);
            upstreams.clear();
            notifyAll();
        }
    }
}
