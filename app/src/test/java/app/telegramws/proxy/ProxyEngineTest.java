package app.telegramws.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import org.junit.Test;

public final class ProxyEngineTest {
    private static final byte[] SECRET = new byte[16];

    @Test
    public void remembersAWorkingRouteOnlyUntilRepeatedFailure() {
        Routes.Dc dc = Routes.Dc.fromWire((short) 2);
        Routes.Target target = new Routes.Target("example.org", "example.org", "/apiws", null, "WSS");
        RouteHealth health = new RouteHealth();
        health.succeeded(dc, target);
        long now = System.nanoTime();
        assertEquals(target, health.preferred(dc));
        health.failed(dc, target, now);
        assertNull(health.preferred(dc));
        assertTrue(health.ready(dc, target, now));
        health.failed(dc, target, now);
        assertFalse(health.ready(dc, target, now + TimeUnit.SECONDS.toNanos(3)));
        assertTrue(health.ready(dc, target, now + TimeUnit.SECONDS.toNanos(4)));
        health.succeeded(dc, target);
        assertTrue(health.ready(dc, target, now));
    }

    @Test
    public void returningToMobileRestoresItsOwnWorkingRoute() {
        var history = new RouteHealth.ByNetwork();
        var dc = Routes.Dc.fromWire((short) 2);
        var relay = new Routes.Target("relay.example.org", "relay.example.org", "/apiws", null, "WS", false, 80);
        var direct = new Routes.Target("direct.example.org", "direct.example.org", "/apiws", null, "WSS");
        history.select(RouteHealth.Kind.WIFI).succeeded(dc, direct);
        var mobile = history.select(RouteHealth.Kind.CELLULAR);
        assertNull(mobile.preferred(dc));
        mobile.succeeded(dc, relay);
        assertEquals(direct, history.select(RouteHealth.Kind.WIFI).preferred(dc));
        assertEquals(relay, history.select(RouteHealth.Kind.CELLULAR).preferred(dc));
        history.select(RouteHealth.Kind.CELLULAR).failed(dc, relay, System.nanoTime(), true);
        assertNull(history.select(RouteHealth.Kind.CELLULAR).preferred(dc));
        assertEquals(direct, history.select(RouteHealth.Kind.WIFI).preferred(dc));
    }

    @Test
    public void olderFailureDoesNotInvalidateARecentlyAnsweredRoute() {
        var dc = Routes.Dc.fromWire((short) 2);
        var target = new Routes.Target("relay.example.org", "relay.example.org", "/apiws", null, "WSS");
        var health = new RouteHealth();
        long olderAttempt = System.nanoTime() - TimeUnit.SECONDS.toNanos(1);
        health.succeeded(dc, target);
        long now = System.nanoTime();
        health.failed(dc, target, olderAttempt, now, true);
        assertEquals(target, health.preferred(dc));
        assertTrue(health.ready(dc, target, now));
        health.failed(dc, target, now, System.nanoTime(), true);
        assertNull(health.preferred(dc));
        assertFalse(health.ready(dc, target, now));
    }

    @Test
    public void ranksVerifiedRoutesByElapsedTimeInsteadOfCompletionOrder() {
        var slow = new Routes.Target("slow.example.org", "slow.example.org", "/apiws", null, "WSS");
        var fast = new Routes.Target("fast.example.org", "fast.example.org", "/apiws", null, "WSS");
        var unanswered = new Routes.Target("silent.example.org", "silent.example.org", "/apiws", null, "WSS");
        var candidates = List.of(slow, unanswered, fast);
        var timings = List.of(new ProxyEngine.RouteTiming(slow, 850), new ProxyEngine.RouteTiming(fast, 150));
        assertEquals(List.of(fast, slow), ProxyEngine.orderedByResponse(timings, candidates));
    }

    @Test
    public void verifiesNewRoutesAndReusesTheRankingForTheNextConnection() throws Exception {
        try (ServerSocket relay = new ServerSocket(0);
             ProxyEngine engine = start(relay, new CopyOnWriteArrayList<>(), new ProxyTraffic(), true)) {
            FutureTask<Void> peers = new FutureTask<>(() -> {
                for (int i = 0; i < 3; i++) {
                    runPeer(relay, true, new CountDownLatch(0)).get(3, TimeUnit.SECONDS);
                }
                return null;
            });
            new Thread(peers).start();

            // The first client needs a route measurement and its own connection.
            assertTrue(ProxyProbe.check(engine.port(), SECRET, (short) 2) >= 0);
            // The only remaining upstream connection is reserved for the next client.
            assertTrue(ProxyProbe.check(engine.port(), SECRET, (short) 2) >= 0);
            peers.get(3, TimeUnit.SECONDS);
        }
    }

    @Test
    public void keepsTelegramConnectionsSeparateFromInAppProbes() throws Exception {
        try (ServerSocket relay = new ServerSocket(0)) {
            var traffic = new ProxyTraffic();
            try (ProxyEngine engine = start(relay, new CopyOnWriteArrayList<>(), traffic)) {
                var probePeer = runPeer(relay, true, new CountDownLatch(0));
                ProxyProbe.check(engine.port(), SECRET, (short) 2);
                probePeer.get(3, TimeUnit.SECONDS);
                var clientPeer = runPeer(relay, true, new CountDownLatch(0));
                try (var client = new Socket()) {
                    client.connect(new InetSocketAddress("127.0.0.1", engine.port()), 1000);
                    client.setSoTimeout(3000);
                    var hello = MtProto.initiate(MtProto.Mode.PADDED, (short) 2, SECRET);
                    var request = ProxyProbe.request();
                    client.getOutputStream().write(hello.header());
                    client.getOutputStream().write(hello.sending().update(request.packet()));
                    request.verify(MtProto.readPacket(client.getInputStream(), hello.receiving(), MtProto.Mode.PADDED));
                }
                clientPeer.get(3, TimeUnit.SECONDS);
                for (int attempt = 0; attempt < 50 && traffic.count(false, ProxyTraffic.Event.REPLY) == 0; attempt++) {
                    Thread.sleep(10);
                }
                for (boolean probe : new boolean[]{false, true}) {
                    assertEquals(1, traffic.count(probe, ProxyTraffic.Event.OPENED));
                    assertEquals(1, traffic.count(probe, ProxyTraffic.Event.ACCEPTED));
                    assertEquals(1, traffic.count(probe, ProxyTraffic.Event.REQUEST));
                    assertEquals(1, traffic.count(probe, ProxyTraffic.Event.REPLY));
                }
            }
        }
    }

    @Test
    public void relaysMtProtoThroughPreferredSocksAndClosesSessionsOnNetworkChange() throws Exception {
        try (ServerSocket relay = new ServerSocket(0)) {
            List<String> journal = new CopyOnWriteArrayList<>();
            try (ProxyEngine engine = start(relay, journal)) {
                FutureTask<Void> server = runPeer(relay, true, new CountDownLatch(0));
                assertTrue(ProxyProbe.check(engine.port(), SECRET, (short) 2) >= 0);
                server.get(3, TimeUnit.SECONDS);
                assertTrue(journal.stream().anyMatch(line -> line.contains("TCP через SOCKS5")));

                CountDownLatch received = new CountDownLatch(1);
                FutureTask<Void> silent = runPeer(relay, false, received);
                FutureTask<Long> client = new FutureTask<>(() -> ProxyProbe.check(engine.port(), SECRET, (short) 2));
                new Thread(client).start();
                assertTrue(received.await(3, TimeUnit.SECONDS));
                engine.networkChanged();
                assertTrue(assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> client.get(2, TimeUnit.SECONDS)).getCause() instanceof EOFException);
                silent.get(2, TimeUnit.SECONDS);
                FutureTask<Void> afterChange = runPeer(relay, true, new CountDownLatch(0));
                assertTrue(ProxyProbe.check(engine.port(), SECRET, (short) 2) >= 0);
                afterChange.get(2, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    public void closesAnUpstreamThatDoesNotReplyAfterReceivingARequest() throws Exception {
        try (ServerSocket relay = new ServerSocket(0)) {
            List<String> journal = new CopyOnWriteArrayList<>();
            try (ProxyEngine engine = start(relay, journal)) {
                FutureTask<Void> silent = runPeer(relay, false, new CountDownLatch(0));
                assertThrows(EOFException.class, () -> ProxyProbe.check(engine.port(), SECRET, (short) 4));
                silent.get(3, TimeUnit.SECONDS);
                assertTrue(journal.stream().anyMatch(line -> line.contains("нет первого ответа")));
            }
        }
    }

    private static ProxyEngine start(ServerSocket relay, List<String> journal) throws IOException {
        return start(relay, journal, new ProxyTraffic());
    }

    private static ProxyEngine start(ServerSocket relay, List<String> journal, ProxyTraffic traffic) throws IOException {
        return start(relay, journal, traffic, false);
    }

    private static ProxyEngine start(ServerSocket relay, List<String> journal, ProxyTraffic traffic, boolean automatic)
        throws IOException {
        relay.setSoTimeout(3000);
        Socks5.Endpoint socks = Socks5.parse("127.0.0.1:" + relay.getLocalPort(), "", "");
        Routes.Config config = new Routes.Config(0, "", Collections.emptyMap(), "", "", false, false, socks, true, false, automatic);
        ProxyEngine engine = new ProxyEngine(config, SECRET, journal::add, traffic);
        new Thread(() -> {
            try {
                engine.serve();
            } catch (IOException ignored) {
                // Closing the engine unblocks the listen socket.
            }
        }).start();
        return engine;
    }

    private static FutureTask<Void> runPeer(ServerSocket listener, boolean respond, CountDownLatch received) {
        FutureTask<Void> server = new FutureTask<>(() -> {
            try (Socket peer = listener.accept()) {
                peer.setSoTimeout(9000);
                var input = peer.getInputStream();
                var output = peer.getOutputStream();
                assertEquals(0, MtProto.readExact(input, 3)[2]);
                output.write(new byte[] {5, 0});
                assertEquals(1, MtProto.readExact(input, 10)[1]);
                output.write(new byte[] {5, 0, 0, 1, 127, 0, 0, 1, 0, 0});
                MtProto.Hello init = MtProto.accept(MtProto.readExact(input, 64), null);
                byte[] request = MtProto.readPacket(input, init.incoming(), init.mode());
                received.countDown();
                if (respond) {
                    byte[] reply = MtProto.little(new byte[44]).putInt(40).putLong(0).putLong(1).putInt(20)
                        .putInt(0x05162463).put(request, 28, 16).array();
                    output.write(init.outgoing().update(reply));
                }
                assertEquals(-1, input.read());
            }
            return null;
        });
        new Thread(server).start();
        return server;
    }
}
