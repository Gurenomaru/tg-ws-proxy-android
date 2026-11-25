package app.telegramws.proxy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

public final class RelayWatchdogTest {
    private static final RelayWatchdog.Timing TIMING = new RelayWatchdog.Timing(80, 120, 420, 30);

    @Test
    public void missingMatchingPongClosesTheStalledTransport() throws Exception {
        var timer = new ScheduledThreadPoolExecutor(1);
        var ref = new AtomicReference<RelayWatchdog>();
        var closed = new CountDownLatch(1);
        try (var watch = new RelayWatchdog(timer, Runnable::run, token -> ref.get().pong(token + 1),
            token -> closed.countDown(), TIMING)) {
            ref.set(watch);
            watch.received();
            watch.sent();
            assertTrue(closed.await(2, TimeUnit.SECONDS));
        } finally {
            timer.shutdownNow();
        }
    }

    @Test
    public void healthyIdleConnectionAndOneWayAcknowledgementAreKept() throws Exception {
        var timer = new ScheduledThreadPoolExecutor(1);
        var ref = new AtomicReference<RelayWatchdog>();
        var closed = new CountDownLatch(1);
        var ping = new CountDownLatch(1);
        try (var watch = new RelayWatchdog(timer, Runnable::run, token -> {
            ref.get().pong(token);
            ping.countDown();
        }, token -> closed.countDown(), TIMING)) {
            ref.set(watch);
            watch.received();
            assertFalse(ping.await(200, TimeUnit.MILLISECONDS));
            watch.sent();
            assertTrue(ping.await(2, TimeUnit.SECONDS));
            assertFalse(closed.await(550, TimeUnit.MILLISECONDS));
        } finally {
            timer.shutdownNow();
        }
    }

    @Test
    public void relayPongDoesNotHideTelegramSilenceAfterRepeatedTraffic() throws Exception {
        var timer = new ScheduledThreadPoolExecutor(1);
        var ref = new AtomicReference<RelayWatchdog>();
        var ping = new CountDownLatch(1);
        var closed = new CountDownLatch(1);
        try (var watch = new RelayWatchdog(timer, Runnable::run, token -> {
            ref.get().pong(token);
            ping.countDown();
        }, token -> closed.countDown(), TIMING)) {
            ref.set(watch);
            watch.received();
            watch.sent();
            assertTrue(ping.await(2, TimeUnit.SECONDS));
            watch.sent();
            assertTrue(closed.await(2, TimeUnit.SECONDS));
        } finally {
            timer.shutdownNow();
        }
    }
}
