package app.telegramws.proxy;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.LongConsumer;

final class RelayWatchdog implements Closeable {
    static final Timing DEFAULT = new Timing(8_000, 5_000, 20_000, 4_000);

    record Timing(long pingAfter, long pongTimeout, long stallAfter, long retryAfter) {}

    interface Ping {
        void send(long token) throws IOException;
    }

    private final ScheduledExecutorService timer;
    private final Executor writer;
    private final Ping ping;
    private final LongConsumer stalled;
    private final Timing timing;
    private ScheduledFuture<?> deadline;
    private boolean enabled;
    private boolean closed;
    private long since;
    private long lastSent;
    private boolean retried;
    private boolean waitingForPong;
    private boolean pong;

    RelayWatchdog(ScheduledExecutorService timer, Executor writer, Ping ping,
                  LongConsumer stalled, Timing timing) {
        this.timer = timer;
        this.writer = writer;
        this.ping = ping;
        this.stalled = stalled;
        this.timing = timing;
    }

    synchronized void sent() {
        if (!enabled || closed) {
            return;
        }
        long now = System.nanoTime();
        if (deadline == null) {
            since = now;
            deadline = ping == null ? schedule(() -> checkTraffic(now), timing.stallAfter)
                : schedule(() -> sendPing(now), timing.pingAfter);
        } else if (now - lastSent >= TimeUnit.MILLISECONDS.toNanos(timing.retryAfter)) {
            retried = true;
        }
        lastSent = now;
    }

    synchronized void received() {
        if (!closed) {
            enabled = true;
            reset();
        }
    }

    synchronized void pong(long token) {
        if (pending(token) && waitingForPong) {
            pong = true;
        }
    }

    private void sendPing(long token) {
        synchronized (this) {
            if (!pending(token)) {
                return;
            }
            waitingForPong = true;
            deadline = schedule(() -> checkPong(token), timing.pongTimeout);
        }
        try {
            writer.execute(() -> {
                synchronized (this) {
                    if (!pending(token) || !waitingForPong) {
                        return;
                    }
                }
                try {
                    ping.send(token);
                } catch (IOException ignored) {
                    // The pong deadline will close the failed transport.
                }
            });
        } catch (RejectedExecutionException ignored) {
            // The engine is stopping or cannot make progress on the relay.
        }
    }

    private void checkPong(long token) {
        synchronized (this) {
            if (!pending(token)) {
                return;
            }
            if (pong) {
                // A relay can answer a WebSocket ping while Telegram upstream is stalled.
                waitingForPong = false;
                deadline = schedule(() -> checkTraffic(token), timing.stallAfter - timing.pingAfter - timing.pongTimeout);
                return;
            }
            reset();
        }
        stalled.accept(token);
    }

    private void checkTraffic(long token) {
        boolean shouldReconnect;
        synchronized (this) {
            if (!pending(token)) {
                return;
            }
            // An acknowledgement or continuous upload may not need an immediate reply.
            shouldReconnect = retried;
            reset();
        }
        if (shouldReconnect) {
            stalled.accept(token);
        }
    }

    private ScheduledFuture<?> schedule(Runnable task, long delay) {
        return timer.schedule(task, delay, TimeUnit.MILLISECONDS);
    }

    private boolean pending(long token) {
        return !closed && deadline != null && token == since;
    }

    private void reset() {
        if (deadline != null) {
            deadline.cancel(false);
            deadline = null;
        }
        retried = false;
        waitingForPong = false;
        pong = false;
    }

    @Override public synchronized void close() {
        closed = true;
        reset();
    }
}
