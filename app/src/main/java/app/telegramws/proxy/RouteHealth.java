package app.telegramws.proxy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

final class RouteHealth {
    private record Key(Routes.Dc dc, Routes.Target target) {}
    private record Failure(int count, long retryAt) {}

    private final Map<Key, Failure> failures = new ConcurrentHashMap<>();
    private final Map<Routes.Dc, Routes.Target> working = new ConcurrentHashMap<>();
    private final Map<Routes.Dc, Long> lastNoRoute = new ConcurrentHashMap<>();

    boolean reportNoRoute(Routes.Dc dc, long now) {
        Long last = lastNoRoute.putIfAbsent(dc, now);
        return last == null || (now - last >= TimeUnit.SECONDS.toNanos(5) && lastNoRoute.replace(dc, last, now));
    }

    Routes.Target preferred(Routes.Dc dc) {
        return working.get(dc);
    }

    boolean ready(Routes.Dc dc, Routes.Target target, long now) {
        Failure failure = failures.get(new Key(dc, target));
        return failure == null || now - failure.retryAt >= 0;
    }

    void succeeded(Routes.Dc dc, Routes.Target target) {
        failures.remove(new Key(dc, target));
        working.put(dc, target);
    }

    void failed(Routes.Dc dc, Routes.Target target, long now) {
        failed(dc, target, now, false);
    }

    void failed(Routes.Dc dc, Routes.Target target, long now, boolean coolDownImmediately) {
        working.remove(dc, target);
        failures.compute(new Key(dc, target), (key, previous) -> {
            int count = previous == null || now - previous.retryAt > TimeUnit.MINUTES.toNanos(2)
                ? 1 : Math.min(4, previous.count + 1);
            long wait = count == 1 ? TimeUnit.SECONDS.toNanos(coolDownImmediately ? 4 : 0)
                : TimeUnit.SECONDS.toNanos(4L << (count - 2));
            return new Failure(count, now + wait);
        });
    }
}
