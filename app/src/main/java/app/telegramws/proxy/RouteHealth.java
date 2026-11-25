package app.telegramws.proxy;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

final class RouteHealth {
    enum Kind { CELLULAR, WIFI, OTHER }

    static final class ByNetwork {
        private final Map<Kind, Map<Routes.Dc, Working>> working = new EnumMap<>(Kind.class);

        synchronized RouteHealth select(Kind kind) {
            Map<Routes.Dc, Working> saved = kind == Kind.OTHER ? new ConcurrentHashMap<>()
                : working.computeIfAbsent(kind, ignored -> new ConcurrentHashMap<>());
            return new RouteHealth(kind, saved);
        }
    }

    private record Working(Routes.Target target, long observedAt) {}

    final Kind kind;
    private record Key(Routes.Dc dc, Routes.Target target) {}
    private record Failure(int count, long retryAt) {}

    private final Map<Key, Failure> failures = new ConcurrentHashMap<>();
    private final Map<Routes.Dc, Working> working;
    private final Map<Routes.Dc, Long> lastNoRoute = new ConcurrentHashMap<>();

    RouteHealth() {
        this(Kind.OTHER, new ConcurrentHashMap<>());
    }

    private RouteHealth(Kind kind, Map<Routes.Dc, Working> working) {
        this.kind = kind;
        this.working = working;
    }

    boolean reportNoRoute(Routes.Dc dc, long now) {
        Long last = lastNoRoute.putIfAbsent(dc, now);
        return last == null || (now - last >= TimeUnit.SECONDS.toNanos(5) && lastNoRoute.replace(dc, last, now));
    }

    Routes.Target preferred(Routes.Dc dc) {
        Working route = working.get(dc);
        if (route == null) {
            return null;
        }
        if (System.nanoTime() - route.observedAt > TimeUnit.MINUTES.toNanos(15)) {
            working.remove(dc, route);
            return null;
        }
        return route.target;
    }

    boolean ready(Routes.Dc dc, Routes.Target target, long now) {
        Failure failure = failures.get(new Key(dc, target));
        return failure == null || now - failure.retryAt >= 0;
    }

    void succeeded(Routes.Dc dc, Routes.Target target) {
        working.compute(dc, (key, previous) -> {
            failures.remove(new Key(dc, target));
            return new Working(target, System.nanoTime());
        });
    }

    void failed(Routes.Dc dc, Routes.Target target, long now) {
        failed(dc, target, now, false);
    }

    void failed(Routes.Dc dc, Routes.Target target, long now, boolean coolDownImmediately) {
        failed(dc, target, now, now, coolDownImmediately);
    }

    void failed(Routes.Dc dc, Routes.Target target, long attemptStarted, long now, boolean coolDownImmediately) {
        working.compute(dc, (key, route) -> {
            boolean sameRoute = route != null && route.target.equals(target);
            if (sameRoute && route.observedAt - attemptStarted > 0) {
                return route;
            }
            failures.compute(new Key(dc, target), (attempt, previous) -> {
                int count = previous == null || now - previous.retryAt > TimeUnit.MINUTES.toNanos(2)
                    ? 1 : Math.min(4, previous.count + 1);
                long wait = count == 1 ? TimeUnit.SECONDS.toNanos(coolDownImmediately ? 4 : 0)
                    : TimeUnit.SECONDS.toNanos(4L << (count - 2));
                return new Failure(count, now + wait);
            });
            return sameRoute ? null : route;
        });
    }
}
