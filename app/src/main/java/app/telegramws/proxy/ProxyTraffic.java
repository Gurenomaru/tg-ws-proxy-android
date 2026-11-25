package app.telegramws.proxy;

import java.util.concurrent.atomic.AtomicLongArray;

final class ProxyTraffic {
    enum Event {
        OPENED("Локальные подключения"),
        LIMIT("Отклонены из-за лимита"),
        ACCEPTED("Принят заголовок MTProto"),
        INVALID("Неверный секрет или заголовок"),
        NO_ROUTE("Нет маршрута"),
        REQUEST("Начата передача первого запроса"),
        REPLY("Первый ответ передан клиенту"),
        NO_REPLY("Соединения без первого ответа");

        final String label;
        Event(String label) { this.label = label; }
    }

    private final AtomicLongArray regular = new AtomicLongArray(Event.values().length);
    private final AtomicLongArray diagnostics = new AtomicLongArray(Event.values().length);

    void record(boolean probe, Event event) {
        (probe ? diagnostics : regular).incrementAndGet(event.ordinal());
    }

    long count(boolean probe, Event event) {
        return (probe ? diagnostics : regular).get(event.ordinal());
    }

    void appendTo(StringBuilder report) {
        report.append("События прокси с запуска, обычные / служебные\n");
        for (Event event : Event.values()) {
            report.append(event.label).append(": ").append(count(false, event))
                .append(" / ").append(count(true, event)).append('\n');
        }
    }
}
