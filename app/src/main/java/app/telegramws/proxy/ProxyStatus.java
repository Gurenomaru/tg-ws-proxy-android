package app.telegramws.proxy;

import android.util.Log;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

final class ProxyStatus {
    enum Phase { OFF, STARTING, RUNNING, FAILED }

    record Snapshot(Phase phase, String detail, int port, String journal, boolean probing, String probe) {}

    private static final ArrayDeque<String> journal = new ArrayDeque<>();
    private static Phase phase = Phase.OFF;
    private static ProxyTraffic traffic = new ProxyTraffic();
    private static String detail = "";
    private static int port;
    private static boolean probing;
    private static String probe = "";
    private static int probeId;

    static synchronized void phase(Phase next, int activePort, String message) {
        phase = next;
        if (next == Phase.STARTING) {
            traffic = new ProxyTraffic();
        }
        port = activePort;
        detail = message;
        if (next == Phase.STARTING || next == Phase.OFF) {
            probing = false;
            probe = "";
            probeId++;
        }
    }

    static synchronized int beginProbe() {
        probing = true;
        probe = "Проверяем маршруты Telegram и медиа…";
        return ++probeId;
    }

    static synchronized void endProbe(int id, String result) {
        if (id == probeId) {
            probe = result;
            probing = false;
            log(probe);
        }
    }

    static synchronized void log(String event) {
        String time = new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date());
        if (journal.size() == 120) {
            journal.removeFirst();
        }
        journal.addLast(time + "  " + event);
        if (BuildConfig.DEBUG) {
            Log.i("TelegramWs", event);
        }
    }

    static synchronized ProxyTraffic traffic() {
        return traffic;
    }

    static synchronized void appendTraffic(StringBuilder report) {
        report.append("Фаза сервиса: ").append(phase).append('\n');
        traffic.appendTo(report);
    }

    static synchronized Snapshot snapshot() {
        return new Snapshot(phase, detail, port, String.join("\n", journal), probing, probe);
    }
}
