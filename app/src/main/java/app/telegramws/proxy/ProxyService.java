package app.telegramws.proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import java.io.IOException;
import java.net.BindException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ProxyService extends Service {
    static final String START = "app.telegramws.proxy.START";
    static final String STOP = "app.telegramws.proxy.STOP";
    private static final String CHANNEL = "proxy";
    private static final int NOTIFICATION = 1;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Object lock = new Object();
    private ProxyEngine engine;
    private volatile boolean destroyed;
    private boolean started;
    private boolean watchingNetwork;
    private Network defaultNetwork;
    private Network reportedNetwork;
    private RouteHealth.Kind networkKind = RouteHealth.Kind.OTHER;
    private final ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
        @Override
        public void onAvailable(Network network) {
            reportedNetwork = network;
        }

        @Override
        public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            if (!network.equals(reportedNetwork)) {
                return;
            }
            RouteHealth.Kind kind = kindOf(capabilities);
            if (!network.equals(defaultNetwork) || kind != networkKind) {
                changeNetwork(network, kind, "Сеть сменилась · переподключение");
            }
        }

        @Override
        public void onLost(Network network) {
            if (network.equals(reportedNetwork)) {
                reportedNetwork = null;
            }
            if (network.equals(defaultNetwork)) {
                changeNetwork(null, RouteHealth.Kind.OTHER, "Сеть недоступна · соединения сброшены");
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationChannel channel = new NotificationChannel(CHANNEL,
            getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int id) {
        if (intent == null || STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (started) {
            return START_NOT_STICKY;
        }
        started = true;
        Routes.Config config = new ProxySettings(this).load();
        ProxyStatus.phase(ProxyStatus.Phase.STARTING, 0, "");
        startForeground(NOTIFICATION, notification(getString(R.string.notification_starting), ""));
        ConnectivityManager connectivity = getSystemService(ConnectivityManager.class);
        defaultNetwork = connectivity.getActiveNetwork();
        reportedNetwork = defaultNetwork;
        networkKind = defaultNetwork == null ? RouteHealth.Kind.OTHER : kindOf(connectivity.getNetworkCapabilities(defaultNetwork));
        connectivity.registerDefaultNetworkCallback(networkCallback, main);
        watchingNetwork = true;
        ProxyTraffic traffic = ProxyStatus.traffic();
        executor.execute(() -> run(config, traffic));
        return START_NOT_STICKY;
    }

    private void run(Routes.Config config, ProxyTraffic traffic) {
        try (ProxyEngine created = new ProxyEngine(config, ProxySettings.key(config.secret()), ProxyStatus::log, traffic)) {
            synchronized (lock) {
                if (destroyed) {
                    return;
                }
                created.networkChanged(networkKind);
                engine = created;
            }
            main.post(() -> {
                if (!destroyed) {
                    String address = "127.0.0.1:" + created.port();
                    ProxyStatus.log("Сервис запущен · " + address);
                    ProxyStatus.phase(ProxyStatus.Phase.RUNNING, created.port(), "");
                    getSystemService(NotificationManager.class).notify(NOTIFICATION,
                        notification(getString(R.string.notification_running), address));
                }
            });
            created.serve();
        } catch (IOException e) {
            main.post(() -> {
                if (!destroyed) {
                    String reason = e instanceof BindException ? "Порт " + config.port() + " занят."
                        : "Ошибка локального сервера";
                    ProxyStatus.log(reason);
                    ProxyStatus.phase(ProxyStatus.Phase.FAILED, 0, reason);
                    stopSelf();
                }
            });
        }
    }

    private void changeNetwork(Network network, RouteHealth.Kind kind, String reason) {
        synchronized (lock) {
            defaultNetwork = network;
            networkKind = kind;
            if (!destroyed && engine != null) {
                ProxyStatus.log(reason);
                engine.networkChanged(kind);
            }
        }
    }

    private static RouteHealth.Kind kindOf(NetworkCapabilities capabilities) {
        if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return RouteHealth.Kind.OTHER;
        }
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return RouteHealth.Kind.WIFI;
        }
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            return RouteHealth.Kind.CELLULAR;
        }
        return RouteHealth.Kind.OTHER;
    }

    private Notification notification(String title, String detail) {
        int immutable = PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT;
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), immutable);
        PendingIntent stop = PendingIntent.getService(this, 1,
            new Intent(this, ProxyService.class).setAction(STOP), immutable);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_proxy).setContentTitle(title)
            .setContentText(detail).setContentIntent(open).setOngoing(true).setShowWhen(false)
            .setOnlyAlertOnce(true).addAction(new Notification.Action.Builder(null,
                getString(R.string.stop), stop).build()).build();
    }

    @Override
    public void onDestroy() {
        if (watchingNetwork) {
            getSystemService(ConnectivityManager.class).unregisterNetworkCallback(networkCallback);
        }
        synchronized (lock) {
            destroyed = true;
            if (engine != null) {
                engine.close();
            }
        }
        executor.shutdownNow();
        stopForeground(STOP_FOREGROUND_REMOVE);
        if (ProxyStatus.snapshot().phase() != ProxyStatus.Phase.FAILED) {
            ProxyStatus.log("Сервис остановлен");
            ProxyStatus.phase(ProxyStatus.Phase.OFF, 0, "");
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
