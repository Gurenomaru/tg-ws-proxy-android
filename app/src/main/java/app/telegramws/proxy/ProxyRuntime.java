package app.telegramws.proxy;

import java.io.Closeable;
import java.io.IOException;

interface ProxyRuntime extends Closeable {
    int port();
    void serve() throws IOException;
    void networkChanged(RouteHealth.Kind kind);
    @Override void close();
}
