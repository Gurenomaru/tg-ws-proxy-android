package app.telegramws.proxy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import org.junit.Test;

public final class Socks5Test {
    @Test
    public void readsUnconfiguredAndValidatesCredentials() {
        assertNull(Socks5.parse("", "", ""));
        assertThrows(IllegalArgumentException.class, () -> Socks5.parse("host", "", ""));
        assertThrows(IllegalArgumentException.class, () -> Socks5.parse("host:1080/path", "", ""));
        assertThrows(IllegalArgumentException.class, () -> Socks5.parse("host:1080", "name", ""));
        assertThrows(IllegalArgumentException.class, () -> Socks5.parse("host:1080", "x".repeat(256), "p"));
        assertEquals(1080, Socks5.parse("[::1]:1080", "", "").port());
    }

    @Test
    public void authenticatesAndConnectsWithoutConsumingTelegramData() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(1500);
            peer.setSoTimeout(1500);
            FutureTask<Void> remote = new FutureTask<>(() -> {
                DataInputStream input = new DataInputStream(peer.getInputStream());
                assertArrayEquals(new byte[] {5, 1, 2}, MtProto.readExact(input, 3));
                peer.getOutputStream().write(new byte[] {5, 2});
                assertArrayEquals(new byte[] {1, 1, 'u', 1, 'p'}, MtProto.readExact(input, 5));
                peer.getOutputStream().write(new byte[] {1, 0});
                assertArrayEquals(new byte[] {5, 1, 0, 1, (byte) 149, (byte) 154, (byte) 167, 51, 1, (byte) 187},
                    MtProto.readExact(input, 10));
                peer.getOutputStream().write(new byte[] {5, 0, 0, 3, 1, 'x', 0, 0, 42});
                return null;
            });
            new Thread(remote).start();
            Socks5.Endpoint proxy = Socks5.parse("127.0.0.1:" + server.getLocalPort(), "u", "p");
            Socks5.connect(client, proxy, InetAddress.getByName("149.154.167.51"), 443);
            assertEquals(42, client.getInputStream().read());
            remote.get(2, TimeUnit.SECONDS);
        }
    }

    @Test
    public void rejectsSocksServerThatDoesNotAcceptRequestedAuthentication() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(1500);
            peer.getOutputStream().write(new byte[] {5, (byte) 255});
            Socks5.Endpoint proxy = Socks5.parse("127.0.0.1:" + server.getLocalPort(), "", "");
            assertThrows(IOException.class, () -> Socks5.connect(client, proxy, InetAddress.getLoopbackAddress(), 443));
        }
    }
}
