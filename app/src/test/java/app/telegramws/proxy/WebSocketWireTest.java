package app.telegramws.proxy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;

public final class WebSocketWireTest {
    private static final Routes.Target TARGET = new Routes.Target("example.org", "127.0.0.1",
        "/apiws", null, "test");

    @Test
    public void computesUpgradeResponseFromRfc6455Example() {
        assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", WebSocketWire.acceptFor("dGhlIHNhbXBsZSBub25jZQ=="));
    }

    @Test
    public void masksClientDataAndReceivesFragmentedBinaryWithPing() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(2000);
            peer.setSoTimeout(2000);
            FutureTask<Void> remote = new FutureTask<>(() -> {
                upgrade(peer, true);
                DataInputStream fromClient = new DataInputStream(peer.getInputStream());
                assertArrayEquals(new byte[] {1, 2, 3}, readMasked(fromClient, 0x82));
                peer.getOutputStream().write(new byte[] {2, 1, 10, (byte) 0x89, 1, 25,
                    (byte) 0x80, 1, 20, (byte) 0x88, 0});
                assertArrayEquals(new byte[] {25}, readMasked(fromClient, 0x8a));
                assertArrayEquals(new byte[0], readMasked(fromClient, 0x88));
                return null;
            });
            new Thread(remote).start();
            WebSocketWire wire = new WebSocketWire(client, TARGET);
            wire.send(new byte[] {1, 2, 3});
            byte[] buffer = new byte[32];
            assertEquals(1, wire.receive(buffer));
            assertEquals(10, buffer[0]);
            assertEquals(1, wire.receive(buffer));
            assertEquals(20, buffer[0]);
            assertEquals(-1, wire.receive(buffer));
            remote.get(3, TimeUnit.SECONDS);
        }
    }

    @Test
    public void matchesPongPayloadWithoutForwardingItToMtproto() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(2000);
            peer.setSoTimeout(2000);
            long token = 912;
            FutureTask<Void> remote = new FutureTask<>(() -> {
                upgrade(peer, true);
                byte[] ping = readMasked(new DataInputStream(peer.getInputStream()), 0x89);
                assertEquals(token, ByteBuffer.wrap(ping).getLong());
                DataOutputStream output = new DataOutputStream(peer.getOutputStream());
                output.writeByte(0x8a);
                output.writeByte(ping.length);
                output.write(ping);
                output.write(new byte[]{(byte) 0x82, 1, 17});
                return null;
            });
            new Thread(remote).start();
            WebSocketWire wire = new WebSocketWire(client, TARGET);
            wire.ping(token);
            AtomicLong pong = new AtomicLong();
            byte[] buffer = new byte[10];
            assertEquals(1, wire.receive(buffer, pong::set));
            assertEquals(token, pong.get());
            assertEquals(17, buffer[0]);
            remote.get(3, TimeUnit.SECONDS);
        }
    }

    @Test
    public void rejectsUpgradeWhenAcceptKeyIsWrong() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(2000);
            peer.setSoTimeout(2000);
            FutureTask<Void> remote = new FutureTask<>(() -> { upgrade(peer, false); return null; });
            new Thread(remote).start();
            assertThrows(IOException.class, () -> new WebSocketWire(client, TARGET));
            remote.get(3, TimeUnit.SECONDS);
        }
    }

    @Test
    public void forwardsLargeFrameBeforeItsTailArrivesAndPreservesBytes() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(3000);
            peer.setSoTimeout(3000);
            byte[] payload = new byte[3 * 1024 * 1024 + 19];
            new Random(89217).nextBytes(payload);
            CountDownLatch firstChunkRead = new CountDownLatch(1);
            FutureTask<Void> remote = new FutureTask<>(() -> {
                upgrade(peer, true);
                DataOutputStream output = new DataOutputStream(peer.getOutputStream());
                output.writeByte(0x82);
                output.writeByte(127);
                output.writeLong(payload.length);
                output.write(payload, 0, 19);
                assertTrue(firstChunkRead.await(3, TimeUnit.SECONDS));
                output.write(payload, 19, payload.length - 19);
                peer.shutdownOutput();
                return null;
            });
            new Thread(remote).start();
            WebSocketWire wire = new WebSocketWire(client, TARGET);
            byte[] buffer = new byte[32 * 1024];
            MessageDigest actual = MessageDigest.getInstance("SHA-256");
            int total = 0;
            while (total < 19) {
                int count = wire.receive(buffer);
                assertTrue(count > 0);
                actual.update(buffer, 0, count);
                total += count;
            }
            firstChunkRead.countDown();
            assertEquals(19, total);
            int count;
            while ((count = wire.receive(buffer)) != -1) {
                actual.update(buffer, 0, count);
                total += count;
            }
            assertEquals(payload.length, total);
            assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(payload), actual.digest());
            remote.get(3, TimeUnit.SECONDS);
        }
    }

    @Test
    public void reportsEofInsideABinaryFrame() throws Exception {
        try (ServerSocket server = new ServerSocket(0); Socket client = new Socket("127.0.0.1", server.getLocalPort());
             Socket peer = server.accept()) {
            client.setSoTimeout(2000);
            peer.setSoTimeout(2000);
            FutureTask<Void> remote = new FutureTask<>(() -> {
                upgrade(peer, true);
                peer.getOutputStream().write(new byte[] {(byte) 0x82, 4, 7, 9});
                peer.shutdownOutput();
                return null;
            });
            new Thread(remote).start();
            WebSocketWire wire = new WebSocketWire(client, TARGET);
            byte[] buffer = new byte[8];
            int total = 0;
            while (total < 2) {
                int count = wire.receive(buffer);
                assertTrue(count > 0);
                total += count;
            }
            assertThrows(EOFException.class, () -> wire.receive(buffer));
            remote.get(3, TimeUnit.SECONDS);
        }
    }

    private static void upgrade(Socket peer, boolean validKey) throws IOException {
        BufferedReader request = new BufferedReader(new InputStreamReader(peer.getInputStream(), StandardCharsets.US_ASCII));
        assertEquals("GET /apiws HTTP/1.1", request.readLine());
        String key = "";
        String line;
        while ((line = request.readLine()) != null && !line.isEmpty()) {
            if (line.startsWith("Sec-WebSocket-Key: ")) {
                key = line.substring("Sec-WebSocket-Key: ".length());
            }
        }
        String reply = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
            + "Sec-WebSocket-Accept: " + (validKey ? WebSocketWire.acceptFor(key) : "invalid") + "\r\n\r\n";
        peer.getOutputStream().write(reply.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] readMasked(DataInputStream input, int opcode) throws IOException {
        assertEquals(opcode, input.readUnsignedByte());
        int length = input.readUnsignedByte();
        assertEquals(0x80, length & 0x80);
        byte[] mask = MtProto.readExact(input, 4);
        byte[] data = MtProto.readExact(input, length & 0x7f);
        for (int i = 0; i < data.length; i++) {
            data[i] ^= mask[i & 3];
        }
        return data;
    }
}
