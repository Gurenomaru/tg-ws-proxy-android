package app.telegramws.proxy;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class ProxyProbe {
    private static final int REQ_PQ_MULTI = 0xbe7e8ef1;
    private static final int RES_PQ = 0x05162463;
    private static final Set<Integer> LOCAL_PROBES = ConcurrentHashMap.newKeySet();

    static boolean isLocalProbe(int port) {
        return LOCAL_PROBES.contains(port);
    }

    static long check(int port, byte[] secret, short dc) throws IOException {
        long start = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.bind(new InetSocketAddress("127.0.0.1", 0));
            int localPort = socket.getLocalPort();
            LOCAL_PROBES.add(localPort);
            try {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 2000);
                socket.setSoTimeout(17_000);
                MtProto.Outbound client = MtProto.initiate(MtProto.Mode.PADDED, dc, secret);
                socket.getOutputStream().write(client.header());

                Request request = request();
                socket.getOutputStream().write(client.sending().update(request.packet()));
                request.verify(MtProto.readPacket(socket.getInputStream(), client.receiving(), MtProto.Mode.PADDED));
            } finally {
                LOCAL_PROBES.remove(localPort);
            }
        }
        return (System.nanoTime() - start) / 1_000_000;
    }
    static void verifyRaw(Socket socket, short dc) throws IOException {
        MtProto.Outbound hello = MtProto.initiate(MtProto.Mode.PADDED, dc, null);
        ProxyProbe.Request probe = ProxyProbe.request();
        socket.getOutputStream().write(hello.header());
        socket.getOutputStream().write(hello.sending().update(probe.packet()));
        probe.verify(MtProto.readPacket(socket.getInputStream(), hello.receiving(), MtProto.Mode.PADDED));
    }

    static void verifyWebSocket(WebSocketWire socket, short dc) throws IOException {
        MtProto.Outbound hello = MtProto.initiate(MtProto.Mode.PADDED, dc, null);
        ProxyProbe.Request probe = ProxyProbe.request();
        socket.send(hello.header());
        socket.send(hello.sending().update(probe.packet()));
        byte[] result = new byte[44];
        int written = 0;
        while (written < result.length) {
            byte[] chunk = new byte[result.length - written];
            int count = socket.receive(chunk);
            if (count < 0) throw new EOFException();
            System.arraycopy(chunk, 0, result, written, count);
            written += count;
        }
        probe.verify(hello.receiving().update(result));
    }

    static Request request() {
        long now = System.currentTimeMillis();
        long messageId = ((now / 1000) << 32) | ((now % 1000) * (1L << 32) / 1000 & ~3L);
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        byte[] packet = MtProto.little(new byte[44]).putInt(40).putLong(0).putLong(messageId)
            .putInt(20).putInt(REQ_PQ_MULTI).put(nonce).array();
        return new Request(nonce, packet);
    }

    record Request(byte[] nonce, byte[] packet) {
        void verify(byte[] reply) throws IOException {
            ByteBuffer data = MtProto.little(reply);
            if (reply.length < 44 || data.getLong(4) != 0 || data.getInt(24) != RES_PQ
                || !Arrays.equals(nonce, Arrays.copyOfRange(reply, 28, 44))) {
                throw new IOException("Неожиданный ответ MTProto");
            }
        }
    }
}
