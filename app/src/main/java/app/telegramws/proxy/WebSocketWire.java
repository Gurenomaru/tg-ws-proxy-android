package app.telegramws.proxy;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.LongConsumer;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

final class WebSocketWire {
    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final int MAX_HEADERS = 16 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final DataInputStream input;
    private final DataOutputStream output;
    private boolean fragmented;
    private long remaining;

    static WebSocketWire connect(Socket raw, Routes.Target target) throws IOException {
        if (target.port() == 80) {
            return new WebSocketWire(raw, target);
        }
        SSLSocket tls = openTls(raw, target);
        try {
            WebSocketWire result = new WebSocketWire(tls, target);
            tls.setSoTimeout(0);
            return result;
        } catch (IOException | RuntimeException e) {
            tls.close();
            throw e;
        }
    }

    static SSLSocket openTls(Socket raw, Routes.Target target) throws IOException {
        // Override only the routing name. The certificate must still identify Telegram Web.
        String peer = target.sni() == null ? target.host() : "web.telegram.org";
        String sni = target.sni() == null ? target.host() : target.sni();
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket tls = (SSLSocket) factory.createSocket(raw, peer, target.port(), true);
        try {
            tls.setSoTimeout(raw.getSoTimeout());
            SSLParameters parameters = tls.getSSLParameters();
            parameters.setServerNames(Collections.singletonList(new SNIHostName(sni)));
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(parameters);
            tls.startHandshake();
            if (target.sni() != null && !hasTelegramIdentity(
                (X509Certificate) tls.getSession().getPeerCertificates()[0])) {
                throw new SSLPeerUnverifiedException("Сертификат не подтверждает Telegram Web");
            }

            return tls;
        } catch (IOException | RuntimeException e) {
            tls.close();
            throw e;
        }
    }

    private static boolean hasTelegramIdentity(X509Certificate certificate) throws SSLPeerUnverifiedException {
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names != null) {
                for (List<?> name : names) {
                    if (Integer.valueOf(2).equals(name.get(0))
                        && ("web.telegram.org".equalsIgnoreCase((String) name.get(1))
                            || "*.telegram.org".equalsIgnoreCase((String) name.get(1)))) {
                        return true;
                    }
                }
            }
            return false;
        } catch (CertificateParsingException e) {
            throw new SSLPeerUnverifiedException("Не удалось проверить сертификат Telegram Web");
        }
    }

    WebSocketWire(Socket socket, Routes.Target target) throws IOException {
        input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);
        String key = Base64.getEncoder().encodeToString(nonce);
        String request = "GET " + target.path() + " HTTP/1.1\r\n"
            + "Host: " + target.host() + "\r\n"
            + "Connection: Upgrade\r\nUpgrade: websocket\r\n"
            + "Sec-WebSocket-Key: " + key + "\r\n"
            + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
        output.write(request.getBytes(StandardCharsets.US_ASCII));
        output.flush();
        checkUpgrade(key);
    }

    private void checkUpgrade(String key) throws IOException {
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        int tail = 0;
        while (response.size() < MAX_HEADERS && tail != 0x0d0a0d0a) {
            int next = input.read();
            if (next == -1) {
                throw new EOFException("Нет ответа на WebSocket Upgrade");
            }
            response.write(next);
            tail = (tail << 8) | next;
        }
        if (tail != 0x0d0a0d0a) {
            throw new IOException("Слишком длинный ответ WebSocket");
        }
        String[] lines = new String(response.toByteArray(), StandardCharsets.ISO_8859_1).split("\r\n");
        String[] status = lines[0].split(" ", 3);
        if (status.length < 2 || !"101".equals(status[1])) {
            String code = status.length >= 2 && status[1].matches("\\d{3}") ? status[1] : "?";
            throw new IOException("WebSocket HTTP " + code);
        }
        Map<String, String> headers = new HashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int separator = lines[i].indexOf(':');
            if (separator > 0) {
                String name = lines[i].substring(0, separator).toLowerCase(Locale.ROOT);
                String value = lines[i].substring(separator + 1).trim();
                headers.merge(name, value, (left, right) -> left + "," + right);
            }
        }
        String protocol = headers.get("sec-websocket-protocol");
        if (!hasToken(headers.get("connection"), "upgrade")
            || !"websocket".equalsIgnoreCase(headers.get("upgrade"))
            || !acceptFor(key).equals(headers.get("sec-websocket-accept"))
            || (protocol != null && !"binary".equals(protocol))
            || headers.containsKey("sec-websocket-extensions")) {
            throw new IOException("Неверный ответ WebSocket Upgrade");
        }
    }

    private static boolean hasToken(String header, String token) {
        if (header == null) {
            return false;
        }
        for (String value : header.split(",")) {
            if (token.equalsIgnoreCase(value.trim())) {
                return true;
            }
        }
        return false;
    }

    static String acceptFor(String key) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-1").digest((key + GUID).getBytes(StandardCharsets.US_ASCII));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    void send(byte[] content) throws IOException {
        writeFrame(2, content);
    }

    void ping(long token) throws IOException {
        writeFrame(9, ByteBuffer.allocate(Long.BYTES).putLong(token).array());
    }

    private synchronized void writeFrame(int opcode, byte[] content) throws IOException {
        int length = content.length;
        output.writeByte(0x80 | opcode);
        if (length < 126) {
            output.writeByte(0x80 | length);
        } else if (length <= 0xffff) {
            output.writeByte(0xfe);
            output.writeShort(length);
        } else {
            output.writeByte(0xff);
            output.writeLong(length);
        }
        byte[] mask = new byte[4];
        RANDOM.nextBytes(mask);
        output.write(mask);
        for (int i = 0; i < length; i++) {
            content[i] ^= mask[i & 3];
        }
        output.write(content);
        output.flush();
    }

    int receive(byte[] buffer) throws IOException {
        return receive(buffer, null);
    }

    int receive(byte[] buffer, LongConsumer pong) throws IOException {
        while (remaining == 0) {
            int first = input.read();
            if (first < 0) {
                if (fragmented) {
                    throw new EOFException("Незавершённое сообщение WebSocket");
                }
                return -1;
            }
            int second = input.readUnsignedByte();
            boolean fin = (first & 0x80) != 0;
            int opcode = first & 0x0f;
            int sizeCode = second & 0x7f;
            boolean control = opcode >= 8;
            if ((first & 0x70) != 0 || (second & 0x80) != 0 || (control && (!fin || sizeCode > 125))) {
                throw new IOException("Неверный кадр WebSocket");
            }
            long size = sizeCode;
            if (sizeCode == 126) {
                size = input.readUnsignedShort();
            } else if (sizeCode == 127) {
                size = input.readLong();
            }
            if (size < 0 || (sizeCode == 126 && size < 126) || (sizeCode == 127 && size <= 0xffff)) {
                throw new IOException("Неверная длина кадра WebSocket");
            }
            switch (opcode) {
                case 0, 2 -> {
                    if (fragmented == (opcode == 2)) {
                        throw new IOException("Неверная последовательность кадров WebSocket");
                    }
                    fragmented = !fin;
                    remaining = size;
                }
                case 8 -> {
                    writeFrame(8, MtProto.readExact(input, (int) size));
                    return -1;
                }
                case 9 -> writeFrame(10, MtProto.readExact(input, (int) size));
                case 10 -> {
                    byte[] payload = MtProto.readExact(input, (int) size);
                    if (pong != null && payload.length == Long.BYTES) {
                        pong.accept(ByteBuffer.wrap(payload).getLong());
                    }
                }
                default -> throw new IOException("Неизвестный кадр WebSocket");
            }
        }
        // WebSocket frames may contain several MTProto packets. Pass the bytes
        // onward as they arrive and keep the caller's buffer size independent.
        int count = input.read(buffer, 0, (int) Math.min(remaining, buffer.length));
        if (count < 0) {
            throw new EOFException("Незавершённый кадр WebSocket");
        }
        remaining -= count;
        return count;
    }
}
