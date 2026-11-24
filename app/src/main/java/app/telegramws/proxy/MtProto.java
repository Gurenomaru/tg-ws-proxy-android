package app.telegramws.proxy;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class MtProto {
    static final int HEADER_SIZE = 64;
    static final int MAX_PACKET = 2 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    enum Mode {
        ABRIDGED(0xefefefef), INTERMEDIATE(0xeeeeeeee), PADDED(0xdddddddd);

        final int marker;

        Mode(int marker) {
            this.marker = marker;
        }
    }

    record Hello(short dc, Mode mode, Cipher incoming, Cipher outgoing) {}

    record Outbound(byte[] header, Cipher sending, Cipher receiving) {}

    static Hello accept(byte[] header, byte[] secret) throws IOException {
        byte[] seed = Arrays.copyOfRange(header, 8, 56);
        Cipher incoming = cipher(seed, secret);
        ByteBuffer clear = little(incoming.update(header));
        int marker = clear.getInt(56);
        for (Mode mode : Mode.values()) {
            if (mode.marker == marker) {
                return new Hello(clear.getShort(60), mode, incoming, cipher(reverse(seed), secret));
            }
        }
        throw new IOException("Секрет или заголовок MTProto не принят");
    }

    static Outbound initiate(Mode mode, short dc, byte[] secret) {
        byte[] header = new byte[HEADER_SIZE];
        do {
            RANDOM.nextBytes(header);
        } while (reserved(header));

        byte[] seed = Arrays.copyOfRange(header, 8, 56);
        Cipher sending = cipher(seed, secret);
        little(header).putInt(56, mode.marker).putShort(60, dc);
        byte[] encoded = sending.update(header);
        System.arraycopy(encoded, 56, header, 56, 8);
        return new Outbound(header, sending, cipher(reverse(seed), secret));
    }

    private static boolean reserved(byte[] header) {
        int first = ByteBuffer.wrap(header).getInt();
        return (header[0] & 0xff) == 0xef || ByteBuffer.wrap(header).getInt(4) == 0
            || first == 0x48454144 || first == 0x504f5354 || first == 0x47455420
            || first == 0x4f505449 || first == 0x16030102
            || first == Mode.INTERMEDIATE.marker || first == Mode.PADDED.marker;
    }

    private static Cipher cipher(byte[] seed, byte[] secret) {
        try {
            byte[] key = Arrays.copyOf(seed, 32);
            if (secret != null) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(key);
                key = digest.digest(secret);
            }
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(seed, 32, 16));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] reverse(byte[] input) {
        byte[] flipped = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            flipped[i] = input[input.length - 1 - i];
        }
        return flipped;
    }

    static ByteBuffer little(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    static byte[] readExact(InputStream input, int count) throws IOException {
        byte[] bytes = new byte[count];
        int offset = 0;
        while (offset < count) {
            int read = input.read(bytes, offset, count - offset);
            if (read == -1) {
                throw new EOFException();
            }
            offset += read;
        }
        return bytes;
    }

    static byte[] readPacket(InputStream input, Cipher decoder, Mode mode) throws IOException {
        int headerLength = mode == Mode.ABRIDGED ? 1 : 4;
        byte[] header = decoder.update(readExact(input, headerLength));
        int length;
        if (mode == Mode.ABRIDGED) {
            int words = header[0] & 0x7f;
            if (words == 0x7f) {
                byte[] extra = decoder.update(readExact(input, 3));
                header = new byte[] {header[0], extra[0], extra[1], extra[2]};
                words = (extra[0] & 0xff) | (extra[1] & 0xff) << 8 | (extra[2] & 0xff) << 16;
            }
            length = words * 4;
        } else {
            length = little(header).getInt() & Integer.MAX_VALUE;
        }
        if (length < 1 || length > MAX_PACKET) {
            throw new IOException("Некорректная длина пакета MTProto");
        }
        byte[] packet = Arrays.copyOf(header, header.length + length);
        byte[] body = decoder.update(readExact(input, length));
        System.arraycopy(body, 0, packet, header.length, body.length);
        return packet;
    }
}
