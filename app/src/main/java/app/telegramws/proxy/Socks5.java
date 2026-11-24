package app.telegramws.proxy;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;

final class Socks5 {
    record Endpoint(String address, String host, int port, String user, String password) {}

    private Socks5() {}

    static Endpoint parse(String address, String user, String password) {
        String value = address.trim();
        if (value.isEmpty() && user.isEmpty() && password.isEmpty()) {
            return null;
        }
        URI uri;
        try {
            uri = URI.create("socks5://" + value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Укажите адрес SOCKS5 в формате host:port");
        }
        if (uri.getHost() == null || uri.getPort() < 1 || uri.getPort() > 65535
            || uri.getRawUserInfo() != null || uri.getRawQuery() != null
            || uri.getRawFragment() != null || !uri.getRawPath().isEmpty()) {
            throw new IllegalArgumentException("Укажите адрес SOCKS5 в формате host:port");
        }
        if (user.isEmpty() != password.isEmpty() || utf8(user).length > 255 || utf8(password).length > 255) {
            throw new IllegalArgumentException("Укажите логин и пароль SOCKS5 длиной до 255 байт каждый");
        }
        return new Endpoint(value, uri.getHost(), uri.getPort(), user, password);
    }

    static void connect(Socket socket, Endpoint proxy, InetAddress destination, int port) throws IOException {
        DataInputStream input = new DataInputStream(socket.getInputStream());
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());
        boolean authenticate = !proxy.user().isEmpty();
        int method = authenticate ? 2 : 0;
        output.write(new byte[] {5, 1, (byte) method});
        if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != method) {
            throw new IOException("SOCKS5: сервер отклонил способ входа");
        }
        if (authenticate) {
            byte[] user = utf8(proxy.user());
            byte[] password = utf8(proxy.password());
            output.writeByte(1);
            output.writeByte(user.length);
            output.write(user);
            output.writeByte(password.length);
            output.write(password);
            if (input.readUnsignedByte() != 1 || input.readUnsignedByte() != 0) {
                throw new IOException("SOCKS5: ошибка авторизации");
            }
        }

        byte[] address = destination.getAddress();
        output.write(new byte[] {5, 1, 0, (byte) (address.length == 4 ? 1 : 4)});
        output.write(address);
        output.writeShort(port);
        int version = input.readUnsignedByte();
        int status = input.readUnsignedByte();
        if (version != 5 || status != 0 || input.readUnsignedByte() != 0) {
            throw new IOException("SOCKS5: CONNECT отклонён (" + status + ")");
        }
        int addressLength = switch (input.readUnsignedByte()) {
            case 1 -> 4;
            case 3 -> input.readUnsignedByte();
            case 4 -> 16;
            default -> throw new IOException("SOCKS5: неверный тип адреса ответа");
        };
        MtProto.readExact(input, addressLength + 2);
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
