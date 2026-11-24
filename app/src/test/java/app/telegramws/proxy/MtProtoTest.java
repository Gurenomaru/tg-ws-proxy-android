package app.telegramws.proxy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HexFormat;
import org.junit.Test;

public final class MtProtoTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] SECRET = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
    private static final byte[] HELLO = HEX.parseHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        + "202122232425262728292a2b2c2d2e2f30313233343536377fb7a7ad45f7ade4"
    );

    @Test
    public void decryptsKnownClientHelloAndKeepsBothDirectionsInSync() throws IOException {
        MtProto.Hello hello = MtProto.accept(HELLO, SECRET);
        assertEquals(-4, hello.dc());
        assertEquals(MtProto.Mode.PADDED, hello.mode());
        byte[] packet = MtProto.readPacket(new ByteArrayInputStream(HEX.parseHex("52deccea1a706e4e")),
            hello.incoming(), hello.mode());
        assertArrayEquals(HEX.parseHex("0400008000010203"), packet);
        assertArrayEquals(HEX.parseHex("a809d788854556e53c85f878"),
            hello.outgoing().update(HEX.parseHex("080000000102030405060708")));
    }

    @Test
    public void rejectsWrongKey() {
        assertThrows(IOException.class, () -> MtProto.accept(HELLO, new byte[16]));
    }

    @Test
    public void readsLongAbridgedPacketWithQuickAckFlag() throws IOException {
        MtProto.Outbound sender = MtProto.initiate(MtProto.Mode.ABRIDGED, (short) 2, SECRET);
        MtProto.Hello server = MtProto.accept(sender.header(), SECRET);
        byte[] packet = new byte[512];
        packet[0] = (byte) 0xff;
        packet[1] = 127;
        packet[511] = 42;
        assertArrayEquals(packet, MtProto.readPacket(new ByteArrayInputStream(sender.sending().update(packet)),
            server.incoming(), server.mode()));
    }

    @Test
    public void rejectsOversizedPacketBeforeReadingBody() throws IOException {
        MtProto.Outbound sender = MtProto.initiate(MtProto.Mode.INTERMEDIATE, (short) 2, SECRET);
        MtProto.Hello server = MtProto.accept(sender.header(), SECRET);
        byte[] header = MtProto.little(new byte[4]).putInt(MtProto.MAX_PACKET + 1).array();
        assertThrows(IOException.class, () -> MtProto.readPacket(
            new ByteArrayInputStream(sender.sending().update(header)), server.incoming(), server.mode()));
    }
}
