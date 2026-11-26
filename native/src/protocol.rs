use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{self, ErrorKind};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};

pub type Cipher = ctr::Ctr128BE<Aes256>;
pub const HELLO_SIZE: usize = 64;
const MAX_PACKET: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Abridged,
    Intermediate,
    Padded,
}

impl Mode {
    fn marker(self) -> [u8; 4] {
        [match self {
            Self::Abridged => 0xef,
            Self::Intermediate => 0xee,
            Self::Padded => 0xdd,
        }; 4]
    }
}

pub struct ClientHello {
    pub dc: i16,
    pub mode: Mode,
    pub from_client: Cipher,
    pub to_client: Cipher,
}

pub struct RelayHello {
    pub header: [u8; HELLO_SIZE],
    pub to_server: Cipher,
    pub from_server: Cipher,
}

fn ciphers(header: &[u8; HELLO_SIZE], secret: Option<&[u8; 16]>) -> (Cipher, Cipher) {
    fn create(seed: &[u8; 48], secret: Option<&[u8; 16]>) -> Cipher {
        let (prekey, iv) = seed.split_at(32);
        let mut key = [0u8; 32];
        if let Some(secret) = secret {
            let mut hash = Sha256::new();
            hash.update(prekey);
            hash.update(secret);
            key.copy_from_slice(&hash.finalize());
        } else {
            key.copy_from_slice(prekey);
        }
        Cipher::new((&key).into(), iv.into())
    }

    let mut seed = [0u8; 48];
    seed.copy_from_slice(&header[8..56]);
    let forward = create(&seed, secret);
    seed.reverse();
    (forward, create(&seed, secret))
}

pub fn accept(header: [u8; HELLO_SIZE], secret: &[u8; 16]) -> io::Result<ClientHello> {
    let (mut from_client, to_client) = ciphers(&header, Some(secret));
    let mut decoded = header;
    from_client.apply_keystream(&mut decoded);
    let mode = [Mode::Abridged, Mode::Intermediate, Mode::Padded]
        .into_iter()
        .find(|mode| mode.marker() == decoded[56..60])
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Неверный заголовок MTProto"))?;
    let dc = i16::from_le_bytes([decoded[60], decoded[61]]);
    Ok(ClientHello {
        dc,
        mode,
        from_client,
        to_client,
    })
}

fn reserved(header: &[u8; HELLO_SIZE]) -> bool {
    header[0] == 0xef
        || header[4..8] == [0; 4]
        || matches!(
            &header[..4],
            b"HEAD"
                | b"POST"
                | b"GET "
                | b"OPTI"
                | [0xee, 0xee, 0xee, 0xee]
                | [0xdd, 0xdd, 0xdd, 0xdd]
                | [0x16, 0x03, 0x01, 0x02]
        )
}

pub fn initiate(mode: Mode, dc: i16, secret: Option<&[u8; 16]>) -> RelayHello {
    let mut header = [0; HELLO_SIZE];
    loop {
        OsRng.fill_bytes(&mut header);
        if !reserved(&header) {
            break;
        }
    }
    let (mut to_server, from_server) = ciphers(&header, secret);
    let mut encoded = header;
    encoded[56..60].copy_from_slice(&mode.marker());
    encoded[60..62].copy_from_slice(&dc.to_le_bytes());
    to_server.apply_keystream(&mut encoded);
    header[56..].copy_from_slice(&encoded[56..]);
    RelayHello {
        header,
        to_server,
        from_server,
    }
}

pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &mut Cipher,
    mode: Mode,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    let mut head = [0; 4];
    let header_len;
    let length;
    if mode == Mode::Abridged {
        reader.read_exact(&mut head[..1]).await?;
        cipher.apply_keystream(&mut head[..1]);
        let words = head[0] & 0x7f;
        if words == 127 {
            reader.read_exact(&mut head[1..]).await?;
            cipher.apply_keystream(&mut head[1..]);
            length =
                (usize::from(head[1]) | (usize::from(head[2]) << 8) | (usize::from(head[3]) << 16))
                    * 4;
            header_len = 4;
        } else {
            length = usize::from(words) * 4;
            header_len = 1;
        }
    } else {
        reader.read_exact(&mut head).await?;
        cipher.apply_keystream(&mut head);
        length = (u32::from_le_bytes(head) & 0x7fff_ffff) as usize;
        header_len = 4;
    }
    if !(1..=MAX_PACKET).contains(&length) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Неверная длина пакета MTProto",
        ));
    }
    buffer.resize(header_len + length, 0);
    buffer[..header_len].copy_from_slice(&head[..header_len]);
    reader.read_exact(&mut buffer[header_len..]).await?;
    cipher.apply_keystream(&mut buffer[header_len..]);
    Ok(())
}

pub struct Probe {
    nonce: [u8; 16],
    pub packet: [u8; 44],
}

impl Probe {
    pub fn new() -> Self {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let msg_id =
            (now.as_secs() << 32) | (((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000) & !3);
        let mut packet = [0; 44];
        packet[..4].copy_from_slice(&40u32.to_le_bytes());
        packet[12..20].copy_from_slice(&msg_id.to_le_bytes());
        packet[20..24].copy_from_slice(&20u32.to_le_bytes());
        packet[24..28].copy_from_slice(&0xbe7e8ef1u32.to_le_bytes());
        packet[28..].copy_from_slice(&nonce);
        Self { nonce, packet }
    }

    pub fn verify(&self, reply: &[u8]) -> io::Result<()> {
        if reply.len() < 44
            || reply[4..12] != [0; 8]
            || reply[24..28] != 0x05162463u32.to_le_bytes()
            || reply[28..44] != self.nonce
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Неожиданный ответ MTProto",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn padded_client_preserves_counter_position_and_uses_reverse_stream() {
        let secret = [3; 16];
        let mut client = initiate(Mode::Padded, -203, Some(&secret));
        let mut server = accept(client.header, &secret).unwrap();
        assert_eq!(server.dc, -203);
        assert_eq!(server.mode, Mode::Padded);
        assert!(accept(client.header, &[9; 16]).is_err());
        let original = [4, 0, 0, 128, 1, 2, 3, 4];
        let mut packet = original;
        client.to_server.apply_keystream(&mut packet);
        let mut readable = packet.as_slice();
        let mut buffer = Vec::new();
        read_packet(
            &mut readable,
            &mut server.from_client,
            server.mode,
            &mut buffer,
        )
        .await
        .unwrap();
        assert_eq!(buffer, original);
        server.to_client.apply_keystream(&mut buffer);
        client.from_server.apply_keystream(&mut buffer);
        assert_eq!(buffer, original);
    }

    #[tokio::test]
    async fn abridged_extended_length_preserves_quick_ack_flag() {
        let secret = [1; 16];
        let mut client = initiate(Mode::Abridged, 4, Some(&secret));
        let mut server = accept(client.header, &secret).unwrap();
        let mut packet = vec![7; 512];
        packet[..4].copy_from_slice(&[255, 127, 0, 0]);
        let mut encrypted = packet.clone();
        client.to_server.apply_keystream(&mut encrypted);
        let mut data = encrypted.as_slice();
        let mut result = Vec::new();
        read_packet(&mut data, &mut server.from_client, server.mode, &mut result)
            .await
            .unwrap();
        assert_eq!(result, packet);
    }
}
