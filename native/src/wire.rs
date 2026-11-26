use crate::routes::Socks;
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use rustls::client::{
    danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    WebPkiServerVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha1::{Digest, Sha1};
use std::io::{self, ErrorKind};
use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEADERS: usize = 16 * 1024;
const MAX_CONTROL: usize = 125;

#[derive(Debug)]
struct TelegramWebIdentity(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for TelegramWebIdentity {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _sni: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The routing name may differ from the authenticated Telegram Web identity.
        let telegram = ServerName::try_from("web.telegram.org").expect("static DNS name");
        self.0
            .verify_server_cert(end_entity, intermediates, &telegram, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn tls_config(telegram_identity: bool) -> Arc<ClientConfig> {
    static CONFIGS: OnceLock<(Arc<ClientConfig>, Arc<ClientConfig>)> = OnceLock::new();
    let configs = CONFIGS.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        let regular = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS 1.2/1.3")
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .expect("bundled CA roots");
        let alternate = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS 1.2/1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TelegramWebIdentity(verifier)))
            .with_no_client_auth();
        (Arc::new(regular), Arc::new(alternate))
    });
    if telegram_identity {
        configs.1.clone()
    } else {
        configs.0.clone()
    }
}

pub async fn tls(
    socket: TcpStream,
    host: &str,
    alternate_sni: Option<&str>,
) -> io::Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(alternate_sni.unwrap_or(host).to_owned())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Неверное имя TLS"))?;
    TlsConnector::from(tls_config(alternate_sni.is_some()))
        .connect(name, socket)
        .await
}

pub async fn socks(stream: &mut TcpStream, proxy: &Socks, destination: Ipv4Addr) -> io::Result<()> {
    let method = if proxy.user.is_empty() { 0 } else { 2 };
    stream.write_all(&[5, 1, method]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, method] {
        return Err(wire_error("Способ входа SOCKS5 отклонён"));
    }
    if method == 2 {
        let user = proxy.user.as_bytes();
        let password = proxy.password.as_bytes();
        if !(1..=255).contains(&user.len()) || !(1..=255).contains(&password.len()) {
            return Err(wire_error("Неверная длина учётных данных SOCKS5"));
        }
        stream.write_all(&[1, user.len() as u8]).await?;
        stream.write_all(user).await?;
        stream.write_u8(password.len() as u8).await?;
        stream.write_all(password).await?;
        stream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err(wire_error("Вход SOCKS5 отклонён"));
        }
    }
    let octets = destination.octets();
    stream
        .write_all(&[
            5, 1, 0, 1, octets[0], octets[1], octets[2], octets[3], 1, 187,
        ])
        .await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] != [5, 0, 0] {
        return Err(wire_error("SOCKS5 не открыл соединение"));
    }
    let len = match header[3] {
        1 => 4,
        3 => usize::from(stream.read_u8().await?),
        4 => 16,
        _ => return Err(wire_error("Неверный адрес ответа SOCKS5")),
    };
    let mut address = [0; 257];
    stream.read_exact(&mut address[..len + 2]).await?;
    Ok(())
}

pub fn wire_error(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

fn expected_accept(key: &str) -> String {
    let mut hash = Sha1::new();
    hash.update(key);
    hash.update(WS_GUID);
    STANDARD.encode(hash.finalize())
}

pub async fn upgrade<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    host: &str,
    path: &str,
) -> io::Result<BufReader<T>> {
    let mut stream = BufReader::new(stream);
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    let key = STANDARD.encode(nonce);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\n\
        Upgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Protocol: binary\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut data = Vec::with_capacity(512);
    while !data.ends_with(b"\r\n\r\n") {
        if data.len() >= MAX_HEADERS {
            return Err(wire_error("Слишком длинный ответ WebSocket"));
        }
        data.push(stream.read_u8().await?);
    }
    let response =
        std::str::from_utf8(&data).map_err(|_| wire_error("Неверный ответ WebSocket"))?;
    let mut lines = response.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1));
    if status != Some("101") {
        return Err(wire_error("WebSocket Upgrade отклонён"));
    }
    let accept = expected_accept(&key);
    let mut accepted = false;
    let mut websocket = false;
    let mut upgraded = false;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        let value = value.trim();
        if name.eq_ignore_ascii_case("connection") {
            upgraded |= value
                .split(',')
                .any(|val| val.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            websocket |= value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            if accepted || value != accept {
                return Err(wire_error("Неверный ответ на WebSocket-ключ"));
            }
            accepted = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-extensions")
            || (name.eq_ignore_ascii_case("sec-websocket-protocol") && value != "binary")
        {
            return Err(wire_error("Неподдерживаемый протокол WebSocket"));
        }
    }
    if !(accepted && websocket && upgraded) {
        return Err(wire_error("Неверный ответ WebSocket Upgrade"));
    }
    Ok(stream)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    body: &mut [u8],
) -> io::Result<()> {
    let mut head = [0; 14];
    head[0] = 0x80 | opcode;
    let mut len = match body.len() {
        0..=125 => {
            head[1] = 0x80 | body.len() as u8;
            2
        }
        126..=65_535 => {
            head[1] = 0xfe;
            head[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
            4
        }
        _ => {
            head[1] = 0xff;
            head[2..10].copy_from_slice(&(body.len() as u64).to_be_bytes());
            10
        }
    };
    let mut mask = [0; 4];
    OsRng.fill_bytes(&mut mask);
    head[len..len + 4].copy_from_slice(&mask);
    len += 4;
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
    writer.write_all(&head[..len]).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

#[derive(Default)]
pub struct Frames {
    remaining: u64,
    fragmented: bool,
}

pub enum Frame {
    Data(usize),
    Control(u8, usize),
    Eof,
}

impl Frames {
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        input: &mut R,
        buffer: &mut [u8],
    ) -> io::Result<Frame> {
        while self.remaining == 0 {
            let Some(first) = read_byte(input).await? else {
                if self.fragmented {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "Незавершённое сообщение WebSocket",
                    ));
                }
                return Ok(Frame::Eof);
            };
            let second = input.read_u8().await?;
            let final_frame = first & 0x80 != 0;
            let opcode = first & 15;
            let short_len = second & 127;
            if first & 0x70 != 0
                || second & 0x80 != 0
                || (opcode >= 8 && (!final_frame || usize::from(short_len) > MAX_CONTROL))
            {
                return Err(wire_error("Неверный кадр WebSocket"));
            }
            let size = match short_len {
                126 => u64::from(input.read_u16().await?),
                127 => input.read_u64().await?,
                size => u64::from(size),
            };
            if size > i64::MAX as u64
                || (short_len == 126 && size < 126)
                || (short_len == 127 && size <= 65535)
            {
                return Err(wire_error("Неверная длина кадра WebSocket"));
            }
            match opcode {
                0 | 2 => {
                    if self.fragmented == (opcode == 2) {
                        return Err(wire_error("Неверная последовательность WebSocket"));
                    }
                    self.fragmented = !final_frame;
                    self.remaining = size;
                }
                8..=10 => {
                    let len = size as usize;
                    input.read_exact(&mut buffer[..len]).await?;
                    return Ok(Frame::Control(opcode, len));
                }
                _ => return Err(wire_error("Неподдерживаемый кадр WebSocket")),
            }
        }
        let limit = self.remaining.min(buffer.len() as u64) as usize;
        let count = input.read(&mut buffer[..limit]).await?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "Незавершённый кадр WebSocket",
            ));
        }
        self.remaining -= count as u64;
        Ok(Frame::Data(count))
    }
}

async fn read_byte<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Option<u8>> {
    let mut byte = [0];
    match input.read(&mut byte).await? {
        0 => Ok(None),
        _ => Ok(Some(byte[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_standard_websocket_accept_value() {
        assert_eq!(
            expected_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn streams_first_bytes_of_large_frame_before_the_tail() {
        let (mut server, mut client) = tokio::io::duplex(1024);
        let mut buffer = [0; 256];
        let mut frames = Frames::default();
        server.write_all(&[0x82, 127]).await.unwrap();
        server.write_u64(3 * 1024 * 1024).await.unwrap();
        server.write_all(b"test").await.unwrap();
        assert!(matches!(
            frames.read(&mut client, &mut buffer).await.unwrap(),
            Frame::Data(4)
        ));
        assert_eq!(&buffer[..4], b"test");
        drop(server);
        assert_eq!(
            frames
                .read(&mut client, &mut buffer)
                .await
                .err()
                .unwrap()
                .kind(),
            ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn fragmented_binary_message_can_include_ping() {
        let bytes = [2, 1, 7, 0x89, 1, 8, 0x80, 1, 9];
        let mut client = bytes.as_slice();
        let mut frames = Frames::default();
        let mut buffer = [0; 256];
        assert!(matches!(
            frames.read(&mut client, &mut buffer).await.unwrap(),
            Frame::Data(1)
        ));
        assert_eq!(buffer[0], 7);
        assert!(matches!(
            frames.read(&mut client, &mut buffer).await.unwrap(),
            Frame::Control(9, 1)
        ));
        assert_eq!(buffer[0], 8);
        assert!(matches!(
            frames.read(&mut client, &mut buffer).await.unwrap(),
            Frame::Data(1)
        ));
        assert_eq!(buffer[0], 9);
    }
}
