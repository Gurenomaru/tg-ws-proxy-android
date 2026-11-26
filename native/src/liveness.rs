use crate::wire;
use std::io::{self, ErrorKind};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::Duration;
use tokio::io::AsyncWrite;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::{sleep_until, timeout_at, Instant};

const PING_AFTER: Duration = Duration::from_secs(8);
const PONG_TIMEOUT: Duration = Duration::from_secs(5);
const STALL_AFTER: Duration = Duration::from_secs(20);
const RETRY_GAP: Duration = Duration::from_secs(4);
static NEXT_PING: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct Pending {
    since: Instant,
    last_sent: Instant,
    retried: bool,
    ping: Option<[u8; 8]>,
    answered: bool,
}

#[derive(Default)]
pub struct Liveness {
    pending: Mutex<Option<Pending>>,
    changed: Notify,
}

impl Liveness {
    pub fn sent(&self) {
        let mut pending = self.pending.lock().unwrap();
        let now = Instant::now();
        if let Some(state) = pending.as_mut() {
            state.retried |= now - state.last_sent >= RETRY_GAP;
            state.last_sent = now;
        } else {
            *pending = Some(Pending {
                since: now,
                last_sent: now,
                retried: false,
                ping: None,
                answered: false,
            });
            self.changed.notify_one();
        }
    }

    pub fn received(&self) {
        if self.pending.lock().unwrap().take().is_some() {
            self.changed.notify_one();
        }
    }

    pub fn started(&self) -> Option<std::time::Instant> {
        self.pending
            .lock()
            .unwrap()
            .map(|pending| pending.since.into_std())
    }

    pub fn pong(&self, bytes: &[u8]) {
        if let Some(pending) = self.pending.lock().unwrap().as_mut() {
            if !pending.answered && pending.ping.is_some_and(|ping| ping == bytes) {
                pending.answered = true;
                self.changed.notify_one();
            }
        }
    }

    pub async fn watch<W>(&self, websocket: Option<&AsyncMutex<W>>) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            let snapshot = *self.pending.lock().unwrap();
            let Some(snapshot) = snapshot else {
                self.changed.notified().await;
                continue;
            };

            let deadline = if websocket.is_none() || snapshot.answered {
                snapshot.since + STALL_AFTER
            } else if snapshot.ping.is_some() {
                snapshot.since + PING_AFTER + PONG_TIMEOUT
            } else {
                snapshot.since + PING_AFTER
            };
            tokio::select! {
                _ = self.changed.notified() => continue,
                _ = sleep_until(deadline) => {}
            }

            let token = {
                let mut pending = self.pending.lock().unwrap();
                let Some(current) = pending
                    .as_mut()
                    .filter(|state| state.since == snapshot.since)
                else {
                    continue;
                };
                if websocket.is_some() && !current.answered {
                    if current.ping.is_some() {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "WebSocket не ответил на Ping",
                        ));
                    }
                    let token = NEXT_PING.fetch_add(1, Ordering::Relaxed).to_be_bytes();
                    current.ping = Some(token);
                    Some(token)
                } else if Instant::now() >= current.since + STALL_AFTER {
                    if current.retried {
                        return Err(io::Error::new(ErrorKind::TimedOut, "Зависшее соединение"));
                    }
                    // Acknowledgements and continuous uploads may have no immediate reply.
                    *pending = None;
                    None
                } else {
                    None
                }
            };
            if let (Some(mut token), Some(writer)) = (token, websocket) {
                let send =
                    async { wire::write_frame(&mut *writer.lock().await, 9, &mut token).await };
                // A partial frame cannot be resumed safely after a failed write.
                timeout_at(snapshot.since + PING_AFTER + PONG_TIMEOUT, send)
                    .await
                    .map_err(|_| {
                        io::Error::new(ErrorKind::TimedOut, "Не удалось отправить Ping")
                    })??;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, Sink};
    use tokio::time::{sleep, timeout};

    #[tokio::test(start_paused = true)]
    async fn closes_websocket_with_no_pong() {
        let (writer, mut peer) = duplex(32);
        let writer = AsyncMutex::new(writer);
        let state = Liveness::default();
        state.sent();
        let (result, ping) = tokio::join!(state.watch(Some(&writer)), async {
            let mut frame = [0; 14];
            peer.read_exact(&mut frame).await.unwrap();
            frame
        });
        assert_eq!(ping[0], 0x89);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn accepts_matching_pong_without_closing_an_idle_relay() {
        let (writer, mut peer) = duplex(32);
        let writer = AsyncMutex::new(writer);
        let state = Liveness::default();
        state.sent();
        let (result, ()) = tokio::join!(
            timeout(Duration::from_secs(21), state.watch(Some(&writer))),
            async {
                let mut frame = [0; 14];
                peer.read_exact(&mut frame).await.unwrap();
                let mut pong = [0; 8];
                for i in 0..8 {
                    pong[i] = frame[6 + i] ^ frame[2 + i % 4];
                }
                state.pong(&pong);
            }
        );
        assert!(result.is_err());
        assert!(state.started().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn closes_raw_connection_after_repeated_unanswered_traffic() {
        let state = Liveness::default();
        state.sent();
        let (result, ()) = tokio::join!(state.watch::<Sink>(None), async {
            sleep(Duration::from_secs(5)).await;
            state.sent();
        });
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
    }
}
