use crate::protocol::{self, ClientHello, RelayHello, HELLO_SIZE};
use crate::routes::{Config, Dc, Family, Health, Stage, Target};
use crate::wire::{self, Frame, Frames};
use ctr::cipher::StreamCipher;
use socket2::{SockRef, TcpKeepalive};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, TcpListener as StdListener};
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::io::{self as async_io, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

const SESSION_LIMIT: usize = 24;
const DIAL_LIMIT: usize = 24;
const DIAL_TIMEOUT: Duration = Duration::from_millis(3500);
const ROUTE_HEAD_START: Duration = Duration::from_millis(220);
const AUTO_SELECT_TIMEOUT: Duration = Duration::from_millis(6500);
const AUTO_DIAL_TIMEOUT: Duration = Duration::from_millis(1600);
const LIVE_DIAL_TIMEOUT: Duration = Duration::from_millis(1000);
const PRIVATE_SCAN_TIMEOUT: Duration = Duration::from_millis(1600);
const PUBLIC_SCAN_TIMEOUT: Duration = Duration::from_millis(2500);
const COMPARISON_WINDOW: Duration = Duration::from_millis(180);
const FIRST_REPLY_TIMEOUT: Duration = Duration::from_secs(6);
const TRANSFER_BUFFER: usize = 32 * 1024;
const SENT: u8 = 1;
const REPLIED: u8 = 2;

#[repr(i32)]
#[derive(Clone, Copy)]
pub enum Event {
    Opened,
    Limit,
    Accepted,
    Invalid,
    NoRoute,
    Request,
    Reply,
    NoReply,
    Stall,
}

pub trait Observer: Send + Sync {
    fn log(&self, line: &str);
    fn is_probe(&self, port: u16) -> bool;
    fn record(&self, probe: bool, event: Event);
}

#[derive(Default)]
struct NetworkState {
    health: Health,
    cellular: bool,
}

pub struct Engine {
    listener: Mutex<Option<StdListener>>,
    signal: watch::Sender<Option<Arc<NetworkState>>>,
    config: Arc<Config>,
    secret: [u8; 16],
    observer: Arc<dyn Observer>,
}

impl Engine {
    pub fn bind(
        port: u16,
        secret: [u8; 16],
        config: Config,
        observer: Arc<dyn Observer>,
    ) -> io::Result<Self> {
        let listener = StdListener::bind((Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        let (signal, _) = watch::channel(Some(Arc::new(NetworkState::default())));
        Ok(Self {
            listener: Mutex::new(Some(listener)),
            signal,
            config: Arc::new(config),
            secret,
            observer,
        })
    }

    pub fn close(&self) {
        self.signal.send_replace(None);
    }

    pub fn network_changed(&self, cellular: bool) {
        self.signal.send_if_modified(|state| {
            if state.is_none() {
                return false;
            }
            *state = Some(Arc::new(NetworkState {
                health: Health::default(),
                cellular,
            }));
            true
        });
    }

    pub async fn serve(&self) -> io::Result<()> {
        let listener = self
            .listener
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::new(ErrorKind::AlreadyExists, "Сервис уже запущен"))?;
        let listener = TcpListener::from_std(listener)?;
        let mut signal = self.signal.subscribe();
        let slots = Arc::new(Semaphore::new(SESSION_LIMIT));
        let dialing = Arc::new(Semaphore::new(DIAL_LIMIT));
        let measurements = Arc::new(Semaphore::new(DIAL_LIMIT));
        let mut sessions = JoinSet::new();
        loop {
            if signal.borrow_and_update().is_none() {
                return Ok(());
            }
            tokio::select! {
                _ = signal.changed() => {},
                _ = sessions.join_next(), if !sessions.is_empty() => {},
                result = listener.accept() => {
                    let (socket, peer) = result?;
                    let probe = self.observer.is_probe(peer.port());
                    self.observer.record(probe, Event::Opened);
                    let Ok(slot) = slots.clone().try_acquire_owned() else {
                        self.observer.record(probe, Event::Limit);
                        continue
                    };
                    let cancellation = self.signal.subscribe();
                    let ctx = SessionContext {
                        config: self.config.clone(), dialing: dialing.clone(),
                        measurements: measurements.clone(), observer: self.observer.clone(),
                        secret: self.secret, probe,
                    };
                    sessions.spawn(async move {
                        let _slot = slot;
                        run_session(socket, ctx, cancellation).await;
                    });
                }
            }
        }
    }
}

struct SessionContext {
    config: Arc<Config>,
    dialing: Arc<Semaphore>,
    measurements: Arc<Semaphore>,
    observer: Arc<dyn Observer>,
    secret: [u8; 16],
    probe: bool,
}

async fn run_session(
    mut socket: TcpStream,
    ctx: SessionContext,
    mut cancellation: watch::Receiver<Option<Arc<NetworkState>>>,
) {
    let network = cancellation.borrow_and_update().clone();
    let Some(network) = network else { return };
    let health = &network.health;
    let run = async {
        let started = Instant::now();
        socket.set_nodelay(true)?;
        let mut header = [0; HELLO_SIZE];
        timeout(Duration::from_secs(7), socket.read_exact(&mut header)).await??;
        let hello = protocol::accept(header, &ctx.secret).inspect_err(|_| {
            ctx.record(Event::Invalid);
        })?;
        ctx.record(Event::Accepted);
        let dc = Dc::decode(hello.dc);
        let selecting = Instant::now();
        let Some((target, upstream)) = select_route(&ctx, dc, &network).await else {
            ctx.record(Event::NoRoute);
            if health.report_no_route(dc) {
                ctx.observer
                    .log(&format!("{} · нет доступного маршрута", dc.label()));
            }
            return Ok::<(), io::Error>(());
        };
        ctx.observer.log(&format!(
            "{} · {} · выбор {} мс",
            dc.label(),
            target.description(),
            selecting.elapsed().as_millis()
        ));

        let relay = protocol::initiate(hello.mode, dc.relay_id(), None);
        let state = AtomicU8::new(0);
        let reply = Reply {
            state: &state,
            health,
            target: &target,
            ctx: &ctx,
            dc,
            progress: Mutex::new(Progress::default()),
            activity: Notify::new(),
        };
        let result = match upstream {
            Upstream::Tcp(stream) => relay_tcp(socket, stream, hello, relay, &reply).await,
            Upstream::WebSocket(stream) => {
                relay_websocket(socket, stream, hello, relay, &reply).await
            }
        };
        if state.load(Ordering::Relaxed) == SENT {
            ctx.record(Event::NoReply);
            health.failed(dc, &target, started, ctx.config.automatic);
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == ErrorKind::TimedOut)
            {
                ctx.observer.log(&format!(
                    "{} · {} · нет первого ответа",
                    dc.label(),
                    target.label
                ));
            }
        } else if let Err(error) = result {
            if error.kind() == ErrorKind::TimedOut {
                ctx.record(Event::Stall);
                let since = reply.progress.lock().unwrap().since.unwrap_or(started);
                health.failed(dc, &target, since, ctx.config.automatic);
                ctx.observer.log(&format!(
                    "{} · {} · зависшее соединение закрыто",
                    dc.label(),
                    target.label
                ));
            } else if error.kind() == ErrorKind::InvalidData {
                ctx.observer.log(&format!(
                    "{} · {} · ошибка обмена",
                    dc.label(),
                    target.label
                ));
            }
        }
        Ok(())
    };
    tokio::select! {
        _ = cancellation.changed() => {},
        _ = run => {},
    }
}

impl SessionContext {
    fn record(&self, event: Event) {
        self.observer.record(self.probe, event);
    }
}

fn sample(group: &[Stage], dc: Dc, health: &Health) -> Vec<Target> {
    let preferred = health.preferred(dc);
    let mut choices = Vec::new();
    for stage in group {
        let mut available: Vec<_> = stage
            .targets
            .iter()
            .filter(|target| health.ready(dc, target))
            .cloned()
            .collect();
        health.rotate(&mut available, stage.limit);
        if let Some(position) = available
            .iter()
            .position(|target| Some(target) == preferred.as_ref())
        {
            available.swap(0, position);
        }
        choices.extend(available.into_iter().take(stage.limit));
    }
    choices
}

async fn select_route(
    ctx: &SessionContext,
    dc: Dc,
    network: &NetworkState,
) -> Option<(Target, Upstream)> {
    let groups = ctx.config.groups(dc, network.cellular);
    let health = &network.health;
    if !ctx.config.automatic {
        for group in groups {
            let choices = sample(group, dc, health);
            if let Some(result) = race(ctx, dc, health, &choices, DIAL_TIMEOUT).await {
                return Some(result);
            }
            if let Some(retry) = choices
                .iter()
                .find(|target| target.sni.is_some() && health.ready(dc, target))
            {
                if let Some(result) =
                    race(ctx, dc, health, std::slice::from_ref(retry), DIAL_TIMEOUT).await
                {
                    return Some(result);
                }
            }
        }
        return None;
    }

    timeout(AUTO_SELECT_TIMEOUT, async {
        if let Some(preferred) = health
            .preferred(dc)
            .filter(|target| health.ready(dc, target))
        {
            if let Some(result) = race(ctx, dc, health, &[preferred], LIVE_DIAL_TIMEOUT).await {
                return Some(result);
            }
        }
        for index in 0..groups.len() {
            if let Some(mut ranked) = health.cached(dc, index) {
                ranked.retain(|target| health.ready(dc, target));
                if let Some(result) = race(ctx, dc, health, &ranked, AUTO_DIAL_TIMEOUT).await {
                    return Some(result);
                }
            }
        }
        for (index, group) in groups.iter().enumerate() {
            let mut ranked = measured_routes(ctx, dc, group, index, health).await;
            ranked.retain(|target| health.ready(dc, target));
            if let Some(result) = race(ctx, dc, health, &ranked, AUTO_DIAL_TIMEOUT).await {
                return Some(result);
            }
        }
        for group in groups {
            if let Some(result) = race(
                ctx,
                dc,
                health,
                &sample(group, dc, health),
                AUTO_DIAL_TIMEOUT,
            )
            .await
            {
                return Some(result);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn measured_routes(
    ctx: &SessionContext,
    dc: Dc,
    group: &[Stage],
    index: usize,
    health: &Health,
) -> Vec<Target> {
    let lock = health.measurement_lock(dc, index);
    let _measurement = lock.lock().await;
    if let Some(cached) = health.cached(dc, index) {
        if cached.is_empty() || cached.iter().any(|target| health.ready(dc, target)) {
            return cached;
        }
    }
    let cutoff = if group.first().is_some_and(|stage| stage.public_relay) {
        PUBLIC_SCAN_TIMEOUT
    } else {
        PRIVATE_SCAN_TIMEOUT
    };
    let mut tasks = JoinSet::new();
    for (order, target) in sample(group, dc, health).into_iter().enumerate() {
        let config = ctx.config.clone();
        let permits = ctx.measurements.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire().await.ok()?;
            let started = Instant::now();
            let upstream = dial(&target, &config).await.ok()?;
            verify(upstream, dc.relay_id()).await.ok()?;
            Some((started.elapsed(), order, target))
        });
    }

    let deadline = tokio::time::Instant::now() + cutoff;
    let mut until = deadline;
    let mut replies = Vec::new();
    while let Ok(Some(result)) = tokio::time::timeout_at(until, tasks.join_next()).await {
        if let Ok(Some(timing)) = result {
            if replies.is_empty() {
                until = deadline.min(tokio::time::Instant::now() + COMPARISON_WINDOW);
            }
            replies.push(timing);
        }
    }
    replies.sort_by_key(|(time, order, _)| (*time, *order));
    let ranked: Vec<_> = replies.into_iter().map(|(_, _, target)| target).collect();
    health.remember(dc, index, ranked.clone());
    ranked
}

async fn race(
    ctx: &SessionContext,
    dc: Dc,
    health: &Health,
    choices: &[Target],
    dial_timeout: Duration,
) -> Option<(Target, Upstream)> {
    let mut attempts = JoinSet::new();
    let label = choices.first()?.label.as_str();
    for (index, target) in choices.iter().cloned().enumerate() {
        let config = ctx.config.clone();
        let dialing = ctx.dialing.clone();
        attempts.spawn(async move {
            if index > 0 {
                sleep(ROUTE_HEAD_START).await;
            }
            let started = Instant::now();
            let result = timeout(dial_timeout, async {
                let _permit = dialing
                    .acquire()
                    .await
                    .map_err(|_| io::Error::new(ErrorKind::Interrupted, "Подключение отменено"))?;
                dial(&target, &config).await
            })
            .await
            .unwrap_or_else(|_| Err(io::Error::new(ErrorKind::TimedOut, "тайм-аут")));
            (target, started, result)
        });
    }
    let mut errors = Vec::new();
    while let Some(attempt) = attempts.join_next().await {
        if let Ok((target, started, result)) = attempt {
            match result {
                Ok(connection) => return Some((target, connection)),
                Err(error) => {
                    health.failed(dc, &target, started, ctx.config.automatic);
                    let message = match error.kind() {
                        ErrorKind::TimedOut => "тайм-аут",
                        ErrorKind::ConnectionRefused => "подключение отклонено",
                        ErrorKind::InvalidData => "ошибка TLS или протокола",
                        _ => "ошибка подключения",
                    };
                    if !errors.contains(&message) {
                        errors.push(message);
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        ctx.observer.log(&format!(
            "{} · {label} · {}",
            dc.label(),
            errors.join(" / ")
        ));
    }
    None
}

trait WebStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WebStream for T {}

enum Upstream {
    Tcp(TcpStream),
    WebSocket(Box<dyn WebStream>),
}

async fn verify(upstream: Upstream, dc: i16) -> io::Result<()> {
    let mut relay = protocol::initiate(protocol::Mode::Padded, dc, None);
    let mut request = protocol::Probe::new();
    relay.to_server.apply_keystream(&mut request.packet);
    match upstream {
        Upstream::Tcp(mut socket) => {
            socket.write_all(&relay.header).await?;
            socket.write_all(&request.packet).await?;
            let mut reply = Vec::new();
            protocol::read_packet(
                &mut socket,
                &mut relay.from_server,
                protocol::Mode::Padded,
                &mut reply,
            )
            .await?;
            request.verify(&reply)
        }
        Upstream::WebSocket(mut socket) => {
            wire::write_frame(&mut socket, 2, &mut relay.header).await?;
            wire::write_frame(&mut socket, 2, &mut request.packet).await?;
            let mut reply = [0; 44];
            let mut copied = 0;
            let mut frames = Frames::default();
            let mut buffer = [0; 125];
            while copied < reply.len() {
                match frames.read(&mut socket, &mut buffer).await? {
                    Frame::Data(length) => {
                        let count = length.min(reply.len() - copied);
                        reply[copied..copied + count].copy_from_slice(&buffer[..count]);
                        copied += count;
                    }
                    Frame::Control(9, length) => {
                        wire::write_frame(&mut socket, 10, &mut buffer[..length]).await?
                    }
                    Frame::Eof | Frame::Control(8, _) => {
                        return Err(ErrorKind::UnexpectedEof.into())
                    }
                    _ => {}
                }
            }
            relay.from_server.apply_keystream(&mut reply);
            request.verify(&reply)
        }
    }
}

async fn dial(target: &Target, config: &Config) -> io::Result<Upstream> {
    if target.socks {
        let proxy = config
            .socks
            .as_ref()
            .ok_or_else(|| wire::wire_error("SOCKS5 не настроен"))?;
        let mut socket = connect(
            proxy.host.trim_matches(['[', ']']),
            proxy.port,
            Family::System,
        )
        .await?;
        let destination = target
            .address
            .parse()
            .map_err(|_| wire::wire_error("Неверный адрес SOCKS5"))?;
        wire::socks(&mut socket, proxy, destination).await?;
        return Ok(Upstream::Tcp(socket));
    }
    let socket = connect(&target.address, target.port, target.family).await?;
    match target.path.as_deref() {
        None => Ok(Upstream::Tcp(socket)),
        Some(path) if target.port == 80 => Ok(Upstream::WebSocket(Box::new(
            wire::upgrade(socket, &target.host, path).await?,
        ))),
        Some(path) => {
            let stream = wire::tls(socket, &target.host, target.sni.as_deref()).await?;
            Ok(Upstream::WebSocket(Box::new(
                wire::upgrade(stream, &target.host, path).await?,
            )))
        }
    }
}

async fn connect(host: &str, port: u16, family: Family) -> io::Result<TcpStream> {
    let stream = if family == Family::System {
        TcpStream::connect((host, port)).await?
    } else {
        let address = lookup_host((host, port))
            .await?
            .find(|address| address.is_ipv4() == (family == Family::Ipv4))
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "Нет адреса нужного семейства"))?;
        TcpStream::connect(address).await?
    };
    stream.set_nodelay(true)?;
    let _ = SockRef::from(&stream)
        .set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(120)));
    Ok(stream)
}

#[derive(Default)]
struct Progress {
    since: Option<Instant>,
    last_sent: Option<Instant>,
    retried: bool,
}

struct Reply<'a> {
    state: &'a AtomicU8,
    health: &'a Health,
    target: &'a Target,
    ctx: &'a SessionContext,
    dc: Dc,
    progress: Mutex<Progress>,
    activity: Notify,
}

impl Reply<'_> {
    fn sent(&self, sender: &mut Option<oneshot::Sender<()>>) {
        if let Some(sender) = sender.take() {
            self.state.fetch_or(SENT, Ordering::Relaxed);
            self.ctx.record(Event::Request);
            let _ = sender.send(());
        }
        if self.state.load(Ordering::Relaxed) & REPLIED != 0 {
            let now = Instant::now();
            let mut progress = self.progress.lock().unwrap();
            if progress.since.is_none() {
                progress.since = Some(now);
                self.activity.notify_one();
            } else if progress
                .last_sent
                .is_some_and(|last| now - last >= Duration::from_secs(4))
            {
                progress.retried = true;
            }
            progress.last_sent = Some(now);
        }
    }

    fn received(&self) {
        let previous = self.state.load(Ordering::Relaxed);
        if previous & SENT != 0 && self.state.fetch_or(REPLIED, Ordering::Relaxed) & REPLIED == 0 {
            self.health.succeeded(self.dc, self.target);
            self.ctx.record(Event::Reply);
        }
        let mut progress = self.progress.lock().unwrap();
        if progress.since.is_some() {
            *progress = Progress::default();
            self.activity.notify_one();
        }
    }

    async fn deadline(&self, first: oneshot::Receiver<()>) -> io::Result<()> {
        if first.await.is_ok() {
            sleep(FIRST_REPLY_TIMEOUT).await;
            if self.state.load(Ordering::Relaxed) & REPLIED == 0 {
                return Err(io::Error::new(ErrorKind::TimedOut, "Нет первого ответа"));
            }
        }
        loop {
            let since = self.progress.lock().unwrap().since;
            if let Some(since) = since {
                let expires = tokio::time::Instant::from_std(since + Duration::from_secs(20));
                tokio::select! {
                    _ = tokio::time::sleep_until(expires) => {
                        let mut progress = self.progress.lock().unwrap();
                        if progress.since == Some(since) && progress.retried {
                            return Err(io::Error::new(ErrorKind::TimedOut, "Зависшее соединение"));
                        }
                        if progress.since == Some(since) {
                            *progress = Progress::default();
                        }
                    }
                    _ = self.activity.notified() => {}
                }
            } else {
                self.activity.notified().await;
            }
        }
    }
}

async fn relay_tcp(
    client: TcpStream,
    mut server: TcpStream,
    mut hello: ClientHello,
    mut relay: RelayHello,
    reply: &Reply<'_>,
) -> io::Result<()> {
    server.write_all(&relay.header).await?;
    let (mut local_read, mut local_write) = client.into_split();
    let (mut remote_read, mut remote_write) = server.into_split();
    let (first_sender, first_receiver) = oneshot::channel();
    let upload = async {
        let mut first = Some(first_sender);
        let mut buffer = vec![0; TRANSFER_BUFFER];
        loop {
            let len = local_read.read(&mut buffer).await?;
            if len == 0 {
                remote_write.shutdown().await?;
                sleep(Duration::from_secs(15)).await;
                return Ok(());
            }
            reply.sent(&mut first);
            let data = &mut buffer[..len];
            hello.from_client.apply_keystream(data);
            relay.to_server.apply_keystream(data);
            remote_write.write_all(data).await?;
        }
    };
    let download = async {
        let mut buffer = vec![0; TRANSFER_BUFFER];
        loop {
            let len = remote_read.read(&mut buffer).await?;
            if len == 0 {
                return Ok(());
            }
            let data = &mut buffer[..len];
            relay.from_server.apply_keystream(data);
            hello.to_client.apply_keystream(data);
            local_write.write_all(data).await?;
            reply.received();
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        result = reply.deadline(first_receiver) => result,
    }
}

async fn relay_websocket<S>(
    client: TcpStream,
    mut server: S,
    mut hello: ClientHello,
    mut relay: RelayHello,
    reply: &Reply<'_>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    wire::write_frame(&mut server, 2, &mut relay.header).await?;
    let (mut local_read, mut local_write) = client.into_split();
    let (mut remote_read, remote_write) = async_io::split(server);
    let remote_write = AsyncMutex::new(remote_write);
    let (first_sender, first_receiver) = oneshot::channel();
    let upload = async {
        let mut first = Some(first_sender);
        let mut packet = Vec::new();
        loop {
            protocol::read_packet(
                &mut local_read,
                &mut hello.from_client,
                hello.mode,
                &mut packet,
            )
            .await?;
            reply.sent(&mut first);
            relay.to_server.apply_keystream(&mut packet);
            wire::write_frame(&mut *remote_write.lock().await, 2, &mut packet).await?;
        }
    };
    let download = async {
        let mut buffer = vec![0; TRANSFER_BUFFER];
        let mut frames = Frames::default();
        loop {
            match frames.read(&mut remote_read, &mut buffer).await? {
                Frame::Data(len) => {
                    let data = &mut buffer[..len];
                    relay.from_server.apply_keystream(data);
                    hello.to_client.apply_keystream(data);
                    local_write.write_all(data).await?;
                    reply.received();
                }
                Frame::Control(9, len) => {
                    wire::write_frame(&mut *remote_write.lock().await, 10, &mut buffer[..len])
                        .await?;
                }
                Frame::Control(8, len) => {
                    wire::write_frame(&mut *remote_write.lock().await, 8, &mut buffer[..len])
                        .await?;
                    return Ok(());
                }
                Frame::Eof => return Ok(()),
                _ => {}
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        result = reply.deadline(first_receiver) => result,
    }
}
