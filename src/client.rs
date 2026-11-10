use crate::{
    addess_to_b64str,
    config::{Client, Config},
    error::{Error, Result},
    server::{END_SESSION, REMOTE_EOF, START_SESSION},
    tls::*,
    udprelay,
    weirduri::WeirdUri,
};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use socks_hub_core::{BoxedStream, HttpConnector, UserKey, run_http_service};
use socks5_impl::{
    Address,
    protocol::Reply,
    server::{
        AuthAdaptor, ClientConnection, Connect, IncomingConnection,
        auth::{NoAuth, UserKeyAuth},
        connection::connect::NeedReply,
    },
};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        client::IntoClientRequest,
        handshake::{
            client::{self, Response},
            machine::TryParse,
        },
        protocol::{Message, Role},
    },
};

pub async fn run_client<F>(config: &Config, quit: crate::CancellationToken, callback: Option<F>) -> Result<()>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    log::info!("starting {} {} client...", clap::crate_name!(), crate::cmdopt::version_info());
    #[cfg(not(target_os = "ios"))]
    {
        log::trace!("with following settings:");
        log::trace!("{}", serde_json::to_string_pretty(config)?);
    }

    let client = config.client.as_ref().ok_or("client")?;

    let listen_user = client.listen_user.as_deref().filter(|s| !s.is_empty());
    if let Some(user) = listen_user {
        let listen_password = client.listen_password.as_deref().unwrap_or("");
        let key = UserKeyAuth::new(user, listen_password);
        _run_client(config, Arc::new(key), quit, callback).await?;
    } else {
        _run_client(config, Arc::new(NoAuth), quit, callback).await?;
    }
    Ok(())
}

async fn _run_client<F>(config: &Config, auth: AuthAdaptor, quit: crate::CancellationToken, callback: Option<F>) -> Result<()>
where
    F: FnOnce(SocketAddr) + Send + Sync + 'static,
{
    let client = config.client.as_ref().ok_or("client")?;
    let addr = SocketAddr::new(client.listen_host.parse()?, client.listen_port);

    let server = TcpListener::bind(addr).await?;

    let pool_max_size = client.pool_max_size.map_or(Some(crate::config::DEFAULT_POOL_MAX_SIZE), Some);

    if let Some(callback) = callback {
        callback(server.local_addr()?);
    }

    if config.disable_tls() {
        let manager = WsPlainConnectionManager { config: config.clone() };
        let connection_pool = ConnectionPool::new(pool_max_size, None, None, None, manager);
        client_event_loop::<_, TcpStream>(connection_pool, quit, server, auth, config).await?;
    } else {
        let manager = WsTlsConnectionManager { config: config.clone() };
        let connection_pool = ConnectionPool::new(pool_max_size, None, None, None, manager);
        client_event_loop::<_, TlsStream<TcpStream>>(connection_pool, quit, server, auth, config).await?;
    };
    Ok(())
}

async fn client_event_loop<M, S>(
    pool: Arc<ConnectionPool<M>>,
    quit: crate::CancellationToken,
    server: TcpListener,
    auth: AuthAdaptor,
    config: &Config,
) -> Result<()>
where
    M: ConnectionManager<Connection = WebSocketStream<S>> + Send + Sync + 'static,
    S: AsyncReadWrite + Unpin + Send + Sync + 'static,
{
    let (udp_tx, _, incomings) = udprelay::create_udp_tunnel();
    udprelay::udp_handler_watchdog(config, &incomings, &udp_tx, quit.clone()).await?;

    let session_id = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let session_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let stats_pool = pool.clone();
    let stats_incomings = incomings.clone();
    crate::perf::spawn_reporter(
        "client",
        session_count.clone(),
        move || {
            let pool = stats_pool.clone();
            let incomings = stats_incomings.clone();
            async move {
                Some(crate::perf::PoolSnapshot {
                    idle: pool.pool_size().await,
                    outstanding: pool.outstanding_count(),
                    max: pool.max_size(),
                    udp_sources: incomings.lock().await.len(),
                })
            }
        },
        quit.clone(),
    );

    loop {
        tokio::select! {
            _ = quit.cancelled() => {
                log::info!("exiting...");
                break;
            }
            result = server.accept() => {
                let (conn, _) = result?;
                let config = config.clone();
                let udp_tx = udp_tx.clone();
                let incomings = incomings.clone();
                let session_id = session_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let session_count = session_count.clone();
                let peer_addr = conn.peer_addr()?;
                let pool = pool.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    let count = session_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    log::debug!("session #{session_id} from {peer_addr} started, session count {count}");
                    if let Err(e) = handle_listener_stream(conn, auth, config, udp_tx, incomings, pool).await {
                        log::debug!("{peer_addr} {e}");
                    }
                    let count = session_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1;
                    log::debug!("session #{session_id} from {peer_addr} ended, session count {count}");
                });
            }
        }
    }

    Ok(())
}

const LOCAL_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const SLOW_ACQUIRE: std::time::Duration = std::time::Duration::from_millis(200);

async fn wait_http_session<S>(stream: &mut WebSocketStream<S>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, async {
        while let Some(message) = stream.next().await {
            match message.map_err(std::io::Error::other)? {
                Message::Text(text) if text.as_str() == START_SESSION => return Ok(()),
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => break,
            }
        }
        Err(std::io::Error::other("remote HTTP proxy connection failed"))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP proxy session timed out"))?
}

/// HTTP tunnels are not recycled, and must not inherit an unfinished SOCKS session.
async fn create_http_ws_stream(config: &Config) -> std::io::Result<WsBoxStream> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let client = config.client.as_ref().ok_or("client not exist")?;
        let addr = client.server_ip_addr().ok_or("server host")?;
        let stream: BoxStream = if config.disable_tls() {
            Box::new(crate::tcp_stream::tokio_create(addr).await?)
        } else if client.dangerous_mode.unwrap_or(false) {
            let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);
            Box::new(create_dangerous_tls_client_stream(addr, domain).await?)
        } else {
            let cert_store = retrieve_root_cert_store_for_client(&client.certificate_content())?;
            let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);
            Box::new(create_tls_client_stream(cert_store, addr, domain).await?)
        };
        create_ws_stream(None, config, None, stream).await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP upstream connection timed out"))?
    .map_err(std::io::Error::other)
}

async fn handle_listener_stream<M, S>(
    stream: TcpStream,
    auth: AuthAdaptor,
    config: Config,
    udp_tx: udprelay::UdpRequestSender,
    incomings: udprelay::SocketAddrHashSet,
    pool: Arc<ConnectionPool<M>>,
) -> Result<()>
where
    M: ConnectionManager<Connection = WebSocketStream<S>> + Send + Sync + 'static,
    S: AsyncReadWrite + Unpin + Send + Sync + 'static,
{
    let mut first = [0];
    let n = tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, stream.peek(&mut first))
        .await
        .map_err(|_| Error::from("local protocol detection timed out"))??;
    if n == 0 {
        return Ok(());
    }
    if first[0] == 5 {
        return handle_incoming(IncomingConnection::new(stream, auth), config, Some(udp_tx), incomings, pool).await;
    }
    if !first[0].is_ascii_alphabetic() {
        return Ok(());
    }
    let client = config.client.as_ref().ok_or("client")?;
    let credentials = match client.listen_user.as_deref().filter(|s| !s.is_empty()) {
        Some(user) => UserKey::new(user, client.listen_password.as_deref().unwrap_or("")),
        None => UserKey::default(),
    };
    let src = stream.peer_addr()?;
    let connector: HttpConnector = Arc::new(move |dst| {
        let config = config.clone();
        Box::pin(async move {
            // SOCKS sessions can leave unread data/EOF messages on recycled WebSockets.
            // HTTP already closes its link after use, so establish a fresh one rather than
            // interpreting a previous SOCKS session's messages as this request's result.
            let mut ws = create_http_ws_stream(&config).await.map_err(|e| {
                log::warn!("{src} HTTP upstream connection failed for {dst}: {e}");
                e
            })?;
            let command = format!("{START_SESSION}:{}", addess_to_b64str(&dst, false));
            ws.send(Message::Text(command.into())).await.map_err(std::io::Error::other)?;
            wait_http_session(&mut ws).await.map_err(|e| {
                log::warn!("{src} HTTP session failed for {dst}: {e}");
                e
            })?;
            let (local, tunnel) = tokio::io::duplex(crate::STREAM_BUFFER_SIZE);
            tokio::spawn(async move {
                if let Err(e) = client_traffic_loop(tunnel, &mut ws, src, dst, true).await {
                    log::debug!("{src} HTTP tunnel ended: {e}");
                }
                let _ = ws.close(None).await;
            });
            Ok(Box::new(local) as BoxedStream)
        })
    });
    run_http_service(stream, connector, credentials).await?;
    Ok(())
}

async fn handle_incoming<M, S>(
    conn: IncomingConnection,
    config: Config,
    udp_tx: Option<udprelay::UdpRequestSender>,
    incomings: udprelay::SocketAddrHashSet,
    pool: Arc<ConnectionPool<M>>,
) -> Result<()>
where
    M: ConnectionManager<Connection = WebSocketStream<S>> + Send + Sync + 'static,
    S: AsyncReadWrite + Unpin + Send + Sync + 'static,
{
    let peer_addr = conn.peer_addr()?;
    let conn = match tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, conn.authenticate()).await {
        Ok(res) => res?,
        Err(_) => {
            log::warn!("perf {peer_addr} socks authenticate timed out after {LOCAL_HANDSHAKE_TIMEOUT:?}");
            return Err(Error::from(format!("{peer_addr} socks authenticate timed out")));
        }
    };
    let request = match tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, conn.wait_request()).await {
        Ok(res) => res?,
        Err(_) => {
            log::warn!("perf {peer_addr} socks request timed out after {LOCAL_HANDSHAKE_TIMEOUT:?}");
            return Err(Error::from(format!("{peer_addr} socks request timed out")));
        }
    };
    match request {
        ClientConnection::UdpAssociate(asso, _) => {
            if let Some(udp_tx) = udp_tx {
                if let Err(e) = udprelay::handle_s5_upd_associate(asso, udp_tx, incomings, config).await {
                    log::debug!("{peer_addr} handle_s5_upd_associate \"{e}\"");
                }
            } else {
                let mut conn = asso.reply(Reply::CommandNotSupported, Address::unspecified_v4()).await?;
                conn.shutdown().await?;
            }
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind.reply(Reply::CommandNotSupported, Address::unspecified_v4()).await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            let acquire_started = std::time::Instant::now();
            let acquired = pool.clone().get_connection().await;
            let waited = acquire_started.elapsed();
            crate::perf::note_acquire(waited, acquired.is_ok());
            if waited >= SLOW_ACQUIRE {
                log::warn!(
                    "perf slow pool acquire {waited:?} for {peer_addr} -> {addr}, ok={} outstanding={} idle={} max={}",
                    acquired.is_ok(),
                    pool.outstanding_count(),
                    pool.pool_size().await,
                    pool.max_size(),
                );
            }
            let mut ws_stream = match acquired {
                Ok(stream) => stream,
                Err(e) => {
                    log::warn!("perf pool acquire failed for {peer_addr} -> {addr}: {e}");
                    let mut failed = connect.reply(Reply::GeneralFailure, Address::unspecified_v4()).await?;
                    let _ = failed.shutdown().await;
                    return Ok(());
                }
            };
            if let Err(e) = handle_socks5_cmd_connection::<S>(connect, addr.clone(), config, &mut *ws_stream).await {
                log::debug!("{peer_addr} <> {addr} {e}");
                // A failed upstream must not go back into the pool. Ping-based validation used to
                // reject it, but that ping ran while the pool mutex was held and stalled every checkout.
                if is_upstream_failure(&e) {
                    log::warn!("perf discard upstream link {peer_addr} <> {addr}: {e}");
                    crate::perf::note_pool_drop();
                    let _dead = ws_stream.into_inner();
                }
            }
        }
    }

    log::trace!("{peer_addr} disconnected");

    Ok(())
}

async fn handle_socks5_cmd_connection<S>(
    connect: Connect<NeedReply>,
    target_addr: Address,
    _config: Config,
    ws_stream: &mut WebSocketStream<S>,
) -> Result<()>
where
    S: AsyncReadWrite + Unpin + Send + Sync + 'static,
{
    let incoming = connect.reply(Reply::Succeeded, Address::unspecified_v4()).await?;

    let peer_addr = incoming.peer_addr()?;

    log::trace!("{peer_addr} -> {target_addr} tunnel establishing");

    client_traffic_loop(incoming, ws_stream, peer_addr, target_addr, false).await?;
    Ok(())
}

async fn client_traffic_loop<T, S>(
    mut incoming: T,
    ws_stream: &mut WebSocketStream<S>,
    src: SocketAddr,
    dst: Address,
    mut session_confirmed: bool,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: AsyncReadWrite + Unpin,
{
    // Send "Start session" command with target address
    let b64_addr = addess_to_b64str(&dst, false);
    let start_cmd = format!("{START_SESSION}:{b64_addr}");
    if !session_confirmed {
        ws_stream.send(Message::Text(start_cmd.into())).await?;
    }

    let mut link_health = crate::link_stall::LinkHealth::new();
    let mut link_check = tokio::time::interval(crate::link_stall::CHECK_INTERVAL);
    link_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown_deadline: Option<tokio::time::Instant> = None;
    loop {
        let mut buf = BytesMut::with_capacity(crate::STREAM_BUFFER_SIZE);
        tokio::select! {
            // Only allow reading from local connection after session_confirmed
            result = async {
                if session_confirmed {
                    incoming.read_buf(&mut buf).await
                } else {
                    futures_util::future::pending::<std::io::Result<usize>>().await
                }
            } => {
                let len = result?;
                if len == 0 {
                    log::debug!("{src} -> {dst} incoming closed");
                    // Send "End session" text message
                    ws_stream.send(Message::Text(END_SESSION.into())).await?;
                    break;
                }
                ws_stream.send(Message::binary(buf.to_vec())).await?;
                log::trace!("{src} -> {dst} length {}", buf.len());

                if let Err(e) = crate::traffic_status::traffic_status_update(len, 0) {
                    log::error!("{e}");
                }

                buf.clear();
            }
            result = ws_stream.next() => {
                let msg = match result {
                    Some(Ok(msg)) => msg,
                    Some(Err(err)) => return Err(err.into()),
                    None => return Err(Error::from("upstream: websocket closed")),
                };
                link_health.on_inbound();

                if let Err(e) = crate::traffic_status::traffic_status_update(0, msg.len()) {
                    log::error!("{e}");
                }

                match msg {
                    Message::Binary(data) => {
                        incoming.write_all(&data).await?;
                        log::trace!("{src} <- {dst} length {}", data.len());
                    }
                    Message::Close(_) => {
                        log::debug!("perf {src} <- {dst} websocket closed, discarding link");
                        return Err(Error::from("upstream: websocket close"));
                    }
                    Message::Text(data) => {
                        let msg_str = data.as_str();
                        if let Some(reason) = msg_str.strip_prefix(END_SESSION) {
                            let reason = reason.strip_prefix(':').unwrap_or(reason).trim();
                            log::debug!("{src} <- {dst} session ended by remote message '{END_SESSION}' with reason: '{reason}'");
                            break;
                        } else if msg_str.starts_with(START_SESSION) {
                            session_confirmed = true;
                            log::debug!("{src} <- {dst} received '{START_SESSION}' confirmation from server");
                        } else if msg_str == REMOTE_EOF {
                            log::debug!("{src} <- {dst} received from server the '{REMOTE_EOF}' indication");
                            // Force shutdown after 1 second
                            shutdown_deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
                        } else {
                            log::warn!("{src} <- {dst} unexpected Websocket text from remote: {msg_str}");
                        }
                    }
                    Message::Ping(_) => {
                        log::trace!("{src} <- {dst} Websocket ping from remote");
                    }
                    Message::Pong(_) => {
                        log::trace!("{src} <- {dst} Websocket pong from remote");
                    }
                    _ => {}
                }
            }
            _ = link_check.tick() => {
                let stats = ws_stream.get_ref().tcp_link_stats();
                match link_health.poll(stats) {
                    crate::link_stall::LinkCheck::Reset(reason) => {
                        log::warn!("perf {src} <> {dst} upstream link stalled ({reason}), resetting");
                        let _ = ws_stream.close(None).await;
                        return Err(Error::from(format!("upstream: link stalled ({reason})")));
                    }
                    crate::link_stall::LinkCheck::Ok { send_ping: true } => {
                        if let Err(e) = send_keepalive_ping(ws_stream).await {
                            log::warn!("perf {src} <> {dst} {e}, resetting");
                            let _ = ws_stream.close(None).await;
                            return Err(e);
                        }
                        log::trace!("{src} -> {dst} Websocket ping from local");
                    }
                    crate::link_stall::LinkCheck::Ok { send_ping: false } => {}
                }
            }
            _ = async {
                if let Some(deadline) = shutdown_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            } => {
                log::debug!("{src} <> {dst} forcibly closed after 1 second of '{REMOTE_EOF}' indication");
                ws_stream.send(Message::Text(END_SESSION.into())).await?;
                let _ = incoming.shutdown().await;
                break;
            }
        }
    }
    Ok(())
}

pub(crate) async fn create_chain_ws_stream(
    chain: &crate::config::Chain,
    dst_addr: Option<Address>,
    udp_tunnel: Option<bool>,
) -> Result<WsBoxStream> {
    let mut client = Client::default();
    client.disable_tls = chain.disable_tls;
    client.client_id = chain.client_id.clone();
    client.server_host = chain.server_host.clone();
    client.server_port = chain.server_port;
    client.server_domain = chain.server_domain.clone();
    client.cafile = chain.cafile.clone();
    client.dangerous_mode = chain.dangerous_mode;
    client.listen_host = String::new();
    client.listen_port = 0;
    let config = Config {
        client: Some(client),
        tunnel_path: chain.tunnel_path.clone().unwrap_or_default(),
        ..Config::default()
    };

    let server_addr = match chain.server_ip_addr {
        Some(addr) => addr,
        None => {
            let mut addrs = (chain.server_host.as_str(), chain.server_port).to_socket_addrs()?;
            addrs.next().ok_or("chain server ip addr not set")?
        }
    };

    if chain.disable_tls.unwrap_or(false) {
        let stream = crate::tcp_stream::tokio_create(server_addr).await?;
        let boxed: BoxStream = Box::new(stream);
        return create_ws_stream(dst_addr, &config, udp_tunnel, boxed).await;
    }

    let stream: BoxStream = if chain.dangerous_mode.unwrap_or(false) {
        log::warn!("Dangerous mode enabled on chain, skipping certificate verification.");
        let domain = chain.server_domain.as_ref().unwrap_or(&chain.server_host);
        let tls_stream = create_dangerous_tls_client_stream(server_addr, domain).await?;
        Box::new(tls_stream)
    } else {
        let cert_content = chain.certificate_content();
        let cert_store = retrieve_root_cert_store_for_client(&cert_content)?;
        let domain = chain.server_domain.as_ref().unwrap_or(&chain.server_host);
        let tls_stream = create_tls_client_stream(cert_store, server_addr, domain).await?;
        Box::new(tls_stream)
    };

    create_ws_stream(dst_addr, &config, udp_tunnel, stream).await
}

pub(crate) async fn create_tls_ws_stream(
    svr_addr: SocketAddr,
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
) -> Result<WsTlsStream> {
    let client = config.client.as_ref().ok_or("client not exist")?;

    if client.dangerous_mode.unwrap_or(false) {
        log::warn!("Dangerous mode enabled, this will skip certificate verification. It is not recommended for production use");
        let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);
        let stream = create_dangerous_tls_client_stream(svr_addr, domain).await?;
        let ws_stream = create_ws_stream(dst_addr, config, udp_tunnel, stream).await?;
        return Ok(ws_stream);
    }

    let cert_content = client.certificate_content();
    let cert_store = retrieve_root_cert_store_for_client(&cert_content)?;
    let domain = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let stream = create_tls_client_stream(cert_store, svr_addr, domain).await?;

    let ws_stream = create_ws_stream(dst_addr, config, udp_tunnel, stream).await?;
    Ok(ws_stream)
}

pub(crate) async fn create_plaintext_ws_stream(
    server_addr: SocketAddr,
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
) -> Result<WsStream> {
    let stream = crate::tcp_stream::tokio_create(server_addr).await?;
    let ws_stream = create_ws_stream(dst_addr, config, udp_tunnel, stream).await?;
    Ok(ws_stream)
}

pub(crate) async fn create_ws_stream<S: AsyncRead + AsyncWrite + Unpin>(
    dst_addr: Option<Address>,
    config: &Config,
    udp_tunnel: Option<bool>,
    mut stream: S,
) -> Result<WebSocketStream<S>> {
    let client = config.client.as_ref().ok_or("client not exist")?;
    let err = "tunnel path not exist";
    let tunnel_path = config.tunnel_path.extract().first().ok_or(err)?.trim_matches('/');

    let b64_dst = dst_addr.as_ref().map(|dst_addr| addess_to_b64str(dst_addr, false));
    let host = client.server_domain.as_ref().unwrap_or(&client.server_host);

    let uri = format!("ws://{host}/{tunnel_path}/");

    let uri = WeirdUri::new(&uri, b64_dst, udp_tunnel, client.client_id.clone());

    let (v, key) = client::generate_request(uri.into_client_request()?)?;
    stream.write_all(&v).await?;

    let mut buf = BytesMut::with_capacity(2048);
    stream.read_buf(&mut buf).await?;

    let response = Response::try_parse(&buf)?.ok_or("response parse failed")?.1;
    let remote_key = response.headers().get("Sec-WebSocket-Accept").ok_or(format!("{response:?}"))?;

    let accept_key = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());

    if accept_key.as_str() != remote_key.to_str().map_err(|e| e.to_string())? {
        return Err(Error::from("accept key error"));
    }

    let ws_stream = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    // let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, stream).await?;

    Ok(ws_stream)
}

type WsStream = WebSocketStream<TcpStream>;
type WsTlsStream = WebSocketStream<TlsStream<TcpStream>>;
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {
    fn tcp_link_stats(&self) -> Option<crate::link_stall::TcpLinkStats> {
        None
    }

    fn inactive_reason(&self) -> Option<String> {
        None
    }
}

impl AsyncReadWrite for TcpStream {
    fn tcp_link_stats(&self) -> Option<crate::link_stall::TcpLinkStats> {
        crate::link_stall::tcp_stats_of_stream(self)
    }

    fn inactive_reason(&self) -> Option<String> {
        crate::tcp_stream::inactive_reason(self)
    }
}

impl AsyncReadWrite for TlsStream<TcpStream> {
    fn tcp_link_stats(&self) -> Option<crate::link_stall::TcpLinkStats> {
        crate::link_stall::tcp_stats_of_stream(self.get_ref().0)
    }

    fn inactive_reason(&self) -> Option<String> {
        crate::tcp_stream::inactive_reason(self.get_ref().0)
    }
}

impl<T> AsyncReadWrite for Box<T>
where
    T: AsyncReadWrite + Unpin + ?Sized,
{
    fn tcp_link_stats(&self) -> Option<crate::link_stall::TcpLinkStats> {
        (**self).tcp_link_stats()
    }

    fn inactive_reason(&self) -> Option<String> {
        (**self).inactive_reason()
    }
}

type BoxStream = Box<dyn AsyncReadWrite + Unpin + Send + Sync>;
pub(crate) type WsBoxStream = WebSocketStream<BoxStream>;

use connection_pool::{ConnectionManager, ConnectionPool};
use std::future::Future;
use std::pin::Pin;

const PING_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ping the upstream, but do not wait forever. A collapsed send window makes `send` park until
/// the buffer drains, which also stops the link check that is supposed to reset that socket.
pub(crate) async fn send_keepalive_ping<S>(stream: &mut WebSocketStream<S>) -> Result<()>
where
    S: AsyncReadWrite + Unpin,
{
    match tokio::time::timeout(PING_SEND_TIMEOUT, stream.send(Message::Ping(vec![].into()))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            crate::perf::note_stall();
            Err(Error::from(format!("upstream: ping failed: {e}")))
        }
        Err(_) => {
            crate::perf::note_stall();
            let stats = stream
                .get_ref()
                .tcp_link_stats()
                .map(|stats| stats.to_string())
                .unwrap_or_else(|| "tcp stats unavailable".to_string());
            Err(Error::from(format!(
                "upstream: ping send blocked for {PING_SEND_TIMEOUT:?} ({stats})"
            )))
        }
    }
}

fn is_upstream_failure(err: &Error) -> bool {
    match err {
        Error::Tungstenite(_) => true,
        Error::String(msg) => msg.starts_with("upstream:"),
        _ => false,
    }
}

#[derive(Clone)]
pub struct WsPlainConnectionManager {
    pub config: Config,
}

impl ConnectionManager for WsPlainConnectionManager {
    type Connection = WsStream;
    type Error = Error;
    type CreateFut = Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send>>;
    type ValidFut<'a>
        = Pin<Box<dyn Future<Output = bool> + Send + 'a>>
    where
        Self: 'a;

    fn create_connection(&self) -> Self::CreateFut {
        let config = self.config.clone();
        Box::pin(async move {
            let client = config.client.as_ref().ok_or("client not exist")?;
            let server_addr = client.server_ip_addr().ok_or("server host")?;
            let ws = create_plaintext_ws_stream(server_addr, None, &config, None).await?;
            Ok(ws)
        })
    }

    fn is_valid<'a>(&'a self, stream: &'a mut Self::Connection) -> Self::ValidFut<'a> {
        Box::pin(async move { ws_link_is_usable(stream) })
    }
}

#[derive(Clone)]
pub struct WsTlsConnectionManager {
    pub config: Config,
}

impl ConnectionManager for WsTlsConnectionManager {
    type Connection = WsTlsStream;
    type Error = Error;
    type CreateFut = Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send>>;
    type ValidFut<'a>
        = Pin<Box<dyn Future<Output = bool> + Send + 'a>>
    where
        Self: 'a;

    fn create_connection(&self) -> Self::CreateFut {
        let config = self.config.clone();
        Box::pin(async move {
            let client = config.client.as_ref().ok_or("client not exist")?;
            let server_addr = client.server_ip_addr().ok_or("server host")?;
            let ws = create_tls_ws_stream(server_addr, None, &config, None).await?;
            Ok(ws)
        })
    }

    fn is_valid<'a>(&'a self, stream: &'a mut Self::Connection) -> Self::ValidFut<'a> {
        Box::pin(async move { ws_link_is_usable(stream) })
    }
}

fn ws_link_is_usable<S>(stream: &WebSocketStream<S>) -> bool
where
    S: AsyncReadWrite + Unpin,
{
    // Checkout and the pool's background cleanup both call this while holding the pool mutex.
    // A ping here blocks every other request for the round trip, which is how a few slow
    // upstreams made the whole proxy slower the longer it ran.
    if let Some(reason) = stream.get_ref().inactive_reason() {
        log::warn!("perf drop pooled link ({reason})");
        crate::perf::note_pool_drop();
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio_tungstenite::{accept_async, connect_async};

    #[tokio::test]
    async fn test_create_chain_ws_stream_to_local_plaintext_server() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let mut ws = accept_async(socket).await?;
            let msg = ws.next().await.ok_or("no initial message")??;
            assert!(matches!(msg, Message::Text(text) if text.starts_with(START_SESSION)));
            ws.send(Message::Text(START_SESSION.into())).await?;
            Ok::<(), Error>(())
        });

        let chain = crate::config::Chain {
            disable_tls: Some(true),
            client_id: Some("proxy-a".to_string()),
            server_host: "127.0.0.1".to_string(),
            server_port: addr.port(),
            server_domain: Some("127.0.0.1".to_string()),
            tunnel_path: Some(crate::config::TunnelPath::Single("/b-tunnel/".to_string())),
            ..Default::default()
        };

        let mut ws = create_chain_ws_stream(&chain, None, None).await?;
        let target = Address::from(("127.0.0.1", 80));
        let text = format!("{}:{}", START_SESSION, addess_to_b64str(&target, false));
        ws.send(Message::Text(text.into())).await?;

        let msg = ws.next().await.ok_or("no response from server")??;
        assert_eq!(msg, Message::Text(START_SESSION.into()));

        server.await.unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_svr_chain_tunnel_forwards_start_session_confirmation() -> Result<()> {
        let b_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let b_addr = b_listener.local_addr()?;

        let b_server = tokio::spawn(async move {
            let (socket, _) = b_listener.accept().await?;
            let mut ws = accept_async(socket).await?;

            let msg = ws.next().await.ok_or("no start-session from A")??;
            assert!(matches!(msg, Message::Text(text) if text.starts_with(START_SESSION)));
            ws.send(Message::Text(START_SESSION.into())).await?;

            Ok::<(), Error>(())
        });

        let chain = crate::config::Chain {
            disable_tls: Some(true),
            client_id: Some("proxy-a".to_string()),
            server_host: "127.0.0.1".to_string(),
            server_port: b_addr.port(),
            server_domain: Some("127.0.0.1".to_string()),
            tunnel_path: Some(crate::config::TunnelPath::Single("/b-tunnel/".to_string())),
            ..Default::default()
        };

        let a_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let a_addr = a_listener.local_addr()?;

        let a_chain = chain.clone();
        let a_server = tokio::spawn(async move {
            let (socket, _) = a_listener.accept().await?;
            let ws = accept_async(socket).await?;
            let traffic_audit = Arc::new(tokio::sync::Mutex::new(crate::traffic_audit::TrafficAudit::new()));
            let config = crate::config::Config {
                tunnel_path: crate::config::TunnelPath::Single("/tunnel/".to_string()),
                ..Default::default()
            };
            crate::server::svr_chain_tunnel(ws, a_addr, config, traffic_audit, &None, None, a_chain).await
        });

        let (mut client_ws, _) = connect_async(format!("ws://127.0.0.1:{}/tunnel/", a_addr.port())).await?;
        let target = Address::from(("127.0.0.1", 80));
        let start_msg = format!("{}:{}", START_SESSION, addess_to_b64str(&target, false));
        client_ws.send(Message::Text(start_msg.into())).await?;

        let msg = client_ws.next().await.ok_or("no confirmation from A")??;
        assert_eq!(msg, Message::Text(START_SESSION.into()));

        a_server.await.unwrap()?;
        b_server.await.unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_svr_udp_chain_tunnel_forwards_binary() -> Result<()> {
        let b_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let b_addr = b_listener.local_addr()?;

        let b_server = tokio::spawn(async move {
            let (socket, _) = b_listener.accept().await?;
            let mut ws = accept_async(socket).await?;
            while let Some(msg) = ws.next().await {
                let msg = msg?;
                match msg {
                    Message::Binary(data) => {
                        ws.send(Message::Binary(data)).await?;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            Ok::<(), Error>(())
        });

        let chain = crate::config::Chain {
            disable_tls: Some(true),
            client_id: Some("proxy-a".to_string()),
            server_host: "127.0.0.1".to_string(),
            server_port: b_addr.port(),
            server_domain: Some("127.0.0.1".to_string()),
            tunnel_path: Some(crate::config::TunnelPath::Single("/b-tunnel/".to_string())),
            ..Default::default()
        };

        let a_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let a_addr = a_listener.local_addr()?;

        let a_chain = chain.clone();
        let a_server = tokio::spawn(async move {
            let (socket, _) = a_listener.accept().await?;
            let ws = accept_async(socket).await?;
            let traffic_audit = Arc::new(Mutex::new(crate::traffic_audit::TrafficAudit::new()));
            let config = crate::config::Config {
                tunnel_path: crate::config::TunnelPath::Single("/tunnel/".to_string()),
                ..Default::default()
            };
            crate::server::svr_udp_chain_tunnel(ws, config, traffic_audit, &None, a_chain).await
        });

        let (mut client_ws, _) = connect_async(format!("ws://127.0.0.1:{}/tunnel/", a_addr.port())).await?;
        let payload = b"udp-chain-test".to_vec();
        client_ws.send(Message::Binary(payload.clone().into())).await?;

        let msg = client_ws.next().await.ok_or("no response from A")??;
        assert_eq!(msg, Message::Binary(payload.into()));

        client_ws.close(None).await?;
        a_server.await.unwrap()?;
        b_server.await.unwrap()?;
        Ok(())
    }
}

#[cfg(test)]
mod http_proxy_tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    async fn proxy(auth: bool) -> (TcpStream, crate::CancellationToken, tokio::task::JoinHandle<()>) {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let remote = tokio::spawn(async move {
            // Configuration validation first probes the upstream TCP port.
            let (probe, _) = upstream.accept().await.unwrap();
            drop(probe);
            let mut ws = loop {
                let (stream, _) = upstream.accept().await.unwrap();
                let mut udp = false;
                let ws = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
                        udp = req.headers().contains_key("udp-tunnel");
                        Ok(resp)
                    },
                )
                .await
                .unwrap();
                if !udp {
                    break ws;
                }
                tokio::spawn(async move {
                    let mut ws = ws;
                    while let Some(Ok(_)) = ws.next().await {}
                });
            };
            let start = ws.next().await.unwrap().unwrap();
            let Message::Text(start) = start else {
                panic!("missing session command")
            };
            let target = crate::b64str_to_address(start.strip_prefix(&format!("{START_SESSION}:")).unwrap(), false).unwrap();
            assert_eq!(target.to_string(), "example.com:80");
            ws.send(Message::Text(START_SESSION.into())).await.unwrap();
            let request = ws.next().await.unwrap().unwrap();
            let Message::Binary(request) = request else {
                panic!("missing request")
            };
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.starts_with("GET / ") || request.starts_with("GET http://example.com/ "),
                "{request}"
            );
            assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
            ws.send(Message::Binary(b"HTTP/1.0 200 OK\r\n\r\nhello".to_vec().into()))
                .await
                .unwrap();
            ws.send(Message::Text(REMOTE_EOF.into())).await.unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                if msg.is_close() {
                    break;
                }
            }
        });
        let mut config = Config {
            tunnel_path: crate::config::TunnelPath::Single("/test/".into()),
            client: Some(
                serde_json::from_value(serde_json::json!({
                    "disable_tls": true,
                    "server_host": "127.0.0.1",
                    "server_port": upstream_addr.port(),
                    "listen_host": "127.0.0.1",
                    "listen_port": 0,
                    "listen_user": auth.then_some("alice"),
                    "listen_password": auth.then_some("secret"),
                }))
                .unwrap(),
            ),
            ..Default::default()
        };
        config.check_correctness(false).unwrap();
        let quit = crate::CancellationToken::new();
        let stop = quit.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            run_client(
                &config,
                stop,
                Some(move |addr| {
                    let _ = tx.send(addr);
                }),
            )
            .await
            .unwrap();
            remote.abort();
        });
        let stream = TcpStream::connect(rx.await.unwrap()).await.unwrap();
        (stream, quit, task)
    }

    async fn response(stream: &mut TcpStream) -> Vec<u8> {
        let mut data = Vec::new();
        timeout(Duration::from_secs(3), stream.read_to_end(&mut data))
            .await
            .unwrap()
            .unwrap();
        data
    }

    #[tokio::test]
    async fn forwards_fragmented_http_until_remote_eof() {
        let (mut stream, quit, task) = proxy(false).await;
        stream.write_all(b"G").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream
            .write_all(b"ET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let data = response(&mut stream).await;
        assert!(data.starts_with(b"HTTP/1.0 200"));
        assert!(data.ends_with(b"hello"));
        quit.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_tunnels_bytes() {
        let (mut stream, quit, task) = proxy(false).await;
        stream
            .write_all(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
            .await
            .unwrap();
        let mut header = Vec::new();
        timeout(Duration::from_secs(3), async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(header.starts_with(b"HTTP/1.1 200"));
        stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        assert!(response(&mut stream).await.ends_with(b"hello"));
        quit.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_http_requests() {
        let (mut stream, quit, task) = proxy(true).await;
        stream
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut header = Vec::new();
        timeout(Duration::from_secs(3), async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(header.starts_with(b"HTTP/1.1 407"));
        stream
            .write_all(b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n")
            .await
            .unwrap();
        assert!(response(&mut stream).await.ends_with(b"hello"));
        quit.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn still_accepts_socks5() {
        let (mut stream, quit, task) = proxy(false).await;
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, [5, 0]);
        quit.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn http_does_not_reuse_socks_socket_with_unread_eof() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let (stale_tx, stale_rx) = tokio::sync::oneshot::channel();
        let remote = tokio::spawn(async move {
            let (probe, _) = upstream.accept().await.unwrap();
            drop(probe);
            let (old, _) = upstream.accept().await.unwrap();
            let mut old = tokio_tungstenite::accept_async(old).await.unwrap();
            // The socket is still live, but the previous SOCKS session left a frame unread.
            old.send(Message::Text(REMOTE_EOF.into())).await.unwrap();
            stale_tx.send(()).unwrap();

            let (fresh, _) = upstream.accept().await.unwrap();
            let mut fresh = tokio_tungstenite::accept_async(fresh).await.unwrap();
            assert!(matches!(fresh.next().await.unwrap().unwrap(), Message::Text(text) if text.starts_with(START_SESSION)));
            fresh.send(Message::Text(START_SESSION.into())).await.unwrap();
            assert!(matches!(fresh.next().await.unwrap().unwrap(), Message::Binary(_)));
            fresh
                .send(Message::Binary(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec().into(),
                ))
                .await
                .unwrap();
            fresh.send(Message::Text(REMOTE_EOF.into())).await.unwrap();
            while let Some(Ok(message)) = fresh.next().await {
                if message.is_close() {
                    break;
                }
            }
            drop(old);
        });
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "tunnel_path": "/test/",
            "client_settings": {
                "disable_tls": true, "server_host": "127.0.0.1", "server_port": addr.port(),
                "listen_host": "127.0.0.1", "listen_port": 0
            }
        }))
        .unwrap();
        config.check_correctness(false).unwrap();
        let pool = ConnectionPool::new(Some(1), None, None, None, WsPlainConnectionManager { config: config.clone() });
        let old = pool.clone().get_connection().await.unwrap();
        stale_rx.await.unwrap();
        drop(old);
        timeout(Duration::from_secs(3), async {
            while pool.pool_size().await != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let handler_pool = pool.clone();
        let handler = tokio::spawn(async move {
            let (incoming, _) = listener.accept().await.unwrap();
            let (udp_tx, _, incomings) = udprelay::create_udp_tunnel();
            handle_listener_stream(incoming, Arc::new(NoAuth), config, udp_tx, incomings, handler_pool)
                .await
                .unwrap();
        });
        stream
            .write_all(b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let data = response(&mut stream).await;
        assert!(data.starts_with(b"HTTP/1.0 200"));
        assert!(data.ends_with(b"hello"));
        assert_eq!(pool.pool_size().await, 1, "HTTP must leave the SOCKS pool untouched");
        handler.await.unwrap();
        timeout(Duration::from_secs(3), remote).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_failed_remote_session() {
        let (client, server) = tokio::io::duplex(4096);
        let mut client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        server.send(Message::Text(START_SESSION.into())).await.unwrap();
        wait_http_session(&mut client).await.unwrap();
        server.send(Message::Text(END_SESSION.into())).await.unwrap();
        assert!(wait_http_session(&mut client).await.is_err());
    }
}
