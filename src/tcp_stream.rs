pub(crate) async fn tokio_create(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    #[cfg(target_os = "android")]
    {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        // for android vpn service, we need to call VPNService.protect(int) to protect the socket
        // https://developer.android.com/reference/android/net/VpnService.html#protect(int)
        use std::os::unix::io::AsRawFd;
        crate::android::protect_socket(socket.as_raw_fd())?;

        let stream = socket.connect(addr).await?;
        tune(&stream);
        Ok(stream)
    }

    #[cfg(not(target_os = "android"))]
    {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        tune(&stream);
        Ok(stream)
    }
}

pub(crate) fn std_create(addr: std::net::SocketAddr, timeout: Option<std::time::Duration>) -> std::io::Result<std::net::TcpStream> {
    use socket2::{Domain, SockAddr, Socket, Type};
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, None)?;

    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        crate::android::protect_socket(socket.as_raw_fd())?;
    }

    if let Some(timeout) = timeout {
        socket.connect_timeout(&SockAddr::from(addr), timeout)?;
    } else {
        socket.connect(&SockAddr::from(addr))?;
    }
    tune(&socket);

    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        Ok(unsafe { std::net::TcpStream::from_raw_fd(socket.into_raw_fd()) })
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
        Ok(unsafe { std::net::TcpStream::from_raw_socket(socket.into_raw_socket()) })
    }
}

const KEEPALIVE_TIME: std::time::Duration = std::time::Duration::from_secs(60);
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// Unacknowledged data sitting this long means the path is not delivering, so the kernel resets it.
#[cfg(any(target_os = "linux", target_os = "android"))]
const USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Enable keepalive so a peer that vanishes without a FIN does not hold a task for hours.
#[cfg(unix)]
pub(crate) fn tune(stream: &impl std::os::fd::AsFd) {
    apply_keepalive(&socket2::SockRef::from(stream));
}

#[cfg(windows)]
pub(crate) fn tune(stream: &impl std::os::windows::io::AsSocket) {
    apply_keepalive(&socket2::SockRef::from(stream));
}

fn apply_keepalive(sock: &socket2::SockRef<'_>) {
    if let Err(e) = sock.set_keepalive(true) {
        log::debug!("SO_KEEPALIVE not applied: {e}");
    }
    let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE_TIME);
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    let keepalive = keepalive.with_interval(KEEPALIVE_INTERVAL);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        log::debug!("tcp keepalive parameters not applied: {e}");
    }
    set_linux_timeouts(sock);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_linux_timeouts(sock: &socket2::SockRef<'_>) {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    let timeout_ms = u32::try_from(USER_TIMEOUT.as_millis()).unwrap_or(u32::MAX);
    let probes: libc::c_int = 3;
    let timeout_rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_USER_TIMEOUT,
            (&timeout_ms as *const u32).cast::<libc::c_void>(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if timeout_rc != 0 {
        log::debug!("TCP_USER_TIMEOUT not applied: {}", std::io::Error::last_os_error());
    }
    let probe_rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            (&probes as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if probe_rc != 0 {
        log::debug!("TCP_KEEPCNT not applied: {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_linux_timeouts(_sock: &socket2::SockRef<'_>) {}

/// Why a pooled socket should be dropped. This only looks at local socket state.
/// The connection pool calls it while holding its mutex, so it must not send a ping or wait.
pub(crate) fn inactive_reason(stream: &tokio::net::TcpStream) -> Option<String> {
    if let Some(stats) = crate::link_stall::tcp_stats_of_stream(stream)
        && stats.is_stalled()
    {
        return Some(format!("tcp window collapsed ({stats})"));
    }
    match stream.take_error() {
        Ok(Some(err)) => return Some(format!("socket error: {err}")),
        Err(err) => return Some(format!("socket error: {err}")),
        Ok(None) => {}
    }
    let sock = socket2::SockRef::from(stream);
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1];
    match sock.peek(&mut buf) {
        Ok(0) => Some(match crate::link_stall::tcp_stats_of_stream(stream) {
            Some(stats) => format!("peer closed ({stats})"),
            None => "peer closed".to_string(),
        }),
        Ok(_) => None,
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(err) => Some(format!("peek failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn connected_socket_stays_active_after_tune() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_accepted, _) = listener.accept().await.unwrap();
        super::tune(&client);
        assert!(super::inactive_reason(&client).is_none());
    }
}
