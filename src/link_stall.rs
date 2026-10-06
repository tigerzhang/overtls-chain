//! Detect an upstream tunnel whose TCP congestion window has collapsed, or
//! that has gone silent, and tell the caller to drop it so a new one is opened.
//!
//! A collapsed window still completes the WebSocket ping used to recycle pool
//! connections, so the socket can stay in service for hours while throughput
//! sits on the floor. `TCP_INFO` shows that state directly: `snd_cwnd` and
//! `snd_ssthresh` stuck at 2, with a growing retransmission count.

use std::fmt;
use std::time::{Duration, Instant};

/// Window at or below this, together with a matching ssthresh, is treated as collapsed.
const STALL_CWND: u32 = 2;
/// Retransmissions required before a small window counts as loss, not a fresh socket.
const STALL_RETRANS: u32 = 8;
/// How long the collapsed snapshot must persist while the socket is in use.
const STALL_HOLD: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// No inbound WebSocket frame for this long after a local ping means the path is black-holed.
const SILENCE_RESET: Duration = Duration::from_secs(15);

pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// `linux/uapi/linux/tcp.h` `tcp_info` fields, native endian.
const SND_SSTHRESH_OFF: usize = 76;
const SND_CWND_OFF: usize = 80;
const TOTAL_RETRANS_OFF: usize = 100;
const TCP_INFO_MIN_LEN: usize = TOTAL_RETRANS_OFF + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpLinkStats {
    pub snd_cwnd: u32,
    pub snd_ssthresh: u32,
    pub total_retrans: u32,
}

impl TcpLinkStats {
    pub(crate) fn is_stalled(self) -> bool {
        self.snd_cwnd <= STALL_CWND && self.snd_ssthresh <= STALL_CWND && self.total_retrans >= STALL_RETRANS
    }
}

impl fmt::Display for TcpLinkStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cwnd={} ssthresh={} retrans={}",
            self.snd_cwnd, self.snd_ssthresh, self.total_retrans
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResetReason {
    Collapsed(TcpLinkStats),
    Silent,
}

impl fmt::Display for ResetReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResetReason::Collapsed(stats) => write!(f, "tcp window collapsed ({stats})"),
            ResetReason::Silent => write!(f, "no inbound data after ping"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum LinkCheck {
    Ok { send_ping: bool },
    Reset(ResetReason),
}

#[derive(Debug)]
struct CollapseWatch {
    since: Option<Instant>,
}

impl CollapseWatch {
    fn new() -> Self {
        Self { since: None }
    }

    fn clear(&mut self) {
        self.since = None;
    }

    /// True once a stalled snapshot has been continuous for [`STALL_HOLD`].
    fn observe(&mut self, stats: Option<TcpLinkStats>, now: Instant) -> bool {
        if !stats.is_some_and(TcpLinkStats::is_stalled) {
            self.since = None;
            return false;
        }
        match self.since {
            None => {
                self.since = Some(now);
                false
            }
            Some(since) => now.saturating_duration_since(since) >= STALL_HOLD,
        }
    }
}

/// Ping, silence, and congestion-window watch for one upstream socket.
#[derive(Debug)]
pub(crate) struct LinkHealth {
    watch: CollapseWatch,
    last_ping: Option<Instant>,
    ping_sent_at: Option<Instant>,
}

impl LinkHealth {
    pub(crate) fn new() -> Self {
        Self {
            watch: CollapseWatch::new(),
            // The first keepalive waits one interval, so a just-opened socket is not probed
            // before the handshake that uses it has finished.
            last_ping: Some(Instant::now()),
            ping_sent_at: None,
        }
    }

    pub(crate) fn on_inbound(&mut self) {
        self.ping_sent_at = None;
    }

    pub(crate) fn poll(&mut self, stats: Option<TcpLinkStats>) -> LinkCheck {
        self.poll_at(stats, Instant::now())
    }

    fn poll_at(&mut self, stats: Option<TcpLinkStats>, now: Instant) -> LinkCheck {
        let silent = self
            .ping_sent_at
            .is_some_and(|sent| now.saturating_duration_since(sent) >= SILENCE_RESET);
        let stalled_stats = stats.filter(|stats| stats.is_stalled());
        let collapsed = self.watch.observe(stats, now);
        let reason = if collapsed {
            stalled_stats.map(ResetReason::Collapsed)
        } else if silent {
            Some(ResetReason::Silent)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.watch.clear();
            self.ping_sent_at = None;
            self.last_ping = Some(now);
            return LinkCheck::Reset(reason);
        }

        let send_ping = match self.last_ping {
            None => true,
            Some(sent) => now.saturating_duration_since(sent) >= PING_INTERVAL,
        };
        if send_ping {
            self.last_ping = Some(now);
            self.ping_sent_at = Some(now);
        }
        LinkCheck::Ok { send_ping }
    }
}

pub(crate) fn tcp_stats_of_stream(stream: &tokio::net::TcpStream) -> Option<TcpLinkStats> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::io::AsRawFd;
        read_tcp_info(stream.as_raw_fd())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = stream;
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_tcp_info(fd: std::os::unix::io::RawFd) -> Option<TcpLinkStats> {
    let mut buf = [0u8; 256];
    let mut len = buf.len() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 || (len as usize) < TCP_INFO_MIN_LEN {
        return None;
    }
    Some(TcpLinkStats {
        snd_ssthresh: read_u32(&buf, SND_SSTHRESH_OFF),
        snd_cwnd: read_u32(&buf, SND_CWND_OFF),
        total_retrans: read_u32(&buf, TOTAL_RETRANS_OFF),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stalled() -> TcpLinkStats {
        TcpLinkStats {
            snd_cwnd: 2,
            snd_ssthresh: 2,
            total_retrans: 162,
        }
    }

    fn healthy() -> TcpLinkStats {
        TcpLinkStats {
            snd_cwnd: 10,
            snd_ssthresh: 0x7fff_ffff,
            total_retrans: 1,
        }
    }

    #[test]
    fn brief_loss_is_not_a_stalled_link() {
        let stats = TcpLinkStats {
            snd_cwnd: 2,
            snd_ssthresh: 2,
            total_retrans: 3,
        };
        assert!(!stats.is_stalled());
    }

    #[test]
    fn recovered_window_is_not_a_stalled_link() {
        let stats = TcpLinkStats {
            snd_cwnd: 10,
            snd_ssthresh: 2,
            total_retrans: 162,
        };
        assert!(!stats.is_stalled());
    }

    #[test]
    fn collapsed_window_with_loss_is_stalled() {
        assert!(stalled().is_stalled());
    }

    #[test]
    fn collapsed_window_resets_only_after_it_holds() {
        let mut health = LinkHealth::new();
        let t0 = Instant::now();
        assert!(matches!(health.poll_at(Some(stalled()), t0), LinkCheck::Ok { .. }));
        assert!(matches!(
            health.poll_at(Some(stalled()), t0 + STALL_HOLD - Duration::from_millis(1)),
            LinkCheck::Ok { .. }
        ));
        assert!(matches!(
            health.poll_at(Some(stalled()), t0 + STALL_HOLD),
            LinkCheck::Reset(ResetReason::Collapsed(_))
        ));
    }

    #[test]
    fn recovery_before_the_hold_restarts_the_watch() {
        let mut health = LinkHealth::new();
        let t0 = Instant::now();
        let _ = health.poll_at(Some(stalled()), t0);
        let _ = health.poll_at(Some(healthy()), t0 + Duration::from_secs(5));
        assert!(matches!(health.poll_at(Some(stalled()), t0 + STALL_HOLD), LinkCheck::Ok { .. }));
        assert!(matches!(
            health.poll_at(Some(stalled()), t0 + STALL_HOLD + STALL_HOLD),
            LinkCheck::Reset(ResetReason::Collapsed(_))
        ));
    }

    #[test]
    fn silence_after_ping_resets() {
        let mut health = LinkHealth::new();
        let t0 = Instant::now();
        health.last_ping = None;
        assert!(matches!(health.poll_at(None, t0), LinkCheck::Ok { send_ping: true }));
        health.on_inbound();
        assert!(matches!(health.poll_at(None, t0 + SILENCE_RESET), LinkCheck::Ok { .. }));

        let mut health = LinkHealth::new();
        health.last_ping = None;
        assert!(matches!(health.poll_at(None, t0), LinkCheck::Ok { send_ping: true }));
        assert!(matches!(
            health.poll_at(None, t0 + SILENCE_RESET),
            LinkCheck::Reset(ResetReason::Silent)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn live_socket_reports_a_usable_window() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_accepted, _) = listener.accept().await.unwrap();
        let stats = tcp_stats_of_stream(&client).expect("TCP_INFO");
        assert_eq!(stats.total_retrans, 0, "{stats}");
        assert!((1..=64).contains(&stats.snd_cwnd), "{stats}");
        assert!(stats.snd_ssthresh > STALL_CWND, "{stats}");
        assert!(!stats.is_stalled(), "{stats}");
    }
}
