//! Limits on the TCP connections themselves, below HTTP.
//!
//! The request limiter only runs once a whole request has arrived, and `axum::serve` has no timeout
//! of its own, so a client that opens a connection and sends one header byte every few seconds held
//! a file descriptor for as long as it liked (measured: 2000 such connections, none closed in five
//! minutes, descriptors growing one for one). The 0.1.12 audit found it.
//!
//! * `MCP_MAX_CONNECTIONS` (default 1024): connections held open at once. Past it, `accept` waits
//!   and one warning a minute says so on stderr.
//! * `MCP_MAX_CONNECTIONS_PER_IP` (default max(8, MCP_MAX_CONNECTIONS / 8); with `MCP_TRUST_PROXY`
//!   set, MCP_MAX_CONNECTIONS, because then every connection comes from the proxy): connections
//!   from one TCP peer address. A new connection past it closes that address's longest-idle
//!   connection; if none of them is idle, the new one is closed. The peer is the TCP address, never
//!   `X-Forwarded-For`, which the client writes. Without this, one client holding every slot and
//!   sending `GET /health` on each every few seconds kept the server answering nobody else.
//! * `MCP_CONN_TIMEOUT_SECS` (default 120): the time a started request has to produce its first
//!   response byte, and the time a response may make no progress while the client is not reading.
//!   A client that dribbles a request, or pipelines requests and never reads the answers, is closed
//!   after it.
//! * A connection waiting for its next request (keep-alive, or never used) is closed after 15 s, or
//!   after the budget if that is shorter.
//! * No connection lives longer than ten budgets, however active it is.
//!
//! The request clock is deliberately "time to first response byte", not "time to finish the
//! headers": below HTTP there is no telling where the headers end, and the response is the one
//! event that proves the request was complete. Legitimate requests stay well inside it because
//! `statement_timeout` is 30s by default.

use axum::serve::Listener;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, Instant, Sleep};

pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 1024;
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// How long a connection may wait for its next request.
pub(crate) const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
/// The hard ceiling on a connection's life, in budgets.
pub(crate) const LIFETIME_BUDGETS: u32 = 10;

pub(crate) fn max_connections() -> usize {
    std::env::var("MCP_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_CONNECTIONS)
}

pub(crate) fn max_per_ip() -> usize {
    let max = max_connections();
    let trust = std::env::var("MCP_TRUST_PROXY").is_ok_and(|v| v == "1" || v == "true");
    std::env::var("MCP_MAX_CONNECTIONS_PER_IP")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(if trust { max } else { (max / 8).max(8) })
        .min(max)
}

pub(crate) fn timeout() -> Duration {
    Duration::from_secs(
        std::env::var("MCP_CONN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
    )
}

/// The peer address as the handlers see it. `axum` only implements `Connected` for its own listener,
/// and the orphan rule keeps us from adding that for `SocketAddr`, so the address travels in a
/// wrapper of ours that dereferences to it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Peer(pub(crate) SocketAddr);

impl std::ops::Deref for Peer {
    type Target = SocketAddr;
    fn deref(&self) -> &SocketAddr {
        &self.0
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, Limited>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Limited>) -> Self {
        Peer(*stream.remote_addr())
    }
}

/// The three clocks of a connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Clocks {
    /// first response byte after a request starts; progress of a response the client is not reading
    pub(crate) budget: Duration,
    /// waiting for the next request
    pub(crate) idle: Duration,
    /// whole life, whatever it does
    pub(crate) lifetime: Duration,
}

impl Clocks {
    pub(crate) fn from_budget(budget: Duration) -> Self {
        Self {
            budget,
            idle: KEEPALIVE_IDLE.min(budget),
            lifetime: budget * LIFETIME_BUDGETS,
        }
    }
}

/// What the listener knows about one open connection, shared with the stream that owns it.
struct Slot {
    id: u64,
    /// milliseconds since the listener started, at the last byte read or written
    last_active: AtomicU64,
    /// a request has started and no response byte has gone out yet
    busy: AtomicBool,
    /// the listener asked this connection to close to make room
    evicted: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Slot {
    fn evict(&self) {
        self.evicted.store(true, Ordering::SeqCst);
        if let Some(w) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            w.wake();
        }
    }
}

type Table = Arc<Mutex<HashMap<IpAddr, Vec<Arc<Slot>>>>>;

/// Says something on stderr at most once a minute per kind, so an operator sees why connections
/// are waiting or being closed, and a flood cannot turn into a flood of log lines.
struct Warner {
    last: Mutex<HashMap<&'static str, std::time::Instant>>,
}

impl Warner {
    fn warn(&self, kind: &'static str, msg: impl FnOnce() -> String) {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if last
            .get(kind)
            .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
        {
            return;
        }
        last.insert(kind, now);
        eprintln!("{}", msg());
    }
}

pub(crate) struct Limited {
    inner: TcpListener,
    permits: Arc<Semaphore>,
    max: usize,
    per_ip: usize,
    clocks: Clocks,
    table: Table,
    epoch: Instant,
    next_id: u64,
    warner: Arc<Warner>,
}

impl Limited {
    pub(crate) fn new(inner: TcpListener, max: usize, per_ip: usize, clocks: Clocks) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max)),
            max,
            per_ip: per_ip.clamp(1, max.max(1)),
            clocks,
            table: Arc::new(Mutex::new(HashMap::new())),
            epoch: Instant::now(),
            next_id: 0,
            warner: Arc::new(Warner {
                last: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Makes room for one more connection from `ip`. Returns false when the address is at its cap
    /// and every one of its connections is in the middle of a request.
    fn admit(&self, ip: IpAddr) -> bool {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        let mine = table.entry(ip).or_default();
        if mine.len() < self.per_ip {
            return true;
        }
        let victim = mine
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.busy.load(Ordering::SeqCst))
            .min_by_key(|(_, s)| s.last_active.load(Ordering::SeqCst))
            .map(|(i, _)| i);
        let per_ip = self.per_ip;
        match victim {
            Some(i) => {
                mine.swap_remove(i).evict();
                self.warner.warn("per-ip-evict", || {
                    format!(
                        "connections: {ip} holds MCP_MAX_CONNECTIONS_PER_IP ({per_ip}) connections; \
                         closing its longest-idle one for each new one (shown once a minute)"
                    )
                });
                true
            }
            None => {
                self.warner.warn("per-ip-refuse", || {
                    format!(
                        "connections: {ip} holds MCP_MAX_CONNECTIONS_PER_IP ({per_ip}) busy \
                         connections; refusing its new ones (shown once a minute)"
                    )
                });
                false
            }
        }
    }
}

impl Listener for Limited {
    type Io = Guarded;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // The permit is taken BEFORE accepting, so a full table leaves new connections in the
            // kernel's backlog instead of in our descriptor table.
            let permit = match self.permits.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    let max = self.max;
                    self.warner.warn("global-full", || {
                        format!(
                            "connections: MCP_MAX_CONNECTIONS ({max}) are open; new connections \
                             wait in the kernel backlog until one closes (shown once a minute)"
                        )
                    });
                    self.permits
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("the connection semaphore is never closed")
                }
            };
            let (stream, addr) = loop {
                match self.inner.accept().await {
                    Ok(pair) => break pair,
                    // EMFILE and friends: back off instead of spinning.
                    Err(_) => sleep(Duration::from_millis(100)).await,
                }
            };
            if !self.admit(addr.ip()) {
                drop(stream);
                continue;
            }
            self.next_id += 1;
            let slot = Arc::new(Slot {
                id: self.next_id,
                last_active: AtomicU64::new(self.epoch.elapsed().as_millis() as u64),
                busy: AtomicBool::new(false),
                evicted: AtomicBool::new(false),
                waker: Mutex::new(None),
            });
            self.table
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(addr.ip())
                .or_default()
                .push(slot.clone());
            let io = Guarded::new(
                stream,
                permit,
                self.clocks,
                slot,
                self.table.clone(),
                addr.ip(),
                self.epoch,
            );
            return (io, addr);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A `TcpStream` with the clocks described above, holding its slot until it is dropped.
pub(crate) struct Guarded {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    clocks: Clocks,
    timer: Pin<Box<Sleep>>,
    /// when the connection must close whatever it is doing
    end_of_life: Instant,
    /// A request has started and no response byte has gone out yet.
    receiving: bool,
    /// The idle clock is running (the server is waiting for the next request).
    idle_armed: bool,
    slot: Arc<Slot>,
    table: Table,
    ip: IpAddr,
    epoch: Instant,
}

impl Guarded {
    fn new(
        inner: TcpStream,
        permit: OwnedSemaphorePermit,
        clocks: Clocks,
        slot: Arc<Slot>,
        table: Table,
        ip: IpAddr,
        epoch: Instant,
    ) -> Self {
        let now = Instant::now();
        let end_of_life = now + clocks.lifetime;
        Self {
            inner,
            _permit: permit,
            clocks,
            timer: Box::pin(tokio::time::sleep_until(
                (now + clocks.idle).min(end_of_life),
            )),
            end_of_life,
            receiving: false,
            idle_armed: true,
            slot,
            table,
            ip,
            epoch,
        }
    }

    /// Restarts the clock at `d` from now, never past the end of life.
    fn restart(&mut self, d: Duration) {
        let at = (Instant::now() + d).min(self.end_of_life);
        self.timer.as_mut().reset(at);
    }

    fn touch(&self) {
        self.slot
            .last_active
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::SeqCst);
    }

    /// The checks every Pending goes through: evicted, out of time. Registers the waker with both
    /// the timer and the slot, so either can end the wait.
    fn must_close(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.slot.evicted.load(Ordering::SeqCst) {
            return Some(closed(
                "connection closed to make room for a newer one from the same address",
            ));
        }
        *self.slot.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
        if self.slot.evicted.load(Ordering::SeqCst) {
            return Some(closed(
                "connection closed to make room for a newer one from the same address",
            ));
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            return Some(timed_out());
        }
        None
    }

    /// The checks a Ready result goes through: a connection that never waits still ages.
    fn past_end(&self) -> Option<io::Error> {
        if self.slot.evicted.load(Ordering::SeqCst) {
            return Some(closed(
                "connection closed to make room for a newer one from the same address",
            ));
        }
        (Instant::now() >= self.end_of_life).then(timed_out)
    }
}

impl Drop for Guarded {
    fn drop(&mut self) {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mine) = table.get_mut(&self.ip) {
            mine.retain(|s| s.id != self.slot.id);
            if mine.is_empty() {
                table.remove(&self.ip);
            }
        }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "connection exceeded its time budget",
    )
}

fn closed(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, msg)
}

impl AsyncRead for Guarded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(e) = this.past_end() {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.touch();
                    this.idle_armed = false;
                    // Bytes arrived. If we were idle, the clock now runs against the first response
                    // byte; if a request was already in progress it keeps running from where it was,
                    // so dribbling one byte at a time buys nothing.
                    if !this.receiving {
                        this.receiving = true;
                        this.slot.busy.store(true, Ordering::SeqCst);
                        this.restart(this.clocks.budget);
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Waiting for a request with none in progress: the short keep-alive clock, started
                // once, from the first wait.
                if !this.receiving && !this.idle_armed {
                    this.idle_armed = true;
                    let at = (Instant::now() + this.clocks.idle).min(this.timer.deadline());
                    this.timer.as_mut().reset(at);
                }
                match this.must_close(cx) {
                    Some(e) => Poll::Ready(Err(e)),
                    None => Poll::Pending,
                }
            }
        }
    }
}

impl AsyncWrite for Guarded {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(e) = this.past_end() {
            return Poll::Ready(Err(e));
        }
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) if n > 0 => {
                // A response byte went out: the request was whole. The clock now measures the
                // progress of the response; a client that stops reading stalls it.
                this.touch();
                this.receiving = false;
                this.idle_armed = false;
                this.slot.busy.store(false, Ordering::SeqCst);
                this.restart(this.clocks.budget);
                Poll::Ready(Ok(n))
            }
            Poll::Pending => match this.must_close(cx) {
                Some(e) => Poll::Ready(Err(e)),
                None => Poll::Pending,
            },
            r => r,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => match this.must_close(cx) {
                Some(e) => Poll::Ready(Err(e)),
                None => Poll::Pending,
            },
            r => r,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair(budget_ms: u64, max: usize) -> (Limited, TcpStream, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let lim = Limited::new(
            l,
            max,
            max,
            Clocks::from_budget(Duration::from_millis(budget_ms)),
        );
        let client = TcpStream::connect(addr).await.unwrap();
        (lim, client, addr)
    }

    #[tokio::test]
    async fn a_client_that_dribbles_a_request_is_cut_off_after_the_budget() {
        let (mut lim, mut client, _) = pair(400, 8).await;
        let (mut io, _) = lim.accept().await;
        client.write_all(b"POST /mcp HTTP/1.1\r\n").await.unwrap();
        let writer = tokio::spawn(async move {
            // one header byte at a time, never finishing: what a slow-connection attack does
            for _ in 0..40 {
                if client.write_all(b"X").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let started = std::time::Instant::now();
        let mut buf = [0u8; 64];
        let err = loop {
            match io.read(&mut buf).await {
                Ok(0) => panic!("closed without a timeout"),
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(1500));
        writer.abort();
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed_and_a_served_one_gets_a_fresh_clock() {
        let (mut lim, mut client, _) = pair(300, 8).await;
        let (mut io, _) = lim.accept().await;
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(io.read(&mut buf).await.unwrap(), 4);
        tokio::time::sleep(Duration::from_millis(200)).await;
        io.write_all(b"pong").await.unwrap(); // response out: the clock restarts
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.write_all(b"ping").await.unwrap();
        assert_eq!(io.read(&mut buf).await.unwrap(), 4, "still alive 400ms in");
        let err = io.read(&mut buf).await.unwrap_err(); // now idle past the budget
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn past_the_cap_accept_waits_until_a_slot_frees() {
        let (mut lim, _c1, addr) = pair(5_000, 1).await;
        let (first, _) = lim.accept().await;
        let _c2 = TcpStream::connect(addr).await.unwrap();
        let waited = tokio::time::timeout(Duration::from_millis(300), lim.accept()).await;
        assert!(
            waited.is_err(),
            "second accept must wait while the slot is held"
        );
        drop(first);
        let again = tokio::time::timeout(Duration::from_millis(500), lim.accept()).await;
        assert!(again.is_ok(), "and proceed once it is released");
    }

    async fn listener(max: usize, per_ip: usize, clocks: Clocks) -> (Limited, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        (Limited::new(l, max, per_ip, clocks), addr)
    }

    fn clocks(budget_ms: u64, idle_ms: u64, life_ms: u64) -> Clocks {
        Clocks {
            budget: Duration::from_millis(budget_ms),
            idle: Duration::from_millis(idle_ms),
            lifetime: Duration::from_millis(life_ms),
        }
    }

    /// R2 of the 0.1.12 review: one address holding every slot. Past its own cap, its oldest idle
    /// connection makes room for the new one, so a newcomer from that address (a health check,
    /// another client behind the same NAT) is still served.
    #[tokio::test]
    async fn past_the_per_address_cap_the_longest_idle_connection_makes_room() {
        let (mut lim, addr) = listener(64, 2, clocks(5_000, 5_000, 50_000)).await;
        let _c1 = TcpStream::connect(addr).await.unwrap();
        let (mut io1, _) = lim.accept().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _c2 = TcpStream::connect(addr).await.unwrap();
        let (mut io2, _) = lim.accept().await;
        let reader1 = tokio::spawn(async move {
            let mut b = [0u8; 4];
            io1.read(&mut b).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _c3 = TcpStream::connect(addr).await.unwrap();
        let third = tokio::time::timeout(Duration::from_millis(500), lim.accept()).await;
        assert!(third.is_ok(), "the third connection must be accepted");
        let r1 = tokio::time::timeout(Duration::from_millis(500), reader1)
            .await
            .expect("the oldest idle connection must be closed promptly")
            .unwrap();
        assert_eq!(r1.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        // the second one is untouched
        let mut b = [0u8; 4];
        let r2 = tokio::time::timeout(Duration::from_millis(200), io2.read(&mut b)).await;
        assert!(r2.is_err(), "the newer connection must stay open");
        assert_eq!(lim.table.lock().unwrap().get(&addr.ip()).unwrap().len(), 2);
    }

    /// When every connection of the address is mid-request, nothing is cut short: the newcomer goes.
    #[tokio::test]
    async fn at_the_cap_with_every_connection_busy_the_new_one_is_refused() {
        let (mut lim, addr) = listener(64, 1, clocks(5_000, 5_000, 50_000)).await;
        let mut c1 = TcpStream::connect(addr).await.unwrap();
        let (mut io1, _) = lim.accept().await;
        c1.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let mut b = [0u8; 64];
        assert!(io1.read(&mut b).await.unwrap() > 0); // a request is in progress
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        let waited = tokio::time::timeout(Duration::from_millis(300), lim.accept()).await;
        assert!(
            waited.is_err(),
            "the busy connection's address gets no new slot"
        );
        let n = tokio::time::timeout(Duration::from_millis(500), c2.read(&mut b))
            .await
            .expect("the refused connection is closed, not left hanging");
        assert_eq!(n.unwrap_or(0), 0);
        // and once the request is answered, the address may connect again
        io1.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let _c3 = TcpStream::connect(addr).await.unwrap();
        let again = tokio::time::timeout(Duration::from_millis(500), lim.accept()).await;
        assert!(again.is_ok());
    }

    /// Different addresses do not share the cap (checked on the table, since a test has one address).
    #[tokio::test]
    async fn the_cap_is_per_address() {
        let (lim, _) = listener(64, 1, clocks(5_000, 5_000, 50_000)).await;
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        lim.table
            .lock()
            .unwrap()
            .entry(a)
            .or_default()
            .push(Arc::new(Slot {
                id: 1,
                last_active: AtomicU64::new(0),
                busy: AtomicBool::new(true),
                evicted: AtomicBool::new(false),
                waker: Mutex::new(None),
            }));
        assert!(!lim.admit(a), "a is at its cap and busy");
        assert!(lim.admit(b), "b has nothing open");
    }

    /// After a response, waiting for the next request runs on the short keep-alive clock, not the
    /// request budget.
    #[tokio::test]
    async fn a_keep_alive_connection_is_closed_on_the_idle_clock() {
        let (mut lim, addr) = listener(8, 8, clocks(3_000, 200, 30_000)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let (mut io, _) = lim.accept().await;
        c.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 8];
        assert_eq!(io.read(&mut b).await.unwrap(), 4);
        io.write_all(b"pong").await.unwrap();
        let started = std::time::Instant::now();
        let err = io.read(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_millis(1_500),
            "{:?}",
            started.elapsed()
        );
    }

    /// R3 of the 0.1.12 review: a client that never reads stalls the server's writes, and the clock
    /// used to be looked at only while reading.
    #[tokio::test]
    async fn a_client_that_does_not_read_is_closed_within_the_budget() {
        let (mut lim, addr) = listener(8, 8, clocks(400, 400, 60_000)).await;
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.set_recv_buffer_size(4096).unwrap();
        let _c = sock.connect(addr).await.unwrap();
        let (mut io, _) = lim.accept().await;
        let chunk = vec![b'x'; 64 * 1024];
        let started = std::time::Instant::now();
        let err = loop {
            match tokio::time::timeout(Duration::from_secs(5), io.write_all(&chunk)).await {
                Ok(Ok(())) => continue,
                Ok(Err(e)) => break e,
                Err(_) => panic!("a write stalled past 5 s without the budget closing it"),
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    /// However busy, a connection ends at its lifetime.
    #[tokio::test]
    async fn an_always_busy_connection_still_ends_at_its_lifetime() {
        let (mut lim, addr) = listener(8, 8, clocks(400, 400, 1_000)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let (mut io, _) = lim.accept().await;
        let started = std::time::Instant::now();
        let mut b = [0u8; 8];
        let err = loop {
            if c.write_all(b"ping").await.is_err() {
                break None;
            }
            match io.read(&mut b).await {
                Ok(_) => {}
                Err(e) => break Some(e),
            }
            if let Err(e) = io.write_all(b"pong").await {
                break Some(e);
            }
            let _ = c.read(&mut b).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(started.elapsed() < Duration::from_secs(3), "never closed");
        };
        assert_eq!(err.unwrap().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(900));
    }
}
