//! Limits on the TCP connections themselves, below HTTP.
//!
//! The request limiter only runs once a whole request has arrived, and `axum::serve` has no timeout
//! of its own, so a client that opens a connection and sends one header byte every few seconds held
//! a file descriptor for as long as it liked (measured: 2000 such connections, none closed in five
//! minutes, descriptors growing one for one). The 0.1.12 audit found it; the fix is two numbers.
//!
//! * `MCP_MAX_CONNECTIONS` (default 1024): connections held open at once. Past it, `accept` waits.
//! * `MCP_CONN_TIMEOUT_SECS` (default 120): a connection that has gone this long without finishing
//!   what it started is closed. Two clocks, one budget. An idle connection (nothing sent since it
//!   opened or since the last response) is closed after the budget; a connection that has started a
//!   request must get its first response byte out within the budget or it is closed.
//!
//! The second clock is deliberately "time to first response byte", not "time to finish the headers":
//! below HTTP there is no telling where the headers end, and the response is the one event that
//! proves the request was complete. Legitimate requests stay well inside it because
//! `statement_timeout` is 30s by default.

use axum::serve::Listener;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, Instant, Sleep};

pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 1024;
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 120;

pub(crate) fn max_connections() -> usize {
    std::env::var("MCP_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_CONNECTIONS)
}

pub(crate) fn timeout() -> Duration {
    Duration::from_secs(
        std::env::var("MCP_CONN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
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

pub(crate) struct Limited {
    inner: TcpListener,
    permits: Arc<Semaphore>,
    budget: Duration,
}

impl Limited {
    pub(crate) fn new(inner: TcpListener, max: usize, budget: Duration) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max)),
            budget,
        }
    }
}

impl Listener for Limited {
    type Io = Guarded;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // The permit is taken BEFORE accepting, so a full table leaves new connections in the
        // kernel's backlog instead of in our descriptor table.
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => return (Guarded::new(stream, permit, self.budget), addr),
                // EMFILE and friends: back off instead of spinning.
                Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A `TcpStream` with the two clocks described above, holding its slot until it is dropped.
pub(crate) struct Guarded {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    budget: Duration,
    timer: Pin<Box<Sleep>>,
    /// A request has started and no response byte has gone out yet.
    receiving: bool,
}

impl Guarded {
    fn new(inner: TcpStream, permit: OwnedSemaphorePermit, budget: Duration) -> Self {
        Self {
            inner,
            _permit: permit,
            budget,
            timer: Box::pin(sleep(budget)),
            receiving: false,
        }
    }

    fn timer_running_for_request(&self) -> bool {
        self.receiving
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.timer.as_mut().poll(cx).is_ready()
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "connection exceeded its time budget",
    )
}

impl AsyncRead for Guarded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    // Bytes arrived. If we were idle, the clock now runs against the first response
                    // byte; if a request was already in progress it keeps running from where it was,
                    // so dribbling one byte at a time buys nothing.
                    if !this.timer_running_for_request() {
                        this.timer.as_mut().reset(Instant::now() + this.budget);
                        this.receiving = true;
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.expired(cx) {
                    Poll::Ready(Err(timed_out()))
                } else {
                    Poll::Pending
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
        let r = Pin::new(&mut this.inner).poll_write(cx, data);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            // A response byte went out: the request was whole. Back to the idle clock.
            this.receiving = false;
            this.timer.as_mut().reset(Instant::now() + this.budget);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
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
        let lim = Limited::new(l, max, Duration::from_millis(budget_ms));
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
}
