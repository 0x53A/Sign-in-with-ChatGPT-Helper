//! Loopback transport. Workers queue requests; only the GUI approves them.
//! The GUI holds the busy flag through login and the result screen, not per socket.
use crate::{
    auth,
    protocol::{self, Envelope, LIMIT, Request},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Sender},
    },
    thread,
    time::{Duration, Instant},
};
use tungstenite::{
    Message, WebSocket,
    handshake::server::{Request as Handshake, Response},
    protocol::WebSocketConfig,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
pub struct Pending {
    pub id: u64,
    pub request: Request,
    pub pin: String,
    pub answer: Sender<bool>,
    pub cancelled: Arc<AtomicBool>,
}
pub enum Delivery {
    Online,
    Offline(Envelope),
}
pub enum Event {
    Pending(Pending),
    Status(u64, String, Option<String>),
    Finished(u64, Result<Delivery, String>),
}
pub struct Listener {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct Connection(Arc<AtomicUsize>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handshake_origin(req: &Handshake, port: u16) -> Result<String> {
    ensure!(
        req.uri().path() == "/pair" && req.uri().query().is_none(),
        "Invalid WebSocket path"
    );
    ensure!(
        req.headers().get_all("origin").iter().count() == 1
            && req.headers().get_all("host").iter().count() == 1,
        "Missing or duplicate origin/host"
    );
    ensure!(
        req.headers().get("host").and_then(|h| h.to_str().ok())
            == Some(format!("127.0.0.1:{port}").as_str()),
        "Invalid loopback host"
    );
    let origin = req
        .headers()
        .get("origin")
        .and_then(|h| h.to_str().ok())
        .context("Missing origin")?;
    ensure!(protocol::valid_origin(origin), "Untrusted origin scheme");
    Ok(origin.into())
}
pub fn start(port: u16, events: Sender<Event>, busy: Arc<AtomicBool>) -> Result<Listener> {
    ensure!(port != 0, "Choose a port from 1 to 65535");
    let listener = TcpListener::bind(("127.0.0.1", port))
        .context("Cannot bind port; choose another in helper and client")?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let connections = Arc::new(AtomicUsize::new(0));
    let thread = thread::spawn(move || {
        while !stopped.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if busy.load(Ordering::SeqCst) || connections.load(Ordering::SeqCst) >= 16 {
                        drop(stream);
                        continue;
                    }
                    connections.fetch_add(1, Ordering::SeqCst);
                    let guard = Connection(connections.clone());
                    let events = events.clone();
                    let stopped = stopped.clone();
                    let busy = busy.clone();
                    thread::spawn(move || {
                        let _guard = guard;
                        let _ = online(stream, port, &events, stopped, busy);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(_) => break,
            }
        }
    });
    Ok(Listener {
        stop,
        thread: Some(thread),
    })
}
fn disconnected(socket: &mut WebSocket<TcpStream>) -> bool {
    match socket.read() {
        Err(tungstenite::Error::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            false
        }
        Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => socket.flush().is_err(),
        _ => true,
    }
}
fn exchange(
    id: u64,
    raw: &str,
    pin: Option<String>,
    cancelled: Arc<AtomicBool>,
    events: &Sender<Event>,
    mut disconnected: impl FnMut() -> bool,
) -> Result<Envelope> {
    let request = Request::parse(raw)?;
    let outcome = (|| {
        if let Some(pin) = pin {
            let (tx, rx) = mpsc::channel();
            let deadline = Instant::now() + Duration::from_secs(120);
            events.send(Event::Pending(Pending {
                id,
                request: request.clone(),
                pin,
                answer: tx,
                cancelled: cancelled.clone(),
            }))?;
            loop {
                ensure!(
                    !cancelled.load(Ordering::SeqCst) && !disconnected(),
                    "Pairing connection closed or cancelled"
                );
                ensure!(
                    Instant::now() < deadline && protocol::now() < request.expires_at,
                    "Pairing request expired"
                );
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(true) => break,
                    Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        anyhow::bail!("Pairing rejected")
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                }
            }
        }
        let tokens = auth::authorize(
            &request,
            || cancelled.load(Ordering::SeqCst) || disconnected(),
            |message, url| {
                let _ = events.send(Event::Status(id, message, url));
            },
        )?;
        ensure!(
            !disconnected() && !cancelled.load(Ordering::SeqCst),
            "Connection closed before delivery"
        );
        protocol::encrypt(raw, &request, &tokens)
    })();
    cancelled.store(true, Ordering::SeqCst);
    outcome
}
#[allow(clippy::result_large_err)] // tungstenite requires its unboxed HTTP error response.
fn online(
    stream: TcpStream,
    port: u16,
    events: &Sender<Event>,
    stop: Arc<AtomicBool>,
    busy: Arc<AtomicBool>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut origin = String::new();
    let mut socket = tungstenite::accept_hdr_with_config(
        stream,
        |request: &Handshake, response: Response| match handshake_origin(request, port) {
            Ok(value) => {
                origin = value;
                Ok(response)
            }
            Err(_) => Err(tungstenite::http::Response::builder()
                .status(403)
                .body(Some("Origin or host rejected".into()))
                .unwrap()),
        },
        Some(
            WebSocketConfig::default()
                .max_message_size(Some(LIMIT))
                .max_frame_size(Some(LIMIT)),
        ),
    )
    .map_err(|_| anyhow::anyhow!("WebSocket handshake rejected or timed out"))?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pair {
        request: String,
        pin: String,
    }
    let message = socket.read().context("No pairing request received")?;
    ensure!(message.is_text(), "Expected a text pairing request");
    let pair: Pair = serde_json::from_str(message.to_text()?).context("Invalid pairing message")?;
    ensure!(
        pair.pin.len() == 4 && pair.pin.bytes().all(|b| b.is_ascii_digit()),
        "PIN must contain four digits"
    );
    ensure!(
        Request::parse(&pair.request)?.origin == origin,
        "Request origin does not match browser handshake"
    );
    socket
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(100)))?;
    ensure!(!busy.load(Ordering::SeqCst), "Login is busy");
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let result = exchange(
        id,
        &pair.request,
        Some(pair.pin),
        Arc::new(AtomicBool::new(false)),
        events,
        || stop.load(Ordering::SeqCst) || disconnected(&mut socket),
    );
    let delivered = match result {
        Ok(envelope) => {
            let sent = socket.send(Message::Text(serde_json::to_string(&envelope)?.into()));
            let _ = socket.close(None);
            sent.map_err(anyhow::Error::from)
        }
        Err(e) => {
            let _ = socket.send(Message::Text(
                serde_json::json!({"error":"Login did not complete. See the helper."})
                    .to_string()
                    .into(),
            ));
            let _ = socket.close(None);
            Err(e)
        }
    };
    let _ = events.send(Event::Finished(
        id,
        delivered
            .map(|_| Delivery::Online)
            .map_err(|e| e.to_string()),
    ));
    Ok(())
}
pub fn offline(raw: String, events: Sender<Event>, cancelled: Arc<AtomicBool>) -> Result<u64> {
    Request::parse(&raw)?;
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    thread::spawn(move || {
        let result = exchange(id, &raw, None, cancelled, &events, || false);
        let _ = events.send(Event::Finished(
            id,
            result.map(Delivery::Offline).map_err(|e| e.to_string()),
        ));
    });
    Ok(id)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn websocket_origin_and_host_are_bound() {
        let make = |host: &str, origin: &str, path: &str| {
            Handshake::builder()
                .uri(path)
                .header("Host", host)
                .header("Origin", origin)
                .body(())
                .unwrap()
        };
        assert_eq!(
            handshake_origin(
                &make("127.0.0.1:17653", "https://example.org", "/pair"),
                17653
            )
            .unwrap(),
            "https://example.org"
        );
        for req in [
            make("evil.test:17653", "https://example.org", "/pair"),
            make("127.0.0.1:17653", "null", "/pair"),
            make("127.0.0.1:17653", "https://example.org", "/pair?x"),
        ] {
            assert!(handshake_origin(&req, 17653).is_err());
        }
    }
}
