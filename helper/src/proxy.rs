//! Click-approved, connection-scoped forwarding. No credentials or bodies persist.
//! Destinations are fixed here; clients cannot supply URLs or arbitrary headers.
use crate::{
    protocol::{self, Tokens},
    server::Event,
    vault::{self, Bundle},
};
use anyhow::{Context, Result, bail, ensure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::Read,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Sender, SyncSender},
    },
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket};

pub const REQUEST_LIMIT: usize = 1024 * 1024;
const RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
const RESOURCE: &str = "https://api.openai.com/v1";
const ISSUER: &str = "https://auth.openai.com";
const JWKS: &str = "https://auth.openai.com/.well-known/jwks.json";

pub struct Session {
    pub id: u64,
    pub origin: String,
    pub requests: AtomicU64,
    pub stopped: AtomicBool,
    pub limited: AtomicBool,
    socket: TcpStream,
}
impl Session {
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
pub struct Pending {
    pub session: Arc<Session>,
    pub answer: Sender<bool>,
}
struct Lifetime(Arc<Session>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[derive(Default)]
struct Rate(VecDeque<Instant>);
impl Rate {
    fn take(&mut self, now: Instant, limit: usize) -> bool {
        while self
            .0
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            self.0.pop_front();
        }
        let allowed = self.0.len() < limit;
        if !allowed {
            self.0.pop_front();
        }
        self.0.push_back(now);
        allowed
    }
}
#[derive(Default)]
struct KeyCache {
    keys: Option<(Instant, JwkSet)>,
    attempted: Option<Instant>,
}
impl KeyCache {
    fn get(&mut self, now: Instant, fetch: impl FnOnce() -> Result<JwkSet>) -> Result<&JwkSet> {
        if self
            .keys
            .as_ref()
            .is_none_or(|(at, _)| now.duration_since(*at) >= Duration::from_secs(86400))
        {
            ensure!(
                self.attempted
                    .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(60)),
                "Signing keys unavailable; retry later"
            );
            self.attempted = Some(now);
            self.keys = Some((now, fetch()?));
        }
        Ok(&self.keys.as_ref().unwrap().1)
    }
}
static KEYS: OnceLock<Mutex<KeyCache>> = OnceLock::new();
fn fetch_keys() -> Result<JwkSet> {
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(JWKS)
        .send()?
        .error_for_status()?;
    let mut bytes = Vec::new();
    response.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 256 * 1024, "Signing key response too large");
    Ok(serde_json::from_slice(&bytes)?)
}
#[derive(Deserialize)]
struct Claims {
    sub: String,
    client_id: String,
    scope: String,
    iat: u64,
}
fn verify(
    token: &str,
    client_id: &str,
    subject: &str,
    keys: &JwkSet,
    allow_expired: bool,
) -> Result<()> {
    let header = decode_header(token)?;
    ensure!(
        header.alg == Algorithm::RS256,
        "Unexpected signing algorithm"
    );
    let key = keys
        .find(header.kid.as_deref().context("Missing signing key ID")?)
        .context("Unknown signing key; cached keys refresh after 24 hours")?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[RESOURCE]);
    validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp", "nbf"]);
    validation.validate_nbf = true;
    validation.validate_exp = !allow_expired;
    validation.leeway = 5;
    let claims = decode::<Claims>(token, &DecodingKey::from_jwk(key)?, &validation)?.claims;
    ensure!(
        !claims.sub.is_empty()
            && claims.sub == subject
            && claims.client_id == client_id
            && claims.iat <= protocol::now() + 5,
        "Invalid token claims"
    );
    let scopes: Vec<_> = claims.scope.split_whitespace().collect();
    ensure!(
        ["resource.invoke", "chatgpt.tokens.use.direct"]
            .iter()
            .all(|s| scopes.contains(s)),
        "Missing inference permission"
    );
    Ok(())
}
fn authorize(tokens: &Tokens, allow_expired: bool) -> Result<()> {
    let token = &tokens.access_token;
    authorize_with(token, &tokens.client_id, &tokens.subject, allow_expired)
}
fn authorize_with(token: &str, client_id: &str, subject: &str, allow_expired: bool) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() < 32000,
        "Invalid access token"
    );
    let header = decode_header(token).map_err(|_| anyhow::anyhow!("Invalid access token"))?;
    ensure!(
        header.alg == Algorithm::RS256 && header.kid.is_some(),
        "Invalid access token header"
    );
    let mut cache = KEYS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("Signing key cache unavailable"))?;
    let keys = cache
        .get(Instant::now(), fetch_keys)
        .map_err(|_| anyhow::anyhow!("Signing keys unavailable; retry later"))?;
    verify(token, client_id, subject, keys, allow_expired).map_err(|_| {
        anyhow::anyhow!("Access token rejected: signature, claims or permission invalid")
    })
}

#[derive(Deserialize)]
#[serde(tag = "endpoint", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Models {
        credentials: Bundle,
    },
    Responses {
        credentials: Bundle,
        body: serde_json::Value,
    },
    Refresh {
        credentials: Bundle,
    },
    Revoke {
        credentials: Bundle,
    },
}
impl Request {
    fn bundle(&self) -> &Bundle {
        match self {
            Self::Models { credentials }
            | Self::Responses { credentials, .. }
            | Self::Refresh { credentials }
            | Self::Revoke { credentials } => credentials,
        }
    }
    fn validate(&self) -> Result<()> {
        if let Self::Responses { body, .. } = self {
            ensure!(
                body.is_object() && body["store"] == false && body["stream"] == true,
                "Inference requires store=false and stream=true"
            );
        }
        Ok(())
    }
    fn upstream(
        &self,
        tokens: &Tokens,
        client: &reqwest::Client,
    ) -> Result<reqwest::RequestBuilder> {
        Ok(match self {
            Self::Models { .. } => client
                .get(format!("{RESOURCE}/models"))
                .bearer_auth(&tokens.access_token),
            Self::Responses { body, .. } => client
                .post(format!("{RESOURCE}/responses"))
                .bearer_auth(&tokens.access_token)
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(body)?),
            Self::Refresh { .. } => client
                .post(format!("{ISSUER}/api/accounts/oauth/token"))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", tokens.client_id.as_str()),
                    ("refresh_token", tokens.refresh_token.as_str()),
                    ("resource", RESOURCE),
                ]),
            Self::Revoke { .. } => client
                .post(format!("{ISSUER}/api/accounts/oauth/revoke"))
                .form(&[
                    ("token", tokens.refresh_token.as_str()),
                    ("client_id", tokens.client_id.as_str()),
                    ("token_type_hint", "refresh_token"),
                ]),
        })
    }
}
fn refreshed(mut tokens: Tokens, value: serde_json::Value) -> Result<Tokens> {
    let scope: Vec<_> = value["scope"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    ensure!(
        scope.len() == protocol::SCOPES.len() && protocol::SCOPES.iter().all(|s| scope.contains(s)),
        "Unexpected refresh permissions"
    );
    ensure!(
        value["token_type"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("bearer")),
        "Invalid refreshed token type"
    );
    let access = value["access_token"]
        .as_str()
        .context("Missing refreshed access token")?;
    let refresh = value["refresh_token"]
        .as_str()
        .context("Missing replacement refresh token")?;
    ensure!(
        !access.is_empty() && access.len() < 32000 && !refresh.is_empty() && refresh.len() < 32000,
        "Invalid refreshed credentials"
    );
    let lifetime = value["expires_in"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= 86400)
        .context("Invalid refreshed expiry")?;
    authorize_with(access, &tokens.client_id, &tokens.subject, false)?;
    tokens.access_token = access.into();
    tokens.refresh_token = refresh.into();
    tokens.expires_at = protocol::now() + lifetime;
    Ok(tokens)
}

fn control(socket: &mut WebSocket<TcpStream>, value: serde_json::Value) -> Result<()> {
    socket.send(Message::Text(value.to_string().into()))?;
    Ok(())
}
// Only the session thread touches the WebSocket. Request workers send through a
// bounded channel, so a slow client cannot accumulate unbounded response buffers.
struct Reply {
    id: u32,
    message: Message,
    done: bool,
}
#[derive(Clone)]
struct Output {
    id: u32,
    sender: SyncSender<Reply>,
    cancelled: Arc<AtomicBool>,
    session: Arc<Session>,
    stop: Arc<AtomicBool>,
}
impl Output {
    fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::SeqCst)
                && !self.session.stopped.load(Ordering::SeqCst)
                && !self.stop.load(Ordering::SeqCst),
            "Request cancelled"
        );
        Ok(())
    }
    async fn send(&self, message: Message) -> Result<()> {
        let mut reply = Reply {
            id: self.id,
            message,
            done: false,
        };
        loop {
            self.check()?;
            match self.sender.try_send(reply) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(value)) => reply = value,
                Err(mpsc::TrySendError::Disconnected(_)) => bail!("Session closed"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn control(&self, mut value: serde_json::Value) -> Result<()> {
        value["id"] = self.id.into();
        self.send(Message::Text(value.to_string().into())).await
    }
    async fn chunk(&self, bytes: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&self.id.to_be_bytes());
        frame.extend_from_slice(bytes);
        self.send(Message::Binary(frame.into())).await
    }
    // Terminal replies must still reach the coordinator after per-request cancel.
    fn finish(&self, result: Result<serde_json::Value>) {
        let mut value = result.unwrap_or_else(
            |error| serde_json::json!({"type":"error", "message":error.to_string()}),
        );
        value["id"] = self.id.into();
        let mut reply = Reply {
            id: self.id,
            message: Message::Text(value.to_string().into()),
            done: true,
        };
        while !self.session.stopped.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst) {
            match self.sender.try_send(reply) {
                Ok(()) | Err(mpsc::TrySendError::Disconnected(_)) => return,
                Err(mpsc::TrySendError::Full(value)) => reply = value,
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
async fn cancellable<T>(
    future: impl Future<Output = reqwest::Result<T>>,
    output: &Output,
) -> Result<T> {
    let mut future = Box::pin(future);
    loop {
        output.check()?;
        match tokio::time::timeout(Duration::from_millis(50), &mut future).await {
            Ok(result) => {
                return result
                    .map_err(|_| anyhow::anyhow!("OpenAI request interrupted or timed out"));
            }
            Err(_) => continue,
        }
    }
}
async fn forward(
    request: &Request,
    tokens: &Tokens,
    output: &Output,
) -> Result<Option<serde_json::Value>> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = cancellable(request.upstream(tokens, &client)?.send(), output).await?;
    if matches!(request, Request::Refresh { .. } | Request::Revoke { .. }) {
        ensure!(
            response.status().is_success(),
            "OpenAI credential operation failed (HTTP {})",
            response.status().as_u16()
        );
        if matches!(request, Request::Revoke { .. }) {
            return Ok(None);
        }
        let mut body = Vec::new();
        while let Some(bytes) = cancellable(response.chunk(), output).await? {
            ensure!(
                body.len() + bytes.len() <= 128 * 1024,
                "Refresh response too large"
            );
            body.extend_from_slice(&bytes);
        }
        return Ok(Some(
            serde_json::from_slice(&body)
                .map_err(|_| anyhow::anyhow!("Invalid refresh response"))?,
        ));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    output.control(serde_json::json!({"type":"headers", "status":response.status().as_u16(), "content_type":content_type})).await?;
    let mut total = 0;
    while let Some(bytes) = cancellable(response.chunk(), output).await? {
        output.check()?;
        total += bytes.len();
        ensure!(total <= RESPONSE_LIMIT, "Response exceeds 8 MiB limit");
        for chunk in bytes.chunks(32 * 1024) {
            output.chunk(chunk).await?;
        }
    }
    Ok(None)
}

fn execute(raw: serde_json::Value, output: &Output) -> Result<serde_json::Value> {
    output.check()?;
    let request: Request = serde_json::from_value(raw)
        .map_err(|_| anyhow::anyhow!("Unsupported endpoint or malformed request"))?;
    request.validate()?;
    let key = vault::installation()?;
    let tokens = key
        .open(request.bundle(), &output.session.origin)
        .map_err(|_| {
            anyhow::anyhow!("Credential bundle rejected: wrong helper, origin or damaged data")
        })?;
    authorize(
        &tokens,
        matches!(request, Request::Refresh { .. } | Request::Revoke { .. }),
    )?;
    output.check()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let value = runtime.block_on(forward(&request, &tokens, output))?;
    output.check()?;
    if let Some(value) = value {
        let credentials = key.seal(&output.session.origin, refreshed(tokens, value)?)?;
        Ok(serde_json::json!({"type":"credentials", "credentials":credentials}))
    } else if matches!(request, Request::Revoke { .. }) {
        Ok(serde_json::json!({"type":"revoked"}))
    } else {
        Ok(serde_json::json!({"type":"end"}))
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Request { id: u32, request: serde_json::Value },
    Cancel { id: u32 },
}
fn read(socket: &mut WebSocket<TcpStream>) -> Result<Option<Message>> {
    match socket.read() {
        Err(tungstenite::Error::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
            socket.flush()?;
            Ok(None)
        }
        Ok(Message::Close(_)) => bail!("Session closed"),
        other => Ok(Some(other?)),
    }
}
fn request_error(socket: &mut WebSocket<TcpStream>, id: u32, message: &str) -> Result<()> {
    control(
        socket,
        serde_json::json!({"id":id,"type":"error","message":message}),
    )
}

pub(crate) fn serve(
    socket: WebSocket<TcpStream>,
    id: u64,
    origin: String,
    events: &Sender<Event>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    serve_with(socket, id, origin, events, stop, execute)
}
// The injectable worker is private and only used by synthetic transport tests.
fn serve_with(
    mut socket: WebSocket<TcpStream>,
    id: u64,
    origin: String,
    events: &Sender<Event>,
    stop: Arc<AtomicBool>,
    execute: fn(serde_json::Value, &Output) -> Result<serde_json::Value>,
) -> Result<()> {
    socket
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(10)))?;
    socket
        .get_mut()
        .set_write_timeout(Some(Duration::from_secs(5)))?;
    let session = Arc::new(Session {
        id,
        origin,
        requests: AtomicU64::new(0),
        stopped: AtomicBool::new(false),
        limited: AtomicBool::new(true),
        socket: socket.get_ref().try_clone()?,
    });
    let _lifetime = Lifetime(session.clone());
    let (answer, reply) = mpsc::channel();
    events.send(Event::Proxy(Pending {
        session: session.clone(),
        answer,
    }))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        ensure!(
            !session.stopped.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst),
            "Session stopped"
        );
        ensure!(
            read(&mut socket)?.is_none(),
            "Request received before approval"
        );
        ensure!(Instant::now() < deadline, "Approval timed out");
        match reply.try_recv() {
            Ok(true) => break,
            Ok(false) | Err(mpsc::TryRecvError::Disconnected) => bail!("Proxy rejected"),
            Err(mpsc::TryRecvError::Empty) => (),
        }
    }
    control(
        &mut socket,
        serde_json::json!({"type":"ready", "protocol":1}),
    )?;
    let (sender, replies) = mpsc::sync_channel::<Reply>(8);
    let mut active: HashMap<u32, Arc<AtomicBool>> = HashMap::new();
    let mut last_id = 0;
    let mut rate = Rate::default();
    loop {
        ensure!(
            !session.stopped.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst),
            "Session stopped"
        );
        // Bound each drain so streaming output cannot starve incoming cancellation.
        for reply in replies.try_iter().take(8) {
            let Some(cancelled) = active.get(&reply.id) else {
                continue;
            };
            if cancelled.load(Ordering::SeqCst) {
                if reply.done {
                    request_error(&mut socket, reply.id, "Request cancelled")?;
                }
            } else {
                socket.send(reply.message)?;
            }
            if reply.done {
                active.remove(&reply.id);
            }
        }
        let Some(message) = read(&mut socket)? else {
            continue;
        };
        let Message::Text(raw) = message else {
            bail!("Expected a request or cancel message")
        };
        ensure!(raw.len() <= REQUEST_LIMIT, "Request exceeds 1 MiB limit");
        match serde_json::from_str::<Command>(&raw).context("Invalid proxy command")? {
            Command::Cancel { id } => {
                if let Some(cancelled) = active.get(&id) {
                    cancelled.store(true, Ordering::SeqCst);
                }
            }
            Command::Request { id, request } => {
                // Never reuse an ID, including after cancellation or rejection. This
                // also prevents delayed frames from being mistaken for a new request.
                ensure!(id > last_id, "Request IDs must increase from 1");
                last_id = id;
                session.requests.fetch_add(1, Ordering::SeqCst);
                let within_rate = rate.take(Instant::now(), 30);
                if session.limited.load(Ordering::SeqCst) {
                    if !within_rate {
                        request_error(
                            &mut socket,
                            id,
                            "Session limit reached (30 requests/minute)",
                        )?;
                        continue;
                    }
                    if active.len() >= 2 {
                        request_error(&mut socket, id, "Session already has two active requests")?;
                        continue;
                    }
                }
                let cancelled = Arc::new(AtomicBool::new(false));
                active.insert(id, cancelled.clone());
                let output = Output {
                    id,
                    sender: sender.clone(),
                    cancelled,
                    session: session.clone(),
                    stop: stop.clone(),
                };
                if std::thread::Builder::new()
                    .name("proxy-request".into())
                    .spawn(move || {
                        let result = execute(request, &output);
                        output.finish(result);
                    })
                    .is_err()
                {
                    active.remove(&id);
                    request_error(&mut socket, id, "Cannot start request worker")?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        rsa::KeySize,
        signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    #[test]
    fn access_tokens_need_signature_audience_client_subject_times_and_scopes() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public = RsaPublicKeyComponents::<Vec<u8>>::from(key.public_key());
        let keys: JwkSet = serde_json::from_value(serde_json::json!({"keys":[{"kty":"RSA","kid":"test","alg":"RS256","n":B64.encode(public.n),"e":B64.encode(public.e)}]})).unwrap();
        let sign = |claims: &serde_json::Value| {
            let message = format!(
                "{}.{}",
                B64.encode(br#"{"alg":"RS256","kid":"test"}"#),
                B64.encode(serde_json::to_vec(claims).unwrap())
            );
            let mut signature = vec![0; key.public_modulus_len()];
            key.sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .unwrap();
            format!("{message}.{}", B64.encode(signature))
        };
        let now = protocol::now();
        let claims = serde_json::json!({"iss":ISSUER,"aud":RESOURCE,"sub":"subject","client_id":"client","scope":"resource.invoke chatgpt.tokens.use.direct","iat":now,"nbf":now,"exp":now+60});
        assert!(verify(&sign(&claims), "client", "subject", &keys, false).is_ok());
        for (field, value) in [
            ("iss", serde_json::json!("https://evil.example")),
            ("aud", serde_json::json!("elsewhere")),
            ("sub", serde_json::json!("other")),
            ("client_id", serde_json::json!("other")),
            ("scope", serde_json::json!("openid")),
            ("iat", serde_json::json!(now + 60)),
            ("nbf", serde_json::json!(now + 60)),
            ("exp", serde_json::json!(now - 60)),
        ] {
            let mut bad = claims.clone();
            bad[field] = value;
            assert!(
                verify(&sign(&bad), "client", "subject", &keys, false).is_err(),
                "{field}"
            );
        }
        let mut expired = claims.clone();
        expired["exp"] = (now - 60).into();
        assert!(
            verify(&sign(&expired), "client", "subject", &keys, true).is_ok(),
            "refresh may use expired access token"
        );
        expired.as_object_mut().unwrap().remove("exp");
        assert!(verify(&sign(&expired), "client", "subject", &keys, true).is_err());
        let token = sign(&claims);
        let mut bytes = token.into_bytes();
        let at = bytes.len() - 10;
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        assert!(
            verify(
                std::str::from_utf8(&bytes).unwrap(),
                "client",
                "subject",
                &keys,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn keys_are_cached_24_hours_and_fetch_failures_are_throttled() {
        let mut cache = KeyCache::default();
        let now = Instant::now();
        let fetch = || Ok(JwkSet { keys: vec![] });
        cache.get(now, fetch).unwrap();
        cache
            .get(now + Duration::from_secs(86399), || {
                panic!("must use cached keys")
            })
            .unwrap();
        assert!(
            cache
                .get(now + Duration::from_secs(86400), || bail!(
                    "network failure"
                ))
                .is_err()
        );
        assert!(
            cache
                .get(now + Duration::from_secs(86401), || panic!(
                    "must not retry yet"
                ))
                .is_err()
        );
        cache.get(now + Duration::from_secs(86460), fetch).unwrap();
    }
    #[test]
    fn rate_window_is_bounded() {
        let mut rate = Rate::default();
        let now = Instant::now();
        for _ in 0..30 {
            assert!(rate.take(now, 30));
        }
        assert!(!rate.take(now + Duration::from_secs(59), 30));
        assert!(rate.take(now + Duration::from_secs(60), 30));
    }
    #[test]
    fn arbitrary_destinations_and_credential_fields_are_rejected() {
        for raw in [
            r#"{"endpoint":"https://evil.example"}"#,
            r#"{"endpoint":"models","token":"plaintext"}"#,
            r#"{"endpoint":"responses","url":"https://evil.example"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(raw).is_err());
        }
    }
    #[test]
    fn approval_is_required_and_invalid_requests_are_counted_without_forwarding() {
        use std::{net::TcpListener, thread};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (events, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let socket = tungstenite::accept(stream).unwrap();
            serve(
                socket,
                1,
                "https://example.org".into(),
                &events,
                Arc::new(AtomicBool::new(false)),
            )
        });
        let (mut client, _) = tungstenite::connect(format!("ws://{address}")).unwrap();
        let Event::Proxy(pending) = received.recv_timeout(Duration::from_secs(2)).unwrap() else {
            panic!("expected approval request")
        };
        assert_eq!(pending.session.requests.load(Ordering::SeqCst), 0);
        if let tungstenite::stream::MaybeTlsStream::Plain(stream) = client.get_mut() {
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
        }
        assert!(client.read().is_err(), "must not be ready without a click");
        pending.answer.send(true).unwrap();
        if let tungstenite::stream::MaybeTlsStream::Plain(stream) = client.get_mut() {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        assert!(client.read().unwrap().to_text().unwrap().contains("ready"));
        client
            .send(Message::Text(
                r#"{"type":"request","id":1,"request":{"endpoint":"unknown"}}"#.into(),
            ))
            .unwrap();
        assert!(
            client
                .read()
                .unwrap()
                .to_text()
                .unwrap()
                .contains("Unsupported endpoint")
        );
        pending.session.stop();
        let _ = worker.join().unwrap();
        assert_eq!(pending.session.requests.load(Ordering::SeqCst), 1);
        assert!(pending.session.stopped.load(Ordering::SeqCst));
    }
    // A synthetic worker exercises the real coordinator and wire framing without
    // accepting fake credentials in production or making any network API calls.
    fn synthetic(raw: serde_json::Value, output: &Output) -> Result<serde_json::Value> {
        if raw["hold"] == true {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                output
                    .control(serde_json::json!({"type":"headers", "status":200}))
                    .await?;
                output.chunk(b"fixture").await?;
                cancellable(std::future::pending::<reqwest::Result<()>>(), output).await
            })?;
        }
        Ok(serde_json::json!({"type":"revoked"}))
    }
    struct Connection {
        client: WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
        session: Arc<Session>,
        worker: Option<std::thread::JoinHandle<Result<()>>>,
    }
    impl Connection {
        fn new() -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (events, received) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                serve_with(
                    tungstenite::accept(stream).unwrap(),
                    1,
                    "https://example.org".into(),
                    &events,
                    Arc::new(AtomicBool::new(false)),
                    synthetic,
                )
            });
            let (mut client, _) = tungstenite::connect(format!("ws://{address}")).unwrap();
            if let tungstenite::stream::MaybeTlsStream::Plain(stream) = client.get_mut() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
            }
            let Event::Proxy(pending) = received.recv_timeout(Duration::from_secs(2)).unwrap()
            else {
                panic!("approval")
            };
            assert!(pending.session.limited.load(Ordering::SeqCst));
            pending.answer.send(true).unwrap();
            let ready: serde_json::Value =
                serde_json::from_str(client.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(ready["protocol"], 1);
            Self {
                client,
                session: pending.session,
                worker: Some(worker),
            }
        }
        fn send(&mut self, value: serde_json::Value) {
            self.client
                .send(Message::Text(value.to_string().into()))
                .unwrap();
        }
        fn request(&mut self, id: u32, hold: bool) {
            self.send(serde_json::json!({"type":"request","id":id,"request":{"hold":hold}}));
        }
        fn reply(&mut self) -> serde_json::Value {
            serde_json::from_str(self.client.read().unwrap().to_text().unwrap()).unwrap()
        }
        fn starts(&mut self, ids: &[u32]) {
            let mut headers = Vec::new();
            let mut chunks = Vec::new();
            for _ in 0..ids.len() * 2 {
                match self.client.read().unwrap() {
                    Message::Text(raw) => {
                        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
                        assert_eq!(value["type"], "headers");
                        headers.push(value["id"].as_u64().unwrap() as u32);
                    }
                    Message::Binary(bytes) => {
                        let id = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                        assert!(
                            headers.contains(&id),
                            "headers must precede data for each ID"
                        );
                        assert_eq!(&bytes[4..], b"fixture");
                        chunks.push(id);
                    }
                    _ => panic!("unexpected frame"),
                }
            }
            headers.sort();
            chunks.sort();
            assert_eq!(headers, ids);
            assert_eq!(chunks, ids);
        }
    }
    impl Drop for Connection {
        fn drop(&mut self) {
            self.session.stop();
            let _ = self.worker.take().unwrap().join().unwrap();
        }
    }
    #[test]
    fn multiplex_limits_toggle_cancellation_and_sessions_are_independent() {
        let mut first = Connection::new();
        let mut second = Connection::new();
        first.request(1, true);
        first.request(2, true);
        first.starts(&[1, 2]);
        second.request(1, true);
        second.request(2, true);
        second.starts(&[1, 2]);
        first.request(3, false);
        let error = first.reply();
        assert_eq!(error["id"], 3);
        assert!(error["message"].as_str().unwrap().contains("two active"));
        first.send(serde_json::json!({"type":"cancel","id":1}));
        let cancelled = first.reply();
        assert_eq!(cancelled["id"], 1);
        assert_eq!(cancelled["message"], "Request cancelled");
        first.request(4, false);
        assert_eq!(first.reply(), serde_json::json!({"id":4,"type":"revoked"}));

        first.session.limited.store(false, Ordering::SeqCst);
        for id in 5..=7 {
            first.request(id, true);
        }
        first.starts(&[5, 6, 7]); // Four active requests in this session, six globally.
        first.session.limited.store(true, Ordering::SeqCst);
        first.request(8, false);
        assert!(
            first.reply()["message"]
                .as_str()
                .unwrap()
                .contains("two active")
        );
        // Re-enabling limits does not cancel work already running.
        for id in [2, 5, 6, 7] {
            first.send(serde_json::json!({"type":"cancel","id":id}));
        }
        let mut cancelled_ids = Vec::new();
        for _ in 0..4 {
            let cancelled = first.reply();
            assert_eq!(cancelled["message"], "Request cancelled");
            cancelled_ids.push(cancelled["id"].as_u64().unwrap());
        }
        cancelled_ids.sort();
        assert_eq!(cancelled_ids, [2, 5, 6, 7]);
        first.session.limited.store(false, Ordering::SeqCst);
        for id in 9..=140 {
            first.request(id, false);
            assert_eq!(first.reply(), serde_json::json!({"id":id,"type":"revoked"}));
        }
        first.session.limited.store(true, Ordering::SeqCst);
        first.request(141, false);
        assert!(
            first.reply()["message"]
                .as_str()
                .unwrap()
                .contains("30 requests")
        );
        assert_eq!(first.session.requests.load(Ordering::SeqCst), 141);
        // Another session has its own rate history despite >120 total attempts.
        second.send(serde_json::json!({"type":"cancel","id":1}));
        assert_eq!(second.reply()["message"], "Request cancelled");
        second.request(3, false);
        assert_eq!(second.reply(), serde_json::json!({"id":3,"type":"revoked"}));
    }
    #[test]
    fn checked_session_rejects_attempt_31_without_closing_connection() {
        let mut connection = Connection::new();
        for id in 1..=30 {
            connection.request(id, false);
            assert_eq!(connection.reply()["type"], "revoked");
        }
        connection.request(31, false);
        assert!(
            connection.reply()["message"]
                .as_str()
                .unwrap()
                .contains("30 requests")
        );
        connection.session.limited.store(false, Ordering::SeqCst);
        connection.request(32, false);
        assert_eq!(connection.reply()["type"], "revoked");
        // Reuse would make delayed replies ambiguous; close the session instead.
        connection.request(32, false);
        assert!(connection.client.read().is_err());
    }
    #[test]
    fn cancel_and_stop_drop_an_inflight_future() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for stop_session in [false, true] {
            let connection = Connection::new();
            let (sender, _receiver) = mpsc::sync_channel(1);
            let output = Output {
                id: 1,
                sender,
                cancelled: Arc::new(AtomicBool::new(false)),
                session: connection.session.clone(),
                stop: Arc::new(AtomicBool::new(false)),
            };
            let dropped = Arc::new(AtomicBool::new(false));
            let guard = Dropped(dropped.clone());
            let future = async move {
                let _guard = guard;
                std::future::pending::<reqwest::Result<()>>().await
            };
            let canceller = output.clone();
            let worker = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                if stop_session {
                    canceller.session.stop();
                } else {
                    canceller.cancelled.store(true, Ordering::SeqCst);
                }
            });
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let start = Instant::now();
            assert!(rt.block_on(cancellable(future, &output)).is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(dropped.load(Ordering::SeqCst));
            worker.join().unwrap();
        }
    }
}
