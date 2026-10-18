//! OpenAI OAuth only: fixed endpoints, PKCE/state, verified identity and exact grants.
//! Disk storage contains registration metadata, never bearer tokens.
use crate::protocol::{Request, SCOPES, Tokens, hash, now, random};
use anyhow::{Context, Result, bail, ensure};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

const ISSUER: &str = "https://auth.openai.com";
const RESOURCE: &str = "https://api.openai.com/v1";

#[derive(Clone, Serialize, Deserialize)]
struct Registration {
    client_id: String,
    subject: Option<String>,
}

fn path() -> Result<PathBuf> {
    Ok(crate::vault::directory(false)?.join("registrations.json"))
}
fn registrations() -> Result<BTreeMap<String, Registration>> {
    match fs::read(path()?) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).context("Invalid registration file")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}
fn save(key: &str, registration: &Registration) -> Result<()> {
    let path = path()?;
    fs::create_dir_all(path.parent().unwrap())?;
    let mut all = registrations()?;
    all.insert(key.into(), registration.clone());
    let temp = path.with_extension(format!("{}.tmp", random()?));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(&serde_json::to_vec(&all)?)?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    Ok(())
}

fn json(response: reqwest::blocking::Response, stage: &str) -> Result<serde_json::Value> {
    ensure!(
        response.status().is_success(),
        "{stage}: HTTP {}",
        response.status().as_u16()
    );
    let mut bytes = Vec::new();
    response.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "{stage}: response too large");
    serde_json::from_slice(&bytes).with_context(|| format!("{stage}: invalid response"))
}

#[derive(Deserialize, Clone)]
struct Identity {
    sub: String,
    nonce: String,
    iat: u64,
}

fn verify(token: &str, client: &str, nonce: &str, keys: &JwkSet) -> Result<Identity> {
    let header = decode_header(token).context("Invalid identity token")?;
    ensure!(
        header.alg == Algorithm::RS256,
        "Unexpected identity signing algorithm"
    );
    let jwk = keys
        .find(
            header
                .kid
                .as_deref()
                .context("Missing identity signing key ID")?,
        )
        .context("Unknown identity signing key")?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[client]);
    validation.set_required_spec_claims(&["sub", "iat", "exp", "iss", "aud"]);
    validation.leeway = 5;
    let identity = decode::<Identity>(token, &DecodingKey::from_jwk(jwk)?, &validation)
        .context("Identity verification failed")?
        .claims;
    ensure!(
        !identity.sub.is_empty() && identity.nonce == nonce && identity.iat <= now() + 5,
        "Identity subject, nonce or issued-at time is invalid"
    );
    Ok(identity)
}

fn check_callback(query: &str, state: &str, existing: Option<&str>) -> Result<(String, String)> {
    let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    let get = |name: &str| -> Result<Option<String>> {
        let values: Vec<_> = pairs.iter().filter(|(k, _)| k == name).collect();
        ensure!(values.len() <= 1, "Duplicate OAuth parameter");
        Ok(values.first().map(|(_, v)| v.to_string()))
    };
    ensure!(
        get("state")?.as_deref() == Some(state),
        "Invalid OAuth state"
    );
    ensure!(get("error")?.is_none(), "OpenAI sign-in declined or failed");
    let client = get("client_id")?
        .or_else(|| existing.map(str::to_string))
        .context("Missing issued client ID")?;
    ensure!(
        client != "dynamic_agent_client"
            && !client.is_empty()
            && client.len() <= 200
            && client
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c)),
        "Invalid issued client ID"
    );
    ensure!(
        existing.is_none_or(|old| old == client),
        "OAuth client ID changed"
    );
    let code = get("code")?
        .filter(|v| !v.is_empty())
        .context("Missing authorization code")?;
    Ok((client, code))
}

fn validate_grant(value: &serde_json::Value) -> Result<()> {
    let scope: Vec<_> = value["scope"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    ensure!(
        scope.len() == SCOPES.len()
            && SCOPES
                .iter()
                .all(|s| scope.iter().filter(|x| *x == s).count() == 1),
        "OpenAI granted missing or unexpected permissions"
    );
    ensure!(
        value["token_type"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("bearer")),
        "Invalid token type"
    );
    for field in ["access_token", "refresh_token", "id_token"] {
        ensure!(
            value[field]
                .as_str()
                .is_some_and(|v| !v.is_empty() && v.len() < 32000),
            "Missing or invalid {field}"
        );
    }
    ensure!(
        value["expires_in"]
            .as_u64()
            .is_some_and(|v| v > 0 && v <= 86400),
        "Invalid access-token expiry"
    );
    Ok(())
}

pub(crate) fn authorize(
    request: &Request,
    mut cancelled: impl FnMut() -> bool,
    mut status: impl FnMut(String, Option<String>),
) -> Result<Tokens> {
    ensure!(!cancelled(), "Sign-in cancelled");
    let client = Client::builder()
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let registration_key = hash(
        format!(
            "{}\n{}\n{}",
            request.origin, request.app_name, request.host_id
        )
        .as_bytes(),
    );
    let old = registrations()?.get(&registration_key).cloned();
    if let (Some(stored), Some(supplied)) = (&old, &request.client_id) {
        ensure!(
            stored.client_id == *supplied,
            "Client registration mismatch"
        );
    }
    let existing = old
        .as_ref()
        .map(|v| v.client_id.as_str())
        .or(request.client_id.as_deref());
    let server = tiny_http::Server::http("127.0.0.1:0")
        .map_err(|e| anyhow::anyhow!("Cannot start OAuth callback: {e}"))?;
    let address = server
        .server_addr()
        .to_ip()
        .context("Missing callback listener")?;
    let redirect = format!("http://{address}/auth/callback");
    let state = random()?;
    let nonce = random()?;
    let verifier = random()?;
    let mut url = url::Url::parse(&format!("{ISSUER}/api/accounts/authorize"))?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", existing.unwrap_or("dynamic_agent_client")),
        ("ext_agent_host_id", &request.host_id),
        ("response_type", "code"),
        ("redirect_uri", &redirect),
        ("scope", &SCOPES.join(" ")),
        ("resource", RESOURCE),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge_method", "S256"),
        ("code_challenge", &hash(verifier.as_bytes())),
    ]);
    if existing.is_none() {
        url.query_pairs_mut()
            .append_pair("agent_name_hint", &request.app_name);
    }
    status(String::new(), Some(url.to_string()));
    ensure!(!cancelled(), "Sign-in cancelled");
    let deadline = Instant::now() + Duration::from_secs(600);
    let (issued, code) = loop {
        ensure!(!cancelled(), "Sign-in cancelled");
        ensure!(
            Instant::now() < deadline && now() < request.expires_at,
            "Sign-in timed out"
        );
        let Some(incoming) = server.recv_timeout(Duration::from_millis(200))? else {
            continue;
        };
        let parsed = url::Url::parse(&format!("http://{address}{}", incoming.url()));
        let hosts: Vec<_> = incoming
            .headers()
            .iter()
            .filter(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str())
            .collect();
        let accepted = parsed.as_ref().is_ok_and(|u| {
            u.path() == "/auth/callback" && u.query_pairs().any(|(k, v)| k == "state" && v == state)
        }) && incoming.method() == &tiny_http::Method::Get
            && hosts == [address.to_string().as_str()];
        let reply = |text, code| {
            tiny_http::Response::from_string(text)
                .with_status_code(code)
                .with_header(tiny_http::Header::from_bytes("Cache-Control", "no-store").unwrap())
                .with_header(
                    tiny_http::Header::from_bytes("Referrer-Policy", "no-referrer").unwrap(),
                )
        };
        if !accepted {
            let _ = incoming.respond(reply("Invalid callback.", 400));
            continue;
        }
        let result = check_callback(parsed?.query().unwrap_or(""), &state, existing);
        let _ = incoming.respond(reply(
            "You may close this tab. Check the login helper for the result.",
            200,
        ));
        break result?;
    };
    drop(server);
    let mut registration = Registration {
        client_id: issued.clone(),
        subject: old.and_then(|r| r.subject),
    };
    // Keep the issued registration even if the single-use code exchange fails.
    save(&registration_key, &registration)?;
    status("Verifying authorization…".into(), None);
    let value = json(
        client
            .post(format!("{ISSUER}/api/accounts/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", &issued),
                ("code", &code),
                ("code_verifier", &verifier),
                ("redirect_uri", &redirect),
                ("resource", RESOURCE),
            ])
            .send()
            .context("Token exchange could not reach OpenAI")?,
        "Token exchange",
    )?;
    let verified = (|| -> Result<Tokens> {
        validate_grant(&value)?;
        let jwks: JwkSet = serde_json::from_value(json(
            client
                .get(format!("{ISSUER}/.well-known/jwks.json"))
                .send()
                .context("Could not retrieve identity signing keys")?,
            "Signing keys",
        )?)?;
        let identity = verify(value["id_token"].as_str().unwrap(), &issued, &nonce, &jwks)?;
        ensure!(
            registration
                .subject
                .as_ref()
                .is_none_or(|s| *s == identity.sub),
            "Returning account identity changed"
        );
        ensure!(
            !cancelled() && now() < request.expires_at,
            "Authorization cancelled or expired"
        );
        registration.subject = Some(identity.sub.clone());
        save(&registration_key, &registration)?;
        Ok(Tokens {
            client_id: issued.clone(),
            host_id: request.host_id.clone(),
            subject: identity.sub,
            access_token: value["access_token"].as_str().unwrap().into(),
            refresh_token: value["refresh_token"].as_str().unwrap().into(),
            token_type: "Bearer".into(),
            scope: SCOPES.join(" "),
            expires_at: now() + value["expires_in"].as_u64().unwrap(),
        })
    })();
    if verified.is_err()
        && let Some(token) = value["refresh_token"]
            .as_str()
            .or(value["access_token"].as_str())
    {
        let revoked = client
            .post(format!("{ISSUER}/api/accounts/oauth/revoke"))
            .form(&[("token", token), ("client_id", &issued)])
            .send()
            .is_ok_and(|r| r.status().is_success());
        if !revoked {
            bail!(
                "Authorization was rejected; remote revocation was not confirmed. Disconnect this app in ChatGPT settings."
            );
        }
    }
    verified
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_identity_is_required_and_bound() {
        use aws_lc_rs::{
            rand::SystemRandom,
            rsa::KeySize,
            signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents},
        };
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let public = RsaPublicKeyComponents::<Vec<u8>>::from(key.public_key());
        let sign = |claims: &serde_json::Value| {
            let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"fixture"}"#);
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
            let message = format!("{header}.{payload}");
            let mut signature = vec![0; key.public_modulus_len()];
            key.sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .unwrap();
            format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
        };
        let claims = serde_json::json!({"sub":"fixture-subject", "nonce":"nonce", "aud":"client", "iss":ISSUER, "iat":now(), "exp":now()+60});
        let token = sign(&claims);
        let keys: JwkSet = serde_json::from_value(serde_json::json!({"keys":[{"kty":"RSA", "kid":"fixture", "alg":"RS256", "n":URL_SAFE_NO_PAD.encode(&public.n), "e":URL_SAFE_NO_PAD.encode(&public.e)}]})).unwrap();
        assert_eq!(
            verify(&token, "client", "nonce", &keys).unwrap().sub,
            "fixture-subject"
        );
        assert!(verify(&token, "other", "nonce", &keys).is_err());
        assert!(verify(&token, "client", "other", &keys).is_err());
        let mut expired = claims.clone();
        expired["exp"] = (now() - 60).into();
        assert!(verify(&sign(&expired), "client", "nonce", &keys).is_err());
        let mut future = claims.clone();
        future["iat"] = (now() + 60).into();
        assert!(verify(&sign(&future), "client", "nonce", &keys).is_err());
        future.as_object_mut().unwrap().remove("iat");
        assert!(verify(&sign(&future), "client", "nonce", &keys).is_err());
        let mut wrong = claims;
        wrong["iss"] = "https://evil.example".into();
        assert!(verify(&sign(&wrong), "client", "nonce", &keys).is_err());
        let mut broken = token.into_bytes();
        let at = broken.len() - 10;
        broken[at] = if broken[at] == b'A' { b'B' } else { b'A' };
        assert!(
            verify(
                std::str::from_utf8(&broken).unwrap(),
                "client",
                "nonce",
                &keys
            )
            .is_err()
        );
    }
    #[test]
    fn callback_binding() {
        assert!(check_callback("state=x&code=c&client_id=oaiapp_123", "x", None).is_ok());
        assert!(check_callback("state=x&code=c", "x", Some("oaiapp_123")).is_ok());
        for query in [
            "state=y&code=c&client_id=a",
            "state=x&state=x&code=c&client_id=a",
            "state=x&error=access_denied",
            "state=x&code=c&client_id=other",
        ] {
            assert!(check_callback(query, "x", Some("oaiapp_123")).is_err());
        }
    }
    #[test]
    fn grants_cannot_expand_permissions() {
        let mut value = serde_json::json!({"scope": SCOPES.join(" "), "token_type":"Bearer", "access_token":"a", "refresh_token":"r", "id_token":"i", "expires_in":3600});
        assert!(validate_grant(&value).is_ok());
        value["scope"] = format!("{} email", SCOPES.join(" ")).into();
        assert!(validate_grant(&value).is_err());
        value["scope"] = SCOPES.join(" ").into();
        value["refresh_token"] = serde_json::Value::Null;
        assert!(validate_grant(&value).is_err());
    }
}
