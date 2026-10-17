use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rsa::{
    BigUint, Oaep, RsaPublicKey,
    rand_core::{OsRng, RngCore},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Cursor, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_PORT: u16 = 17653;
pub const LIMIT: usize = 64 * 1024;
pub const SCOPES: [&str; 4] = [
    "openid",
    "resource.invoke",
    "chatgpt.tokens.use.direct",
    "offline_access",
];

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn random() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    B64.encode(b)
}
pub fn hash(bytes: &[u8]) -> String {
    B64.encode(Sha256::digest(bytes))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub kty: String,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub request_id: String,
    pub app_name: String,
    pub origin: String,
    pub host_id: String,
    pub client_id: Option<String>,
    pub expires_at: u64,
    pub scopes: Vec<String>,
    pub public_key: PublicKey,
}

pub fn valid_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let allowed = url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        || matches!(url.scheme(), "moz-extension" | "chrome-extension");
    allowed
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.path().is_empty() || url.path() == "/")
        && !value.ends_with('/')
        && url.host_str().is_some()
}

impl Request {
    pub fn parse(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= LIMIT, "Request too large");
        let request: Self = serde_json::from_str(raw).context("Invalid request JSON")?;
        ensure!(request.version == 1, "Unsupported protocol version");
        ensure!(
            B64.decode(&request.request_id).is_ok_and(|v| v.len() == 32),
            "Invalid request ID"
        );
        ensure!(
            !request.app_name.is_empty()
                && request.app_name.len() <= 80
                && !request.app_name.chars().any(char::is_control),
            "Invalid app name"
        );
        ensure!(
            valid_origin(&request.origin),
            "Expected an HTTPS, loopback, or extension origin"
        );
        ensure!(
            request.origin.len() <= 512
                && request.host_id.len() <= 100
                && request.host_id.starts_with("urn:uuid:")
                && request
                    .host_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ":-".contains(c)),
            "Invalid host identifier"
        );
        ensure!(
            request.client_id.as_ref().is_none_or(|v| !v.is_empty()
                && v.len() <= 200
                && v != "dynamic_agent_client"
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))),
            "Invalid client ID"
        );
        ensure!(
            request.expires_at > now() && request.expires_at <= now() + 86400,
            "Request expired or lifetime exceeds 24 hours"
        );
        ensure!(
            request.scopes.len() == SCOPES.len()
                && SCOPES.iter().all(|s| request
                    .scopes
                    .iter()
                    .filter(|x| x.as_str() == *s)
                    .count()
                    == 1),
            "Unexpected requested permissions"
        );
        request.key()?;
        Ok(request)
    }
    pub fn key(&self) -> Result<RsaPublicKey> {
        ensure!(
            self.public_key.kty == "RSA"
                && self.public_key.n.len() <= 700
                && self.public_key.e == "AQAB",
            "Expected RSA key with exponent 65537"
        );
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(&B64.decode(&self.public_key.n)?),
            BigUint::from(65537u32),
        )?;
        ensure!(
            (2048..=4096).contains(&key.n().bits()),
            "RSA key must be 2048–4096 bits"
        );
        Ok(key)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tokens {
    pub client_id: String,
    pub host_id: String,
    pub subject: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub scope: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub request_id: String,
    pub request_hash: String,
    pub wrapped_key: String,
    pub iv: String,
    pub ciphertext: String,
}

pub fn encrypt(raw: &str, request: &Request, tokens: &Tokens) -> Result<Envelope> {
    ensure!(
        request.expires_at > now(),
        "Request expired before delivery"
    );
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);
    let request_hash = hash(raw.as_bytes());
    let aad = format!("chatgpt-helper-v1:{}:{}", request.request_id, request_hash);
    let plaintext = serde_json::to_vec(tokens)?;
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    let wrapped = request
        .key()?
        .encrypt(&mut OsRng, Oaep::new::<rsa::sha2::Sha256>(), &key)?;
    Ok(Envelope {
        version: 1,
        request_id: request.request_id.clone(),
        request_hash,
        wrapped_key: B64.encode(wrapped),
        iv: B64.encode(iv),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn read_package(bytes: &[u8], name: &str) -> Result<String> {
    ensure!(bytes.len() <= LIMIT, "Package too large");
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).context("Invalid ZIP")?;
    ensure!(zip.len() == 1, "Package must contain exactly one JSON file");
    let mut file = zip.by_index(0)?;
    ensure!(
        file.name()? == name && file.size() <= LIMIT as u64,
        "Unexpected ZIP entry"
    );
    let mut result = String::new();
    (&mut file)
        .take(LIMIT as u64 + 1)
        .read_to_string(&mut result)?;
    if result.len() > LIMIT {
        bail!("Expanded package too large");
    }
    Ok(result)
}

pub fn package(name: &str, json: &str) -> Result<Vec<u8>> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        name,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    zip.write_all(json.as_bytes())?;
    Ok(zip.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origins_are_precise() {
        for origin in [
            "https://example.org",
            "http://127.0.0.1:8080",
            "moz-extension://abc",
        ] {
            assert!(valid_origin(origin));
        }
        for origin in [
            "null",
            "http://evil.test",
            "https://user@host.test",
            "https://host.test/path",
            "https://host.test?x=1",
            "https://host.test/",
        ] {
            assert!(!valid_origin(origin));
        }
    }
    #[test]
    fn archives_are_bounded_and_named() {
        let bytes = package("request.json", "{}").unwrap();
        assert_eq!(read_package(&bytes, "request.json").unwrap(), "{}");
        assert!(read_package(&bytes, "response.json").is_err());
        assert!(
            read_package(
                &package("request.json", &"x".repeat(LIMIT + 1)).unwrap(),
                "request.json"
            )
            .is_err()
        );
    }
}
