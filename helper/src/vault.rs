//! Installation keypair. Clients hold sealed credentials; only this helper opens them.
use crate::protocol::{self, Tokens};
use anyhow::{Context, Result, ensure};
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    encoding::AsDer,
    rand,
    rsa::{
        KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
        PrivateDecryptingKey,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub(crate) fn directory(data: bool) -> Result<PathBuf> {
    let variable = if data {
        "XDG_DATA_HOME"
    } else {
        "XDG_CONFIG_HOME"
    };
    let absolute = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let root = absolute(variable)
        .or_else(|| absolute("APPDATA"))
        .or_else(|| absolute("HOME").map(|p| p.join(if data { ".local/share" } else { ".config" })))
        .context("Cannot locate application directory")?;
    Ok(root.join(if data {
        "0x53a-chatgpt-login-helper"
    } else {
        "chatgpt-login-helper"
    }))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    version: u8,
    helper_id: String,
    wrapped_key: String,
    iv: String,
    ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub bundle: Bundle,
    pub client_id: String,
    pub host_id: String,
    pub subject: String,
    pub expires_at: u64,
}
#[derive(Serialize, Deserialize)]
struct Payload {
    origin: String,
    tokens: Tokens,
}
#[derive(Clone)]
pub struct Key {
    private: PrivateDecryptingKey,
    id: String,
}
impl Key {
    pub fn generate() -> Result<Self> {
        Self::new(PrivateDecryptingKey::generate(KeySize::Rsa2048)?)
    }
    fn new(private: PrivateDecryptingKey) -> Result<Self> {
        let id = protocol::hash(private.public_key().as_der()?.as_ref());
        Ok(Self { private, id })
    }
    fn load(path: &Path) -> Result<Self> {
        match fs::File::open(path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 16 * 1024, "Helper key file too large");
                Self::new(PrivateDecryptingKey::from_pkcs8(&bytes).context(
                    "Invalid helper key; restore the original key to use existing credentials",
                )?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().context("Missing key directory")?;
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(parent)?;
                let key = Self::generate()?;
                let temp = path.with_extension(format!("{}.tmp", protocol::random()?));
                let result = (|| -> Result<()> {
                    let mut options = fs::OpenOptions::new();
                    options.create_new(true).write(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let mut file = options.open(&temp)?;
                    file.write_all(key.private.as_der()?.as_ref())?;
                    file.sync_all()?;
                    // Publish without overwriting another helper process's key.
                    match fs::hard_link(&temp, path) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                        Err(e) => Err(e.into()),
                    }
                })();
                let _ = fs::remove_file(&temp);
                result?;
                Self::load(path)
            }
            Err(e) => Err(e.into()),
        }
    }
    pub fn seal(&self, origin: &str, tokens: Tokens) -> Result<Credentials> {
        let client_id = tokens.client_id.clone();
        let host_id = tokens.host_id.clone();
        let subject = tokens.subject.clone();
        let expires_at = tokens.expires_at;
        let mut ciphertext = serde_json::to_vec(&Payload {
            origin: origin.into(),
            tokens,
        })?;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        rand::fill(&mut key)?;
        rand::fill(&mut iv)?;
        let aad = format!("chatgpt-helper-sealed-v2:{}", self.id);
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key)?).seal_in_place_append_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_bytes()),
            &mut ciphertext,
        )?;
        let public = OaepPublicEncryptingKey::new(self.private.public_key())?;
        let mut wrapped = vec![0; public.ciphertext_size()];
        public.encrypt(
            &OAEP_SHA256_MGF1SHA256,
            &key,
            &mut wrapped,
            Some(aad.as_bytes()),
        )?;
        Ok(Credentials {
            bundle: Bundle {
                version: 2,
                helper_id: self.id.clone(),
                wrapped_key: B64.encode(wrapped),
                iv: B64.encode(iv),
                ciphertext: B64.encode(ciphertext),
            },
            client_id,
            host_id,
            subject,
            expires_at,
        })
    }
    pub(crate) fn open(&self, bundle: &Bundle, origin: &str) -> Result<Tokens> {
        ensure!(
            bundle.version == 2 && bundle.helper_id == self.id,
            "Credentials belong to another helper installation; sign in again"
        );
        ensure!(
            bundle.ciphertext.len() <= 128 * 1024 && bundle.wrapped_key.len() <= 700,
            "Credential bundle too large"
        );
        let aad = format!("chatgpt-helper-sealed-v2:{}", self.id);
        let iv: [u8; 12] = B64
            .decode(&bundle.iv)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid credential nonce"))?;
        let private = OaepPrivateDecryptingKey::new(self.private.clone())?;
        let mut unwrapped = vec![0; self.private.key_size_bytes()];
        let key = private.decrypt(
            &OAEP_SHA256_MGF1SHA256,
            &B64.decode(&bundle.wrapped_key)?,
            &mut unwrapped,
            Some(aad.as_bytes()),
        )?;
        ensure!(key.len() == 32, "Invalid credential key");
        let mut ciphertext = B64.decode(&bundle.ciphertext)?;
        let plaintext = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key)?).open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_bytes()),
            &mut ciphertext,
        )?;
        let payload: Payload = serde_json::from_slice(plaintext)?;
        ensure!(
            payload.origin == origin,
            "Credentials belong to a different browser origin"
        );
        Ok(payload.tokens)
    }
}
static KEY: Mutex<Option<Key>> = Mutex::new(None);
pub(crate) fn installation() -> Result<Key> {
    let mut key = KEY
        .lock()
        .map_err(|_| anyhow::anyhow!("Helper key unavailable"))?;
    if key.is_none() {
        *key = Some(Key::load(&directory(true)?.join("helper-key.pk8"))?);
    }
    Ok(key.as_ref().unwrap().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tokens() -> Tokens {
        Tokens {
            client_id: "client".into(),
            host_id: "host".into(),
            subject: "subject".into(),
            access_token: "secret-access".into(),
            refresh_token: "secret-refresh".into(),
            scope: protocol::SCOPES.join(" "),
            token_type: "Bearer".into(),
            expires_at: protocol::now() + 60,
        }
    }
    #[test]
    fn sealed_credentials_require_original_key_origin_and_integrity() {
        let key = Key::generate().unwrap();
        let credentials = key.seal("https://example.org", tokens()).unwrap();
        let json = serde_json::to_string(&credentials).unwrap();
        assert!(!json.contains("secret-access") && !json.contains("secret-refresh"));
        assert_eq!(
            key.open(&credentials.bundle, "https://example.org")
                .unwrap()
                .access_token,
            "secret-access"
        );
        assert!(
            key.open(&credentials.bundle, "https://evil.example")
                .is_err()
        );
        assert!(
            Key::generate()
                .unwrap()
                .open(&credentials.bundle, "https://example.org")
                .is_err()
        );
        let mut changed = credentials.bundle.clone();
        let mut bytes = B64.decode(&changed.ciphertext).unwrap();
        bytes[0] ^= 1;
        changed.ciphertext = B64.encode(bytes);
        assert!(key.open(&changed, "https://example.org").is_err());
    }
    #[test]
    fn key_persists_without_saving_credentials_and_corruption_never_rotates_it() {
        let dir =
            std::env::temp_dir().join(format!("helper-key-test-{}", protocol::random().unwrap()));
        let path = dir.join("helper-key.pk8");
        let first = Key::load(&path).unwrap();
        let sealed = first.seal("https://example.org", tokens()).unwrap();
        let second = Key::load(&path).unwrap();
        assert_eq!(
            second
                .open(&sealed.bundle, "https://example.org")
                .unwrap()
                .refresh_token,
            "secret-refresh"
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(&path, b"broken").unwrap();
        assert!(Key::load(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
        fs::remove_dir_all(dir).unwrap();
    }
}
