# Repository instructions

Parent instructions apply. Task records: ~/tasks/0066-generic-openai-login-helper.
The user will write the human-facing README. Do not create or regenerate it.
Visual rules are in DESIGN.md.

## Layout

- helper/: Rust egui app, protocol, native OAuth and Cargo manifests/lockfile.
- demo/: dependency-free HTML/JS client; build.mjs and serve.mjs use Node built-ins.
- tests/: tests, npm manifests and Playwright dependencies. fixtures/interop.rs is
  a synthetic Cargo example target, used by browser tests for Rust/WebCrypto
  interoperability. It never contacts OpenAI and is not shipped with the helper.
- Generated: helper/target/, demo/dist/, tests/artifacts/, tests/node_modules/.
- .github/workflows/: PR validation and main-branch attested publication.

Only the helper performs interactive OAuth. The browser owns credentials,
refresh and inference. Do not add a persistent inference proxy, read credentials
from Codex/other apps, or add production auth bypasses/endpoint overrides.
Never log tokens, codes, PINs or request/response payloads. Native registration
metadata contains no bearer credentials. Preserve exact origin, request, identity,
scope, expiry and cryptographic binding checks. No service worker, PWA install,
explicit updater or runtime CDN. npm dependencies are test-only.

Use the root nix-shell for Rust/native GUI libraries and Node. Add crates with
cargo add --manifest-path helper/Cargo.toml. Keep lockfiles and pinned Actions.
Run Rust format/Clippy/tests, JS unit tests, static build and browser tests using
commands below. GUI verification: build the helper, then run under nix-shell:
CHROMIUM=/path/to/chromium XVFB=/path/to/Xvfb node tests/native-smoke.mjs
It needs ImageMagick import for screenshots and never approves real OAuth.
Use synthetic fixtures for automation; live login requires user interaction.

## Rust review map and dependency policy

The helper's own crates forbid unsafe code; platform/crypto dependencies still
contain their own implementations. No application-level async runtime is used:
the UI owns approval/result state and bounded blocking workers handle requests.

- main.rs: UI, listener controls, PIN attempts and exclusive request selection.
- server.rs: loopback Host/Origin validation, pending workers and delivery.
- protocol.rs: request/schema validation, Stored ZIPs, RSA-OAEP/AES-GCM envelopes.
- auth.rs: fixed OpenAI endpoints, callback validation, identity verification,
  exact grants, metadata persistence and rejection-time revocation.

Keep standard protocol and crypto libraries instead of replacing them with
custom parsers merely to lower the crate count. Direct dependencies have these
roles:

| Dependencies | Purpose / selected scope |
| --- | --- |
| eframe, rfd, webbrowser | egui GUI/OS clipboard, native file picker, open the OAuth URL |
| reqwest | Blocking HTTPS/form requests, Rustls/platform trust, no redirects |
| tiny_http, tungstenite | Loopback OAuth callback HTTP and WebSocket handshake |
| url | Origin/URL parsing and query encoding |
| jsonwebtoken | Verified RS256/JWK identity; shares TLS's AWS-LC backend, no PEM |
| aws-lc-rs | Shared TLS/JWT crypto backend: RSA-OAEP, AES-GCM, SHA-256, secure randomness |
| serde, serde_json, base64 | Typed messages, JSON and base64url encoding |
| zip | Bounded single-entry Stored archives, no compression features |
| anyhow | Contextual errors across these boundaries |

All cryptographic operations use the existing AWS-LC backend. Never substitute weak
randomness. Request IDs, OAuth state/nonce/verifier, AES key/IV and OAEP padding
all use operating-system randomness. Tests generate synthetic private keys
for signing fixtures. No real credentials are needed for test/build commands.

# Implementation and operation reference

An egui desktop application that completes OpenAI's loopback OAuth flow for a
website, PWA or extension. A small plain HTML/JS demo owns its credentials and
calls OpenAI directly after sign-in. No service worker, updater or backend.

Demo: https://0x53a.github.io/Sign-in-with-ChatGPT-Helper/

## Run

On NixOS:

```sh
nix-shell --run 'cargo run --manifest-path helper/Cargo.toml --locked'
```

On other desktop systems, install Rust and the platform's GUI build dependencies,
then `cargo run --manifest-path helper/Cargo.toml --locked`. Linux binary artifacts are built on Ubuntu 24.04; use
the source/Nix shell on NixOS. Other native platforms have not been validated.

Serve the demo locally with Node 22.7+ (CI uses Node 24):

```sh
node demo/serve.mjs
```

Open http://127.0.0.1:8767. Keep the same origin/browser profile to retain its
registration and encrypted credentials. Static hosting needs only the five
browser assets in `demo/`; the Node scripts are development tools.
`node demo/build.mjs` creates a fresh `demo/dist/` with assets, metadata and hashes.
Local metadata records the commit and whether the checkout is dirty. CI refuses
to build from a dirty checkout. Rebuilding removes stale files only from demo/dist.

## Online handoff

1. Start the helper. Default WebSocket port is **17653**, bound to **127.0.0.1**.
2. Click **Connect to helper** on the page. If needed, change the revealed port
   to match the helper and retry.
3. Check the browser-provided origin shown in the native window. Enter the page's
   four-digit PIN in its row and select **→**.
4. Choose **Open in Browser** (the system default), or **Copy Link to Clipboard**
   to use another browser. The helper never opens a browser automatically.
   Complete OpenAI sign-in. The helper verifies identity and grants, encrypts the
   response for this client, and sends it on that same WebSocket. It saves no tokens.
5. Select a model, enter a message and **Send**. The helper can close.

The helper lists incoming requests (up to 16 connections), with three PIN attempts
and a two-minute pairing deadline. Accepting one rejects the others and pauses
new requests until **Close** returns from the result screen. **Allow Connections**
controls the listener; the adjacent field changes its port. OAuth has a ten-minute
deadline. Closing the socket cancels the
transaction; a new socket cannot claim an old transaction by PIN. A PIN is a human
pairing check, not encryption or protection against malicious local processes.

Browsers may ask for local-network permission or block WebSockets to loopback.
The helper must already be running; the page cannot launch an executable. Use
request/response files if direct communication is unavailable. Localhost means
the device running the browser, not another computer on your network.

## File handoff

Choose **Download Offline Package** to download the request ZIP, open it in the
helper using **Import**. Importing a valid package starts sign-in immediately,
rejects pending requests and pauses new ones until the result is closed. The helper
still needs internet. Choose **Save result** for its encrypted response ZIP and import it on the original
page using **Import result**. This step survives a page reload. Imported app
names/origins are claims, not browser-verified identities. After login the demo
shows **Login Success**, **Logout**, and the inference controls.

The page keeps its non-extractable private key in IndexedDB, including across
reloads. Each new request replaces the previous pending request in this minimal
demo. Requests expire after 24 hours; successfully accepted responses consume
that pending key. The page has no token/private-key download controls.

Request: one `request.json` entry, version 1, random 32-byte base64url request ID,
app name, origin, persistent random `urn:uuid:` host ID, optional issued client ID,
Unix-seconds expiry, exact scope array and public RSA JWK (`kty`, `n`, `e`).
WebSocket `/pair` takes `{request: "<exact JSON bytes>", pin: "0000"}`. The declared
origin must equal the handshake Origin; Host must be the literal loopback address
and selected port. Missing/null origins and insecure non-loopback web origins fail.

Response: one stored `response.json` ZIP entry, or that JSON object on the socket:
`version`, `request_id`, `request_hash`, `wrapped_key`, `iv`, `ciphertext`.
RSA-OAEP/SHA-256 wraps a random AES-256 key. AES-GCM uses a random 12-byte IV and a
128-bit tag appended to ciphertext. Binary fields use unpadded base64url.
Additional authenticated data is UTF-8
`chatgpt-helper-v1:<request_id>:<SHA256-of-exact-request-JSON-base64url>`.
The decrypted payload contains the issued client ID, host ID, verified subject,
access/refresh tokens, token type, granted scopes and expiry. Encryption protects
the recipient; it does not authenticate an arbitrary file's producer. Only import
responses obtained from the helper you trust. Only uncompressed (Stored) ZIP entries are supported on both sides. ZIPs are bounded and never extracted
to filesystem paths; the client accepts the helper's single-entry stored format.

## Authorization and storage

The requested scopes are exactly:

```
openid resource.invoke chatgpt.tokens.use.direct offline_access
```

`openid` enables signed identity validation. `offline_access` enables refresh,
not offline inference. No email/profile scope is requested. Extra/missing grants
are rejected. State, PKCE, callback/client binding and ID-token signature, issuer,
audience, expiry, issued-at time and nonce are checked. Returning native registrations must retain
their verified subject. The native metadata file under
`$XDG_CONFIG_HOME/chatgpt-login-helper/registrations.json` (or the platform config
fallback) contains registration IDs and subjects, never access/refresh/ID tokens.

The browser encrypts its saved credentials using AES-GCM and a non-extractable
Web Crypto key in IndexedDB. Access tokens are decrypted into memory when needed;
refresh replacements are saved before use. Web Locks serialize refresh across
tabs. This is browser-owned authorization: same-origin code is trusted with it.
Non-extractable does **not** promise TPM protection, encrypted disk keys, or
protection from copying a profile or malicious same-origin scripts. Clearing site
data loses credentials and pending file keys. OpenAI currently recommends native/
server credential storage; this browser-owned demo deliberately explores another
architecture. No keys or tokens are logged, displayed or exported in plaintext.

Refresh and inference use the public OpenAI endpoints from the browser. CORS,
account eligibility and provider policy can prevent those requests. There is no
native proxy or silent API-key/billing fallback. A rotated refresh token is never
retried automatically after an ambiguous failure; sign in again if needed.
Disconnect attempts remote revocation and clears local tokens even if that fails;
use ChatGPT Settings to revoke access if remote revocation is unconfirmed.

Provider requests: https://developers.openai.com/siwc/token-sharing-open-source/sign-in
and https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions
and https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference.

## Tests

```sh
nix-shell --run 'cargo fmt --manifest-path helper/Cargo.toml --check && cargo clippy --manifest-path helper/Cargo.toml --locked --all-targets -- -D warnings && cargo test --manifest-path helper/Cargo.toml --locked && cargo build --manifest-path helper/Cargo.toml --locked --examples'
npm ci --prefix tests
npm test --prefix tests
node demo/build.mjs
npm exec --prefix tests -- playwright install chromium
WEB_ROOT=demo/dist npm run test:browser --prefix tests
```

Set `CHROMIUM=/path/to/chromium` on NixOS. Rust tests cover callback/grant checks,
origin/Host restrictions, bounded archives and exclusive request selection. Browser tests use synthetic tokens
and intercepted OpenAI responses: they exercise real Rust/WebCrypto ZIP exchange,
non-extractable key persistence, replay rejection, refresh serialization, streamed
inference and desktop/mobile layout. They do not prove live OpenAI admission or
browser CORS compatibility. Real login requires the user's interactive consent.

## Attested builds and GitHub Pages

The main-branch workflow checks the code and demo, builds the native helper,
attests both `site.tar.gz` and `helper-linux-x86_64.tar.gz` with GitHub OIDC/Sigstore,
verifies the evidence, then deploys the static page. This follows Secure-PWA's
build-provenance approach, without its runtime verification or updater.
PRs run checks without signing/publishing permissions. Actions and dependencies
are pinned. Audit archives and their bundle are retained in the Actions artifact;
`site.tar.gz` and `attestation.jsonl` are also available beside the live page.

Download the artifact from the Actions run for the commit you reviewed, then:

```sh
gh attestation verify site.tar.gz --bundle attestation.jsonl \
  --repo 0x53A/Sign-in-with-ChatGPT-Helper \
  --signer-workflow 0x53A/Sign-in-with-ChatGPT-Helper/.github/workflows/publish.yml \
  --source-ref refs/heads/main --source-digest REVIEWED_COMMIT \
  --deny-self-hosted-runners
```

Use the same command for the native archive. Extract the verified site archive
and run `sha256sum -c SHA256SUMS`. Compare against actual browser-received bytes
when auditing what executed. Attestations identify the build, not source safety,
reproducibility, freshness, or whether the hosting server delivered those bytes.
The plain page does not authenticate itself before execution. `build.json` links
its source commit and Actions run; it is metadata, not independently trusted proof.
