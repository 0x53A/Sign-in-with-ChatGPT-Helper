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

The helper performs OAuth and approved proxy operations. The browser stores only
opaque, helper-encrypted credential bundles. Never return bearer tokens to JS,
read credentials from Codex/other apps, or add production auth bypasses/endpoint
overrides. Proxy sessions require a click and last only for their WebSocket.
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
contain their own implementations. The UI owns approval/result state. Login workers are blocking; each proxy request uses a worker with a current-thread Tokio runtime so request
cancellation, Stop and disconnect can cancel its upstream work. A single session
thread owns the WebSocket; workers share a bounded output channel. No new dependencies.

- main.rs: UI, listener controls, PIN attempts and exclusive request selection.
- server.rs: loopback Host/Origin validation, pending workers and delivery.
- protocol.rs: request/schema validation, Stored ZIPs, RSA-OAEP/AES-GCM envelopes.
- proxy.rs: approval, rate limits, cached JWKS, JWT validation and streaming relay.
- vault.rs: persistent installation keypair and origin-bound credential sealing.
- auth.rs: fixed OpenAI endpoints, callback validation, identity verification,
  exact grants, metadata persistence and rejection-time revocation.

Keep standard protocol and crypto libraries instead of replacing them with
custom parsers merely to lower the crate count. Direct dependencies have these
roles:

| Dependencies | Purpose / selected scope |
| --- | --- |
| eframe, rfd, webbrowser | egui GUI/OS clipboard, native file picker, open the OAuth URL |
| reqwest, tokio | Blocking login and cancellable async proxy HTTPS, Rustls/platform trust, no redirects |
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
website, PWA or extension. A small plain HTML/JS demo stores opaque credentials and
sends requests through click-approved helper sessions. No service worker, updater or backend.

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
registration and encrypted credentials. Static hosting needs only the six
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
5. Close the helper login result, then select **Connect proxy** on the page and
   **Approve** in the helper. Select a model, enter a message and **Send**. Keep
   the helper running; each tab/reconnection needs separate approval.

The helper lists incoming requests, with three PIN attempts
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

Request: one `request.json` entry, version 2, random 32-byte base64url request ID,
app name, origin, persistent random `urn:uuid:` host ID, optional issued client ID,
Unix-seconds expiry, exact scope array and public RSA JWK (`kty`, `n`, `e`).
WebSocket `/pair` takes `{request: "<exact JSON bytes>", pin: "0000"}`. The declared
origin must equal the handshake Origin; Host must be the literal loopback address
and selected port. Missing/null origins and insecure non-loopback web origins fail.

Response (v2): one stored `response.json` ZIP entry, or that JSON object on the socket:
`version`, `request_id`, `request_hash`, `wrapped_key`, `iv`, `ciphertext`.
RSA-OAEP/SHA-256 wraps a random AES-256 key. AES-GCM uses a random 12-byte IV and a
128-bit tag appended to ciphertext. Binary fields use unpadded base64url.
Additional authenticated data is UTF-8
`chatgpt-helper-v2:<request_id>:<SHA256-of-exact-request-JSON-base64url>`.
The decrypted transport payload contains client ID, host ID, verified subject,
expiry and an opaque credential bundle. The bundle is separately encrypted for
this helper installation (RSA-OAEP/SHA256 wrapping AES-256-GCM); its plaintext
contains the origin and tokens. The browser never receives the underlying tokens. Encryption protects
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

The helper keeps its RSA private key in
`$XDG_DATA_HOME/0x53a-chatgpt-login-helper/helper-key.pk8`, defaulting to
`~/.local/share/0x53a-chatgpt-login-helper/helper-key.pk8`. Empty/relative XDG paths
are ignored. APPDATA is the Windows fallback. Newly created Unix directories are
0700 and key files 0600. The key is generated lazily, atomically published without
overwriting another process's key, and reused. Corrupt keys fail closed; restoring
the original key recovers bundles. Losing it requires signing in again. No user
tokens are stored by the helper. Registrations remain under XDG_CONFIG_HOME.

The browser stores sealed bundles and registration metadata in IndexedDB. It keeps
only a non-extractable transport private key while an offline request is pending.
The v2 storage upgrade removes old browser-decryptable tokens and requires a fresh
sign-in. Close old demo tabs if they block the upgrade. A compromised origin can
use its bundle through an approved session; it cannot extract OpenAI bearer keys.
Copying a bundle to a different origin/helper fails. This does not protect against
malicious native software with access to the helper key or process memory.

## Approved proxy sessions

The same loopback listener accepts WebSocket `/proxy`. Host/Origin checks are
identical to pairing. Each connection queues a native Approve/Reject row with its
browser origin; approval is never inherited by a reconnect. Approved rows show
request counts and Stop. Each row has a checked-by-default Rate limit checkbox,
editable before or after approval. Disabling the listener, changing port, exiting the helper,
Stop, or closing the page terminates sessions. Existing approved sessions remain
visible during another login; new approvals wait until its result is closed.

Only these operations are allowed (no arbitrary URL, method or header forwarding):

| Operation | Fixed upstream |
| --- | --- |
| models | GET https://api.openai.com/v1/models |
| responses | POST https://api.openai.com/v1/responses, store=false, stream=true |
| refresh | POST https://auth.openai.com/api/accounts/oauth/token, refresh_token grant only |
| revoke | POST https://auth.openai.com/api/accounts/oauth/revoke, stored refresh token only |

After approval, the helper sends `{type:"ready", protocol:1}`. Clients send
`{type:"request", id, request:{endpoint, credentials:bundle, body?}}`.
IDs are increasing nonzero unsigned 32-bit integers, never reused on a connection,
including after rejection/cancellation. Each JSON response carries its request ID.
Models/inference return headers, binary chunks prefixed with the four-byte
big-endian request ID, then end. Streams may interleave. Refresh returns credentials
with a replacement sealed bundle; revoke returns revoked. A request error has
`{id,type:"error",message}` and does not terminate other requests. Malformed
commands/reused IDs close the session. Neither side automatically retries.
`{type:"cancel",id}` cancels just that request; Stop/disconnect cancels all.
The demo transport accepts an optional AbortSignal as its fourth argument, and
cancelling a Response body also cancels just that request. Late cancelled replies
are discarded. Client-side refresh remains serialized with Web Locks.
Token endpoint responses are never relayed in plaintext. Credentials are decrypted
only for an operation and discarded afterwards; no conversation/request history.
Transient buffers and counters are necessary for forwarding and limits.

The first token-validation request fetches the fixed issuer JWKS, cached in memory
for 24 hours. Unknown key IDs do not trigger extra downloads. Failed fetches back
off for 60 seconds and stale keys are not used. RS256 signatures, issuer, audience,
client, subject, iat, nbf, expiry and inference scopes are checked. Refresh/revoke
allow an expired access-token signature because the sealed refresh token must remain
usable; OpenAI still decides revocation/refresh validity. Local validation cannot
prove a token has not been revoked.

A checked Rate limit allows 30 request attempts per rolling minute and two active
requests per session. Unchecking disables both restrictions. There are no global
request/concurrency/connection limits. Rechecking applies to new requests without
cancelling existing work; recent attempts while unchecked still count. Rejected
attempts count, cancellation messages do not. A limit violation rejects only that
request, keeping the approved connection usable. Requests are bounded to 1 MiB and streamed responses to
8 MiB (demo inference text stream limit 4 MiB). Approval times out after two minutes;
upstream operations after two minutes. Stop cancels the upstream future; already
processed upstream work cannot be undone. Browser refreshes are serialized with
Web Locks and persisted before use. An ambiguous refresh leaves a marker requiring
sign-in again rather than risking reuse of a rotating refresh token. Logout clears
local storage first and attempts revocation through the approved connection; if it
cannot, use ChatGPT settings to revoke. No native billing/API-key fallback.

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
inference and desktop/mobile layout. They do not prove live OpenAI admission. Real login requires the user's interactive consent.

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
