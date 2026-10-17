# Sign in with ChatGPT Helper

An egui desktop application that completes OpenAI's loopback OAuth flow for a
website, PWA or extension. A small plain HTML/JS demo owns its credentials and
calls OpenAI directly after sign-in. No service worker, updater or backend.

Demo: https://0x53a.github.io/Sign-in-with-ChatGPT-Helper/

## Run

On NixOS:

```sh
nix-shell --run 'cargo run --locked'
```

On other desktop systems, install Rust and the platform's GUI build dependencies,
then `cargo run --locked`. Linux binary artifacts are built on Ubuntu 24.04; use
the source/Nix shell on NixOS. Other native platforms have not been validated.

Serve the demo locally with Node 22+:

```sh
npm run serve
```

Open http://127.0.0.1:8767. Keep the same origin/browser profile to retain its
registration and encrypted credentials. Static hosting needs only `web/` files;
`npm run build` adds build metadata and hashes under `target/pages/`.

## Online handoff

1. Start the helper. Default WebSocket port is **17653**, bound to **127.0.0.1**.
2. Set the same port on the page and click **Sign in**.
3. Check the browser-provided origin shown in the native window. Enter the page's
   four-digit PIN there and select **Continue with ChatGPT**.
4. Complete OpenAI sign-in. The helper verifies identity and grants, encrypts the
   response for this client, and sends it on that same WebSocket. It saves no tokens.
5. Select a model, enter a message and **Send**. The helper can close.

Only one pairing is active at a time, with three PIN attempts and a two-minute
pairing deadline. OAuth has a ten-minute deadline. Closing the socket cancels the
transaction; a new socket cannot claim an old transaction by PIN. A PIN is a human
pairing check, not encryption or protection against malicious local processes.

Browsers may ask for local-network permission or block WebSockets to loopback.
The helper must already be running; the page cannot launch an executable. Use
request/response files if direct communication is unavailable. Localhost means
the device running the browser, not another computer on your network.

## File handoff

Expand **Use request / response files**, download the request ZIP, open it in the
helper, and explicitly approve the displayed app information. The helper still
needs internet. Save its encrypted response ZIP and import it on the original
page. Imported app names/origins are claims, not browser-verified identities.

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
responses obtained from the helper you trust. ZIPs are bounded and never extracted
to filesystem paths; the client accepts the helper's single-entry stored format.

## Authorization and storage

The requested scopes are exactly:

```
openid resource.invoke chatgpt.tokens.use.direct offline_access
```

`openid` enables signed identity validation. `offline_access` enables refresh,
not offline inference. No email/profile scope is requested. Extra/missing grants
are rejected. State, PKCE, callback/client binding and ID-token signature, issuer,
audience, expiry and nonce are checked. Returning native registrations must retain
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
nix-shell --run 'cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked && cargo build --locked --examples'
npm ci
npm test
npm run build
npx playwright install chromium
WEB_ROOT=target/pages npm run test:browser
```

Set `CHROMIUM=/path/to/chromium` on NixOS. Rust tests cover callback/grant checks,
origin/Host restrictions and bounded archives. Browser tests use synthetic tokens
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
