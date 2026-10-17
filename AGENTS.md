# ChatGPT login helper

Rust egui native helper plus dependency-free HTML/JS example client. See README.md
for protocol and operational limits and DESIGN.md for visual rules. Parent
instructions apply. Operational records: ~/tasks/0066-generic-openai-login-helper.

Only the helper performs interactive OAuth. The browser owns credentials,
refresh and inference. Do not add a persistent inference proxy or read credentials
from Codex/other apps. Endpoint overrides and auth bypasses must never enter the
production app. Synthetic fixtures live in examples/interop.rs and tests/ only.
Never log tokens, codes, PINs, or request/response payloads. Native registration
metadata contains no bearer credentials. Preserve exact origin, request, identity,
scope, expiry and cryptographic binding checks.

Use `nix-shell` (matching `.envrc`) for Rust and native GUI libraries. Add crates
through cargo. No service worker, PWA installation, or explicit updater. Static
build copies local assets; no runtime CDN. Playwright is test-only.

Checks: cargo fmt --check; cargo clippy --locked --all-targets -- -D warnings;
cargo test --locked; cargo build --locked --examples; npm test; npm run build;
WEB_ROOT=target/pages npm run test:browser. CHROMIUM can select a local browser.
Publishing signs native and static archives with GitHub attestations; PRs cannot
sign/deploy. Keep actions pinned, lockfiles committed, and verify exact artifacts.
