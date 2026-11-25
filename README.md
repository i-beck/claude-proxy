# Claude Proxy

A Rust proxy that speaks the **Claude Messages API** on the wire and translates
to an **OpenAI-compatible** backend. On top of that translation layer it carries
a second, independent module: an **end-to-end encrypted (E2E) client for Chutes
TEE models** with **Intel TDX attestation verification**.

Two things to know up front:

- The translation layer is the live, shipped path. It is what `cargo run` serves.
- The E2E + TDX-attestation module (`src/e2ee/`) is **fully implemented, tested,
  and wired into the proxy's request path** behind the `E2E_ENABLED` flag. When
  the flag is on and a request targets a `-TEE` model, the running binary routes
  it through the encrypted, attested E2E channel. See
  [Status of the E2E module](#status-of-the-e2e-module) for what the flag does.

The original `claude-proxy` only did protocol translation. The `src/e2ee/` module
adds: encrypting requests to TEE models and verifying that those models are
running in genuine Intel TDX hardware (a full attestation chain, down to a
cryptographic DCAP signature check against Intel PCS).

---

## What the proxy does (translation layer)

It lets Claude Code or other Claude clients talk to a backend that exposes
`/v1/chat/completions`, while preserving Claude-style streaming, tool calls,
token counting, and model-friendly errors.

### Endpoints

- `POST /v1/messages`
- `POST /v1/messages/count_tokens`
- `GET /health`

### What works

- Claude-style SSE streaming and `stream: false`
- text, image, system, tool use, and tool result blocks
- multi-turn conversations
- model discovery and case correction when `/v1/models` is available
- thinking blocks when the backend exposes reasoning output

### Important limits

- only inline base64 document inputs are translated; URL/file-backed documents are
  degraded instead of forwarded
- prompt caching, citations, server tools, and audio are not implemented
- best results come from backends that expose both `/v1/chat/completions` and
  `/v1/models`

---

## Status of the E2E module

This section is the most important part of the README, because it states what the
code actually does today versus what is planned.

### What is implemented and tested

The `src/e2ee/` module is complete and covered by the test suite:

- **Crypto primitives** (`crypto.rs`) — ML-KEM-768 key exchange, HKDF-SHA256 key
  derivation, ChaCha20-Poly1305 AEAD, gzip. Blob layout:
  `mlkem_ct(1088) || nonce(12) || ciphertext || tag(16)`
  (`crypto.rs:10-12`, `crypto.rs:236`).
- **Instance + nonce discovery** (`discovery.rs`) — `GET /e2e/instances/{chute_id}`,
  TTL-cached nonce pool, proactive pre-fetch when the TTL is short
  (`discovery.rs:153`, `discovery.rs:175`).
- **TDX quote parsing + measurement pinning** (`attestation.rs`) — parses a raw
  TDX quote (MRTD / RTMR0-3 / REPORTDATA), pins measurements per guest image
  version (`attestation.rs:120`), and verifies key binding.
- **Miner attestation via `node_ip`** (`handler.rs`, `messages.rs`) — when the
  operator supplies `CHUTES_MINER_IP`, the proxy fetches a live TDX quote from
  the miner's attestation service (`https://{node_ip}:30443/server/attest`) and
  verifies it before falling back to the evidence endpoint.
- **Evidence endpoint integration** (`attestation.rs:1215`) — fetches a live TDX
  quote + TEE certificate from the user-reachable
  `GET /instances/{id}/evidence?nonce=` endpoint.
- **`use_evidence` cert binding** (`handler.rs:447`) — verifies
  `SHA-256(SPKI-der(cert)) == report_data[32..]`, binding the quote to the TEE's
  own attestation-service key.
- **DCAP verification against Intel PCS** (`attestation.rs:930`,
  `attestation.rs:1432`) — fetches Intel PCS v4 collateral and runs the
  `dcap-qvl` cryptographic signature check (the trusted root of the chain).
- **GLM-5.2 → Kimi-K3 swap** — the second cross-model smoke target is
  `moonshotai/Kimi-K3-TEE` (`smoke.rs:49`), swapped from `zai-org/GLM-5.2-TEE`
  (which was rate-limited / unreachable).
- **Robustness fixes (FIX 1–4)** — nonce pre-fetch (`discovery.rs:175`), SSE
  partial-chunk buffering with a 5s gap timeout (`crypto.rs:372`,
  `crypto.rs:498`), human-readable error messages (`handler.rs:49`,
  `attestation.rs:330`), and strict-mode retry on network error only
  (`handler.rs:353`, `handler.rs:391`, `attestation.rs:316`).

### How it is wired (as of d41bc10)

`E2E_ENABLED` is parsed into `RuntimeConfig` (`main.rs`) and threaded through
`build_app` into `App` (`app.rs`). When the flag is `true` and a request targets
a `-TEE` model, the request path in `src/handlers/messages.rs` calls
`e2e_request_attested` (`handler.rs`) — discovery, attestation, encryption,
decryption, and translation to the Claude Messages response.

Miner attestation via `node_ip` (this commit) is wired the same way: the
operator passes the miner's public IP via env `CHUTES_MINER_IP`; the proxy then
tries `https://{node_ip}:30443/server/attest` first for a live TDX quote, and
falls back to the user-reachable evidence endpoint (`use_evidence`) if the miner
hop is unreachable or returns an error. See
[Configuration](#configuration) for the env var and
[The E2E module, file by file](#the-e2e-module,-file-by-file) for the attestation
chain the fallback paths join.

### How to exercise the E2E module

Set `E2E_ENABLED=true` and (optionally) `CHUTES_MINER_IP` before starting the
proxy, then send requests to `-TEE` models. Or run the tests:

```sh
# Offline unit + integration tests (no network, no API key):
cargo test --bin claude_openai_proxy

# Live smoke tests against the real Chutes TEE API (need a key + network):
set -a; . ~/.hermes/.env 2>/dev/null; set +a
cargo test --release -- --ignored --nocapture e2e_smoke
```

---

## Fastest Bootstrap

If you want the hosted Chutes setup, use the installer:

```bash
./install_claude_code.sh
```

That script:
- installs or updates Node.js and `@anthropic-ai/claude-code`
- fetches models from `https://llm.chutes.ai/v1/models`
- writes `~/.claude/settings.json`
- points Claude Code at `https://claude.chutes.ai`

This is the easiest way to get Claude Code working against the hosted proxy.

## Self-Host

### Run From Source

```bash
BACKEND_URL=http://127.0.0.1:8000/v1/chat/completions \
HOST_PORT=8080 \
cargo run --release
```

The binary (`claude_openai_proxy`, `Cargo.toml:2-3`, version `0.1.15`) listens on
`HOST_PORT`, which defaults to `8080`.

### Run With Docker Compose

For a simple local setup without TLS:

```bash
HOST_PORT=8181 \
CADDY_PORT=8180 \
CADDY_TLS=false \
BACKEND_URL=https://llm.chutes.ai/v1/chat/completions \
docker compose up -d --build
```

With Compose:
- the proxy listens directly on `HOST_PORT`
- Caddy fronts it on `CADDY_PORT`
- `.env.example` is a starting point, not a one-size-fits-all local config

## Configure Claude Code Manually

If you are not using the installer, configure Claude Code the same way the
bootstrap script does:

```json
{
  "model": "zai-org/GLM-4.5-Air",
  "alwaysThinkingEnabled": true,
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8080",
    "ANTHROPIC_AUTH_TOKEN": "cpk_your_backend_key",
    "API_TIMEOUT_MS": "6000000"
  }
}
```

Put that in `~/.claude/settings.json` and adjust the URL, token, and model for
your setup.

Important:
- the proxy forwards the client bearer token to the backend
- use a backend-compatible token such as `cpk_*`
- Anthropic OAuth tokens like `sk-ant-*` are rejected

---

## The E2E module, file by file

All under `src/e2ee/` (declared in `mod.rs:1-7`).

| File | Lines | Responsibility |
|---|---|---|
| `crypto.rs` | 563 | ML-KEM-768, HKDF-SHA256, ChaCha20-Poly1305, gzip; blob layout; SSE partial-chunk buffering (`StreamChunkBuffer`, `decrypt_stream_buffered`) |
| `discovery.rs` | 544 | `GET /e2e/instances/{chute_id}` discovery, TTL nonce cache, proactive pre-fetch, 403 nonce handling |
| `attestation.rs` | 3899 | TDX quote parse, measurement pinning, key binding, evidence fetch, DCAP verify, network-error classifier |
| `handler.rs` | 3170 | Request pipeline: `e2e_request`, `e2e_request_attested`, attestation config, strict-mode retry, error messages |
| `smoke.rs` | 962 | Live smoke tests against the real Chutes TEE API (all `#[ignore]`d) |
| `mod.rs` | 343 | Module wiring + crypto round-trip tests |

### Wire protocol (do not change)

- **ML-KEM-768**: 1184-byte encapsulation key, 1088-byte ciphertext, 64-byte
  seed secret (`crypto.rs:10-12`).
- **ChaCha20-Poly1305**: 12-byte nonce + 16-byte tag, AEAD with empty AAD
  (`crypto.rs:149`, `crypto.rs:179`).
- **Request/response blob**: `mlkem_ct(1088) || nonce(12) || ciphertext || tag(16)`
  (`crypto.rs:236`, `crypto.rs:248`).
- **Streaming**: SSE `data: {"e2e": <base64>}` events; each event is one
  variable-length frame delimited by the `\n\n` event boundary, not a byte count
  (`crypto.rs:450`, `crypto.rs:498`).

### Attestation chain

1. **Parse** the raw TDX quote: header + TD report → MRTD, RTMR0-3, REPORTDATA
   (`attestation.rs:373`).
2. **Pin measurements** against the published table per guest image version
   (`attestation.rs:120`, `attestation.rs:653`).
3. **Key binding**: REPORTDATA = `nonce(32) || cert_hash(32)`; the cert-hash
   half must equal `SHA-256(SPKI-der(cert))` for the `use_evidence` path
   (`attestation.rs:715`, `handler.rs:447`).
4. **DCAP signature** (the trusted root): fetch Intel PCS v4 collateral and run
   `dcap-qvl` verification — `signature_verified` is `true` only when collateral
   is supplied and the check passes (`attestation.rs:930`, `attestation.rs:1432`).
5. **Mode**: `Strict` refuses on any attestation failure; `Permissive` logs and
   proceeds (`attestation.rs:809`).

### Robustness fixes (FIX 1–4)

- **FIX 1 — Nonce pre-fetch**: when the cached pool's TTL is `< 60s`, refresh
  proactively instead of handing out a nonce that will 403
  (`discovery.rs:175`, `discovery.rs:153`).
- **FIX 2 — SSE partial-chunk buffering**: reassemble raw bytes into complete SSE
  events before decrypting; never block more than 5s waiting for a frame
  (`crypto.rs:372`, `crypto.rs:498`, `crypto.rs:516`).
- **FIX 3 — Human-readable errors**: `user_message()` on every error type maps
  internal errors to plain-language strings, keeping the original as the debug
  source (`handler.rs:49`, `attestation.rs:330`, `discovery.rs:318`).
- **FIX 4 — Strict-mode retry**: on a *network* error (HTTP transport, 5xx,
  timeout) during the `use_evidence` evidence/collateral fetch, retry once after
  3s; refuse only if the second attempt also fails. Verification failures are
  **not** retried (`handler.rs:353`, `handler.rs:391`,
  `attestation.rs:316`).

---

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `BACKEND_URL` | OpenAI-compatible chat completions endpoint | `http://127.0.0.1:8000/v1/chat/completions` |
| `HOST_PORT` | Listen port for the Rust proxy | `8080` |
| `BACKEND_TIMEOUT_SECS` | Backend request timeout | `600` |
| `ENABLE_CIRCUIT_BREAKER` | Optional backend failure protection | `false` |
| `RUST_LOG` | Log level | `info` |
| `E2E_ENABLED` | Opt-in switch for the E2E module (routes `-TEE` models through the encrypted, attested channel) | `false` |
| `E2E_API_BASE` | E2E control-plane base URL (discovery + invoke) | `https://api.chutes.ai` |
| `CHUTES_MINER_IP` | Optional miner node IP; when set, attestation fetches a live TDX quote from `https://{ip}:30443/server/attest` before failing over to the evidence endpoint | unset |

`E2E_ENABLED` is live as of commit `d41bc10` (`main.rs`, `app.rs`,
`messages.rs`). `CHUTES_MINER_IP` is threaded the same way; when unset, the
proxy skips the miner hop and uses the user-reachable evidence endpoint only.

---

## Testing

```bash
export PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
./test.sh --ci --all
```

### Current test status

- **720 unit/integration tests pass, 0 fail, 15 ignored**
  (`cargo test --bin claude_openai_proxy`).
- The **15 ignored** tests are all live/network tests in `src/e2ee/smoke.rs`
  (8) and `src/e2ee/attestation.rs` (7). They require `CHUTES_API_KEY` and
  network access to `api.chutes.ai` and/or Intel PCS. Two of them
  (`test_fetch_quote_from_miner_live`, `test_full_attestation_flow_live`) are
  **by-design unreachable** — they need `CHUTES_MINER_IP`, which the user API does
  not expose (the raw `:30443/server/attest` hop is validator-gated).
- **Shell installer tests:** 32 (`bash tests/test_install_script.sh`).

Run the live suite (needs a key; the 2 miner-IP tests are skipped by design):

```sh
set -a; . ~/.hermes/.env 2>/dev/null; set +a
cargo test --release -- --ignored \
  --skip test_fetch_quote_from_miner_live \
  --skip test_full_attestation_flow_live
```

More test details live in [tests/README.md](tests/README.md).

### Coverage

Measured on the current 720-test tree with `cargo llvm-cov --release`:

| Scope | Line coverage |
|---|---|
| Whole `src/` (incl. the test-only `src/e2ee/`) | **91.98%** (15,899 / 17,286) |
| `src/` minus `src/e2ee/` (production) | **99.01%** (10,748 / 10,856) |
| `src/e2ee/` alone (test-only module) | **80.11%** (5,151 / 6,430) |

The whole-repo figure is dragged down by the `src/e2ee/` module (which carries
heavier test/live-only surfaces); the wiring of E2E into the request path
(`d41bc10`) added ~1,200 lines of new production code, moving the production
line-coverage baseline from 99.73% → 99.01%. When the live tests are included
(the reproducible "ceiling" run, 5 flaky/unreachable tests skipped) the
whole-repo figure rises to ~96% (96.32% per the last reproducible run documented
in `COVERAGE.md`). The `src/e2ee/smoke.rs` file reads 0% in the default suite
because the entire file is `#[ignore]`d live tests.

Reproduce:

```sh
cargo llvm-cov --release --json --summary-only --output-path coveragereport/cov.json
```

---

## The E2E commits

13 commits touch `src/e2ee/` (9 milestone commits + 4 robustness fixes; 15
including 2 docs commits). The milestone sequence:

| Commit | What it added |
|---|---|
| `ababba3` | E2E crypto primitives (ML-KEM-768, HKDF, ChaCha20-Poly1305, gzip) |
| `09be7fc` | Instance/nonce discovery with TTL caching + mock-server tests |
| `11c7c2b` | Handler with full request pipeline, 403 retry, and the `E2E_ENABLED` flag |
| `1a21094` | Smoke tests against the real Chutes TEE API |
| `f3805c6` | TDX attestation module: quote parsing, MRTD/RTMR verification, 51 tests |
| `5ded623` | Live TDX quote fetch + DCAP verification against real Intel PCS |
| `adcf69d` | User-reachable `use_evidence` attestation path + DCAP collateral |
| `ecf4b51` | Swap `GLM-5.2-TEE` → `Kimi-K3-TEE` for cross-model smoke tests |
| `7e82b0b` | Offline coverage for reachable-but-untested attestation paths |
| `bef4d0a` | FIX 1: nonce pre-fetch (proactive refresh when TTL < 60s) |
| `08b67b8` | FIX 2: SSE partial-chunk buffering (reassemble split events, 5s gap timeout) |
| `ffa0047` | FIX 3: human-readable error messages (`user_message()` on all error types) |
| `648febb` | FIX 4: strict-mode retry on network-error only (`use_evidence`) |

---

## Docs

- [docs/README.md](docs/README.md)
- [docs/CLAUDE_CODE_SETUP.md](docs/CLAUDE_CODE_SETUP.md)
- [docs/DOCKER.md](docs/DOCKER.md)
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
- [docs/e2e-attestation-investigation.md](docs/e2e-attestation-investigation.md) — the live API investigation and the current attestation reality
- [COVERAGE.md](COVERAGE.md) — coverage report and reproduction notes
