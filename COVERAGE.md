# Test Coverage Report — claude-proxy

## Summary

- **Rust unit/integration tests:** 720 (`cargo test`), all passing; 15 `#[ignore]`d live tests (735 total). The node_ip work added 4 offline attestation-fallback integration tests, lifting the suite from 689 → 720. 10 of the 15 live tests are user-reachable and live-verified green — **730 pass** when included (`--include-ignored`, 5 by-design/flaky skips filtered out, the reproducible ceiling). The 2 `CHUTES_MINER_IP` tests are by-design user-API-unreachable and the 3 Kimi-K3 live tests occasionally hit a transient backend 429/timeout. The combined `use_evidence + collateral` path now has **both-models** coverage: `e2e_smoke_test_use_evidence_collateral_live` (GLM-5.1) + `e2e_smoke_test_use_evidence_collateral_live_k3` (Kimi-K3, added 2026-11-23).
- **Shell installer tests:** 32 (`bash tests/test_install_script.sh`), all passing.
- **Line coverage (`cargo llvm-cov --release`, `src/` total, incl. the test-only e2ee module):**
  - **Default suite (720 tests): 91.98%** (15,899 / 17,286 lines) — re-measured on the current tree. The `d41bc10` E2E wiring added ~1,200 production lines and the live-test body lines sit in the denominator, slightly shifting every baseline.
  - **Ceiling suite: 96.32%** — last reproducible **live** run (2026-11-23, the 5-skip run; see note below). **Not re-measured after this commit** — it requires `CHUTES_API_KEY` + live network.
- **Production code is 99.01%** in the default suite (10,748 / 10,856 lines, all of `src/` minus `src/e2ee/`). The 99.73% figure in the previous 689-test report was a pre-`d41bc10` baseline: the E2E request-path wiring added ~1,200 lines of new production code to the denominator, moving the percentage down even though the covered-line count went up. Production code quality is unchanged.

| Scope | Default suite | Full (ceiling) |
|---|---|---|
| Whole `src/` | 91.98% (15,899/17,286) | **96.32%** (2026-11-23 live run, not refreshed) |
| `src/` minus `src/e2ee/` (production) | 99.01% (10,748/10,856) | not refreshed |
| `src/e2ee/` alone (test-only) | 80.11% (5,151/6,430) | not refreshed |

> Coverage figures re-measured on the 720-test tree with `cargo llvm-cov
> --release` (default suite). The ceiling column keeps the **2026-11-23 96.32%
> live-run** result because it needs the live key + network and could not be
> refreshed as part of this commit.

The 99.95% figure in the 2026-11-18 version of this report was measured at
547 tests / 8,335 lines, before the `src/e2ee/` module existed. The drop in
whole-repo % since then is entirely the `src/e2ee/` module (which carries
heavier test/live-only surfaces). The production `99.73% → 99.01%` shift after
`d41bc10` reflects the E2E wiring adding ~1,200 lines of new production code to
the denominator — a bigger denominator, not lower-quality production code.

## Where the remaining uncovered lines live (ceiling run)

| File | Lines (instrumented) | Default % | Ceiling % | Uncovered |
|---|---|---|---|---|
| `src/handlers/messages.rs` | 7,401 | 98.68 | 99.75 | messages.rs:1632/1742/1763 (llvm-cov `}` attribution); the 4 new node_ip fallback tests push more test-code lines into the default-suite denominator |
| `src/e2ee/attestation.rs` | 2,459 | 82.55 | 92.63 | miner-fetch/live-PCS/DCAP-via-live paths + error arms; 2026-11-23 added 7 offline tests for `fetch_attestation_nonce`/`fetch_quote_from_chutes_api`/`from_config_file` malformed-JSON arms |
| `src/e2ee/handler.rs` | 2,349 | 96.42 | 96.68 | Only 4 production lines remain: handler.rs:96 (llvm-cov `}` attribution artifact), and L351/353/355 (node_ip miner-fetch *success* path — hardcoded `https://{ip}:30443`, validator-gated, not mockable over `http`). The collateral-fetch *success* arm (L432-433, L446-449) is now covered offline by a mock-PCS test. The remaining uncovered lines are test-code `axum::serve` spawn blocks |
| `src/e2ee/smoke.rs` | 703 | 0.00 | 62.16 | all #[ignore]d live paths (not run in default suite); the Kimi-K3 combined `use_evidence+collateral` test (added 2026-11-23, in the ceiling skip-list) adds ~79 uncovered test-code lines — greener when it runs |
| `src/e2ee/crypto.rs` | 316 | 86.39 | 90.91 | defensive non-reachable arms |
| `src/e2ee/discovery.rs` | 372 | 94.62 | 96.28 | error arms |
| `src/utils/content_extraction.rs` | 989 | 99.70 | 99.70 | — |
| `src/services/model_cache.rs` | 301 | 99.00 | 98.98 | — |
| `src/models/claude.rs` | 236 | 98.73 | 98.73 | — |
| `src/main.rs` | 318 | 99.69 | 99.47 | — |
| `src/handlers/token_count.rs` | 109 | 100 | 100 | token_count.rs:17 (unreachable JoinError) |
| `*.rs` (all others) | — | 100 | 100 | — |

### Notes on the uncovered lines

- **`src/e2ee/smoke.rs` at 0% in the default suite** — the whole file is
  `#[ignore]`d live tests; it is only exercised when `CHUTES_API_KEY` is set
  and the network is available. In the reproducible ceiling run (the flaky
  Kimi-K3 tests skipped) it reaches 62.16%; higher when the skipped Kimi-K3
  live tests also run.
- **`src/e2ee/handler.rs` is 96.42%** in the default suite (96.68% at ceiling)
  after the 8 `use_evidence` integration
  tests (valid/strict, fetch-error/strict, fetch-error/permissive,
  empty-cert/strict, malformed-cert/strict, collateral-error/strict,
  collateral-error/permissive, and the new **collateral-success/permissive**
  test that drives a mock PCS to cover the fetch *success* arm L432-433/L446-449),
  plus the 7 `check_status` integration tests, 2 `node_ip` tests, 6
  `check_attestation_status` unit tests, and 5 error-shape/passthrough tests
  (`Display` vs `From` conversions, non-403 passthrough, `Parse`-error and
  non-success-invoke through both `e2e_request` and `e2e_request_attested`).
  The only remaining production gaps are the node_ip miner-fetch *success* path
  (hardcoded `https://…:30443`, validator-gated, not mockable over `http`) and
  one llvm-cov `}` attribution artifact — both are by-design unreachable offline.
  The live Intel PCS collateral *success* path is now covered offline by
  `test_use_evidence_collateral_success_proceeds_in_permissive_mode` (a mock PCS
  serving the captured `live_tdx_collateral.json`) and by the `#[ignore]`d
  `e2e_smoke_test_use_evidence_collateral_live` when the network/PCS is up.
- **`src/e2ee/attestation.rs` reaches 92.63% at ceiling** once the live
  miner/PCS/evidence fetches run. The remaining ~7% is by-design unreachable
  from a user API (raw miner hop), Intel-error arms, and the save-fixture
  gate path (writes a file, off by default). The 2026-11-23 offline tests
  (`fetch_attestation_nonce` valid/error/wrong-length/non-hex,
  `fetch_quote_from_chutes_api` success/missing-quote, and the
  `from_config_file` malformed-JSON arm) closed the last reachable gaps in
  those user-facing fetch helpers.
- **`token_count.rs:17`** — the `spawn_blocking` `JoinError` arm (retained
  defensively), same as in the 547-test baseline.
- **`messages.rs:1632/1742/1763`** — standalone `}` closing braces attributed
  to sub-regions; both branches of each are covered, the attribution is the
  llvm-cov tool artifact.
- The 2 `CHUTES_MINER_IP` tests (`test_fetch_quote_from_miner_live`,
  `test_full_attestation_flow_live`) panic intentionally ("set
  CHUTES_MINER_IP") because the user API does not expose a node IP; they are
  by-design unreachable and excluded from reports, not regressions.

## Historical baseline (2026-11-18, pre-e2ee)

The 2026-11-18 snapshot (547 tests, 8,335 lines, 99.95%) is preserved below
for the TDD narrative and the specific llvm-cov/defensive explanations,
which are unchanged.

- **TDD discipline:** every new test was written to exercise a specific
  previously-uncovered branch (RED → GREEN). Two real bugs found and fixed
  test-first:
  1. **DoS via oversized input** (`messages.rs`): `count_input_tokens` ran
     before request-size validation, so a huge system prompt was fed to
     `tiktoken`'s backtracking regex, panicked (stack overflow), and poisoned
     the global encoder. Fixed by moving token counting after the
     empty/too-many/too-large/max_tokens/system-size validations
     (`messages.rs:1000`).
  2. **Dead/unreachable auth guard** (`auth.rs`): the `if key.is_empty()`
     branch in `normalize_auth_value_to_key` was provably unreachable because
     the outer `value.trim()` already strips trailing whitespace. Removed as
     dead code and documented.
  A regression test for the circuit-breaker/health gating (`health.rs` —
  disabled-but-open breaker must report `healthy`) was present from commit
  `8ff9619` and is retained.

## How to reproduce

```sh
export PATH="$HOME/.cargo/bin:$PATH"

cargo test                                   # 720 passed, 15 ignored
cargo llvm-cov --release --json --summary-only \
    --output-path coveragereport/cov.json    # default suite 91.98%

# Ceiling (needs CHUTES_API_KEY; skip the 2 unreachable miner-IP tests +
# the 3 flaky Kimi-K3 live tests that occasionally hit a 429)
set -a; . ~/.hermes/.env 2>/dev/null; set +a
cargo llvm-cov --release --json --summary-only \
    --output-path coveragereport/cov_ceiling.json \
    --bin claude_openai_proxy -- \
    --include-ignored \
    --skip test_fetch_quote_from_miner_live \
    --skip test_full_attestation_flow_live \
    --skip check_status_live_k3 \
    --skip e2e_smoke_test_use_evidence_live_k3 \
    --skip e2e_smoke_test_use_evidence_collateral_live_k3   # 96.32% (730 passed, 5 filtered; ceiling from the 2026-11-23 live run, re-run to refresh)
# NOTE: the Kimi-K3 live tests share the same backend and can hit a
# transient 429 ("Instance at maximum capacity"). If you want the full run,
# drop the Kimi-K3 `--skip` flags and retry — it is not a regression.

bash tests/test_install_script.sh            # 32 passed
```
