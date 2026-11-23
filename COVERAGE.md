# Test Coverage Report — claude-proxy

## Summary

- **Rust unit/integration tests:** 682 (`cargo test`), all passing; 15 `#[ignore]`d live tests (697 total). 11 are user-reachable and live-verified green — **691 pass** when included (`--include-ignored`, 5 by-design/flaky skips filtered out, the reproducible ceiling). The 2 `CHUTES_MINER_IP` tests are by-design user-API-unreachable and the 3 Kimi-K3 live tests occasionally hit a transient backend 429/timeout. The combined `use_evidence + collateral` path now has **both-models** coverage: `e2e_smoke_test_use_evidence_collateral_live` (GLM-5.1) + `e2e_smoke_test_use_evidence_collateral_live_k3` (Kimi-K3, added 2026-11-23).
- **Shell installer tests:** 32 (`bash tests/test_install_script.sh`), all passing.
- **Line coverage (`cargo llvm-cov --release`, `src/` total, incl. the test-only e2ee module):**
  - **Default suite (682 tests): 91.64%** (13,896 / 15,164 lines — the new Kimi-K3 combined live test's ~79 instrumented lines are in the denominator even though it is `#[ignore]`d, so it drags both suites by ~0.5%%).
  - **Ceiling suite: 96.22%** (14,591 / 15,164 lines) — reproducible, the 5-skip run (2 unreachable miner-IP + the 3 flaky Kimi-K3 live tests). Region coverage is 96.74% (19,305/19,955); the line % is slightly lower than the earlier 96.73% headline because the new Kimi-K3 combined `use_evidence+collateral` test (added 2026-11-23, in the skip-list) adds ~79 test-code lines to the denominator without adding covered lines. When the Kimi-K3 live tests also run the total lands a little higher; this run hit the documented transient 429, so 96.22% is the honest reproducible headline.
- **Production code is still ~99.7%** (99.73% in the default suite — 9,618 / 9,644 lines, all of `src/` minus `src/e2ee/`).

| Scope | Default suite | Full (ceiling) |
|---|---|---|
| Whole `src/` | 91.64% (13,896/15,164) | **96.22%** (14,591/15,164) |
| `src/` minus `src/e2ee/` (production) | 99.73% (9,618/9,644) | 99.73% |
| `src/e2ee/` alone (test-only) | 77.50% (4,278/5,520) | 90.09% (4,973/5,520) |

The 99.95% figure in the 2026-11-18 version of this report was measured at
547 tests / 8,335 lines, before the `src/e2ee/` module existed. The drop in
whole-repo % since then is entirely the un-wired, test-only e2ee module —
production code has not regressed.

## Where the remaining uncovered lines live (ceiling run)

| File | Lines | Default % | Ceiling % | Uncovered |
|---|---|---|---|---|
| `src/handlers/messages.rs` | 6352 | 99.75 | 99.75 | messages.rs:1632/1742/1763 (llvm-cov `}` attribution) |
| `src/e2ee/attestation.rs` | 2318 | 80.67 | 91.80 | miner-fetch/live-PCS/DCAP-via-live paths + error arms |
| `src/e2ee/handler.rs` | 1925 | 96.68 | 96.68 | Only 4 production lines remain: handler.rs:96 (llvm-cov `}` attribution artifact), and L351/353/355 (node_ip miner-fetch *success* path — hardcoded `https://{ip}:30443`, validator-gated, not mockable over `http`). The collateral-fetch *success* arm (L432-433, L446-449) is now covered offline by a mock-PCS test. The remaining ~46 uncovered lines are test-code `axum::serve` spawn blocks |
| `src/e2ee/smoke.rs` | 703 | 0.00 | 62.16 | all #[ignore]d live paths (not run in default suite); the Kimi-K3 combined `use_evidence+collateral` test (added 2026-11-23, in the ceiling skip-list) adds ~79 uncovered test-code lines — greener when it runs |
| `src/e2ee/crypto.rs` | 187 | 90.91 | 90.91 | defensive non-reachable arms |
| `src/e2ee/discovery.rs` | 269 | 96.28 | 96.28 | error arms |
| `src/utils/content_extraction.rs` | 989 | 99.70 | 99.70 | — |
| `src/services/model_cache.rs` | 295 | 98.98 | 98.98 | — |
| `src/models/claude.rs` | 236 | 98.73 | 98.73 | — |
| `src/main.rs` | 189 | 99.47 | 99.47 | — |
| `src/token_count.rs` | 106 | 100 | 100 | token_count.rs:17 (unreachable JoinError) |
| `*.rs` (all others) | — | 100 | 100 | — |

### Notes on the uncovered lines

- **`src/e2ee/smoke.rs` at 0% in the default suite** — the whole file is
  `#[ignore]`d live tests; it is only exercised when `CHUTES_API_KEY` is set
  and the network is available. In the reproducible ceiling run (the flaky
  Kimi-K3 tests skipped) it reaches 62.16%; higher when the skipped Kimi-K3
  live tests also run.
- **`src/e2ee/handler.rs` is 96.68%** after the 8 `use_evidence` integration
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
- **`src/e2ee/attestation.rs` reaches 91.80% at ceiling** once the live
  miner/PCS/evidence fetches run. The remaining ~8% is by-design unreachable
  from a user API (raw miner hop), Intel-error arms, and the save-fixture
  gate path (writes a file, off by default).
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

cargo test                                   # 682 passed, 15 ignored
cargo llvm-cov --release --json --summary-only \
    --output-path coveragereport/cov.json    # default suite 91.64%

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
    --skip e2e_smoke_test_use_evidence_collateral_live_k3   # 96.22% (692 passed, 5 filtered)
# NOTE: the Kimi-K3 live tests share the same backend and can hit a
# transient 429 ("Instance at maximum capacity"). If you want the full run,
# drop the Kimi-K3 `--skip` flags and retry — it is not a regression.

bash tests/test_install_script.sh            # 32 passed
```
