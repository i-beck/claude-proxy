#!/usr/bin/env bash
#
# test_install_script.sh — verifies each security/correctness fix in install_claude_code.sh
# committed in d0f6cb6.  Each test asserts a property that would have FAILED before the fix.
#
# Run: bash test_install_script.sh  (requires bash >= 4; uses Homebrew bash on macOS)
# Exit non-zero on any failure.

set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/install_claude_code.sh"

PASS=0
FAIL=0

ok() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

err() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

# ---------------------------------------------------------------------------
# 1. Default model is a current, valid model (was zai-org/GLM-4.7-TEE — does not exist)
# ---------------------------------------------------------------------------
echo "Test: default model is valid (not the nonexistent GLM-4.7-TEE)"
default_model=$(grep -E '^DEFAULT_MODEL=' "$SCRIPT" | head -1 | sed 's/DEFAULT_MODEL=//; s/"//g')
if [ "$default_model" = "zai-org/GLM-4.7-TEE" ]; then
    err "default model is still the nonexistent GLM-4.7-TEE"
elif echo "$default_model" | grep -qE '^zai-org/GLM-[0-9].*-TEE$'; then
    ok "default model is a current TEE model: $default_model"
else
    err "default model '$default_model' does not match a GLM TEE pattern"
fi

# ---------------------------------------------------------------------------
# 2. e2ee PROXY_BASE_URL uses 127.0.0.1 (not the remote e2ee-local-proxy host)
# ---------------------------------------------------------------------------
echo "Test: e2ee proxy base URL points at 127.0.0.1"
if grep -q 'PROXY_BASE_URL="https://127.0.0.1:' "$SCRIPT"; then
    ok "e2ee PROXY_BASE_URL uses 127.0.0.1 with the local port"
else
    err "e2ee PROXY_BASE_URL does not use 127.0.0.1"
fi
# The old broken pattern (remote host + local port) must be absent.
if grep -q 'PROXY_BASE_URL="${E2EE_PROXY_HOST}:' "$SCRIPT"; then
    err "old broken e2ee URL (remote host + local port) is still present"
else
    ok "old broken e2ee URL pattern is absent"
fi

# ---------------------------------------------------------------------------
# 3. API key is passed via process.env, not string interpolation into JS
# ---------------------------------------------------------------------------
echo "Test: API key is not interpolated into JS (uses process.env)"
if grep -q 'process.env.CHUTES_API_KEY' "$SCRIPT" && grep -q 'const apiKey = process.env.CHUTES_API_KEY' "$SCRIPT"; then
    ok "API key is read from process.env.CHUTES_API_KEY"
else
    err "API key is not passed via process.env"
fi
# The old interpolation pattern must be absent.
if grep -q 'const apiKey = "'"$"'api_key'"'"'";' "$SCRIPT"; then
    err "old string-interpolation of api_key into JS is still present"
else
    ok "old string-interpolation of api_key is absent"
fi

# ---------------------------------------------------------------------------
# 4. API timeout is 600000 (10 min), not 6000000 (100 min)
# ---------------------------------------------------------------------------
echo "Test: API timeout is 600000 (10 minutes)"
timeout_ms=$(grep -E '^API_TIMEOUT_MS=' "$SCRIPT" | head -1 | sed 's/API_TIMEOUT_MS=//; s/"//g')
if [ "$timeout_ms" = "600000" ]; then
    ok "API_TIMEOUT_MS is 600000 (10 minutes)"
else
    err "API_TIMEOUT_MS is '$timeout_ms' (expected 600000)"
fi

# ---------------------------------------------------------------------------
# 5. Permission bypass is opt-in (CLAUDE_DANGEROUS_MODE), not on by default
# ---------------------------------------------------------------------------
echo "Test: permission bypass is opt-in"
if grep -q 'CLAUDE_DANGEROUS_MODE' "$SCRIPT"; then
    if grep -q 'skipDangerousModePermissionPrompt: true' "$SCRIPT" && ! grep -q 'dangerous ? { skipDangerousModePermissionPrompt: true' "$SCRIPT"; then
        err "skipDangerousModePermissionPrompt is unconditional"
    else
        ok "permission bypass is gated behind CLAUDE_DANGEROUS_MODE"
    fi
else
    err "CLAUDE_DANGEROUS_MODE opt-in flag not found"
fi
# The bypass must NOT be unconditionally enabled.
if grep -q 'bypassPermissions' "$SCRIPT" && ! grep -q 'dangerous ? { defaultMode: "bypassPermissions"' "$SCRIPT"; then
    err "bypassPermissions is set unconditionally"
else
    ok "bypassPermissions is only set when dangerous mode is enabled"
fi

# ---------------------------------------------------------------------------
# 6. Checksums are verified (download_and_verify + pinned SHA-256 for nvm and docker)
# ---------------------------------------------------------------------------
echo "Test: remote installers are checksum-verified"
if grep -q 'download_and_verify()' "$SCRIPT"; then
    ok "download_and_verify function exists"
else
    err "download_and_verify function not found"
fi
if grep -qE '^NVM_INSTALL_SHA256="[0-9a-f]{64}"' "$SCRIPT"; then
    ok "NVM installer has a pinned SHA-256 checksum"
else
    err "NVM installer is missing a pinned SHA-256 checksum"
fi
if grep -qE '^DOCKER_INSTALL_SHA256="[0-9a-f]{64}"' "$SCRIPT"; then
    ok "Docker installer has a pinned SHA-256 checksum"
else
    err "Docker installer is missing a pinned SHA-256 checksum"
fi
# download_and_verify must be called for both.
if grep -q 'download_and_verify "$DOCKER_INSTALL_URL" "$DOCKER_INSTALL_SHA256"' "$SCRIPT"; then
    ok "Docker install calls download_and_verify"
else
    err "Docker install does not call download_and_verify"
fi
if grep -q 'download_and_verify "$NVM_INSTALL_URL" "$NVM_INSTALL_SHA256"' "$SCRIPT"; then
    ok "nvm install calls download_and_verify"
else
    err "nvm install does not call download_and_verify"
fi

# ---------------------------------------------------------------------------
# 7. Bash version guard requires bash >= 4
# ---------------------------------------------------------------------------
echo "Test: bash version guard requires >= 4"
if grep -Fq '_major="${BASH_VERSION%%.*}"' "$SCRIPT" && grep -Fq '[ "$_major" -lt 4 ]' "$SCRIPT"; then
    ok "bash version guard checks for major version >= 4"
else
    err "bash version guard not found"
fi
# Shebang must use /usr/bin/env bash, not /bin/bash.
if head -1 "$SCRIPT" | grep -q '^#!/usr/bin/env bash'; then
    ok "shebang uses /usr/bin/env bash"
else
    err "shebang does not use /usr/bin/env bash"
fi

# ---------------------------------------------------------------------------
# 8. claude update falls back to npm update -g
# ---------------------------------------------------------------------------
echo "Test: claude update falls back to npm update"
if grep -q 'claude update 2>/dev/null || npm update -g' "$SCRIPT"; then
    ok "claude update falls back to npm update -g on failure"
else
    err "claude update fallback not found"
fi

# ---------------------------------------------------------------------------
# 9. nvm init is persisted to shell rc (idempotent)
# ---------------------------------------------------------------------------
echo "Test: nvm init persisted to shell rc"
if grep -q 'persist_nvm_in_shell_rc()' "$SCRIPT"; then
    ok "persist_nvm_in_shell_rc function exists"
else
    err "persist_nvm_in_shell_rc function not found"
fi
if grep -q 'export NVM_DIR=' "$SCRIPT" && grep -q 'nvm.sh' "$SCRIPT"; then
    ok "nvm init snippet is present"
else
    err "nvm init snippet not found"
fi

# ---------------------------------------------------------------------------
# 10. Functional test: download_and_verify rejects a bad checksum
# ---------------------------------------------------------------------------
echo "Test: download_and_verify rejects bad checksum"
tmpfile=$(mktemp)
bad_content="this is not the real installer"
printf '%s' "$bad_content" > "$tmpfile"
# Source just the logging + download_and_verify helpers (set -e is active in the
# script, so we extract the functions carefully).
eval "$(sed -n '/^log_info()/,/^}/p; /^log_success()/,/^}/p; /^log_error()/,/^}/p; /^download_and_verify()/,/^}/p' "$SCRIPT")"

# Create a fake URL->file by using a file:// URL won't work with curl -fsSL well,
# so instead test the checksum comparison directly by calling download_and_verify
# with a local file we control via a tiny mock.
mock_url="file://$tmpfile"
if download_and_verify "$mock_url" "deadbeef" "$tmpfile.verify" 2>/dev/null; then
    err "download_and_verify accepted a bad checksum"
else
    ok "download_and_verify rejected a bad checksum"
fi
rm -f "$tmpfile" "$tmpfile.verify"

# ---------------------------------------------------------------------------
# 11. Functional test: download_and_verify accepts a good checksum
# ---------------------------------------------------------------------------
echo "Test: download_and_verify accepts good checksum"
tmpfile2=$(mktemp)
good_content="legit installer content"
printf '%s' "$good_content" > "$tmpfile2"
good_url="file://$tmpfile2"
good_sha=$(shasum -a 256 "$tmpfile2" | awk '{print $1}')
if download_and_verify "$good_url" "$good_sha" "$tmpfile2.verify" 2>/dev/null; then
    ok "download_and_verify accepted a correct checksum"
else
    err "download_and_verify rejected a correct checksum"
fi
rm -f "$tmpfile2" "$tmpfile2.verify"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
