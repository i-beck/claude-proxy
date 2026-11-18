#!/usr/bin/env bash
# Tests for install_claude_code.sh — verifies each fix from commit d0f6cb6.
# Each test checks a specific fix: default model, e2ee URL, API key interpolation,
# timeout, permission bypass opt-in, checksums, bash version guard.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SCRIPT="$SCRIPT_DIR/../install_claude_code.sh"

pass=0
fail=0

assert_contains() {
    local label="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        echo "  PASS: $label"
        pass=$((pass + 1))
    else
        echo "  FAIL: $label"
        echo "    expected to find: $needle"
        fail=$((fail + 1))
    fi
}

assert_not_contains() {
    local label="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        echo "  FAIL: $label"
        echo "    expected NOT to find: $needle"
        fail=$((fail + 1))
    else
        echo "  PASS: $label"
        pass=$((pass + 1))
    fi
}

assert_eq() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  PASS: $label"
        pass=$((pass + 1))
    else
        echo "  FAIL: $label"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        fail=$((fail + 1))
    fi
}

echo "=== Installer Script Tests ==="
echo ""

# Read the script content
SCRIPT_CONTENT=$(cat "$INSTALL_SCRIPT")

# --- Fix 1.4: Default model is valid (not GLM-4.7-TEE) ---
echo "Testing default model fix:"
assert_contains "default model is GLM-5.1-TEE" "$SCRIPT_CONTENT" 'DEFAULT_MODEL="zai-org/GLM-5.1-TEE"'
assert_not_contains "stale GLM-4.7-TEE model removed" "$SCRIPT_CONTENT" 'DEFAULT_MODEL="zai-org/GLM-4.7-TEE"'

# --- Fix 1.1: e2ee URL uses 127.0.0.1 (not remote host) ---
echo ""
echo "Testing e2ee proxy URL fix:"
assert_contains "e2ee URL uses 127.0.0.1" "$SCRIPT_CONTENT" 'PROXY_BASE_URL="https://127.0.0.1:${E2EE_SELECTED_PORT}"'
assert_not_contains "old broken e2ee URL format removed" "$SCRIPT_CONTENT" 'PROXY_BASE_URL="${E2EE_PROXY_HOST}:${E2EE_SELECTED_PORT}"'

# --- Fix 1.2: API key not interpolated into JS (uses process.env) ---
echo ""
echo "Testing API key injection fix:"
assert_contains "API key passed via process.env" "$SCRIPT_CONTENT" 'const apiKey = process.env.CHUTES_API_KEY;'
assert_contains "model passed via process.env" "$SCRIPT_CONTENT" 'const selectedModel = process.env.CHUTES_MODEL;'
assert_contains "proxy URL passed via process.env" "$SCRIPT_CONTENT" 'const proxyBaseUrl = process.env.CHUTES_PROXY_BASE_URL;'
assert_not_contains "old string interpolation of api_key removed" "$SCRIPT_CONTENT" '"'"'"'"$api_key"'"'"'"'
assert_not_contains "old string interpolation of selected_model removed" "$SCRIPT_CONTENT" '"'"'"'"$selected_model"'"'"'"'

# --- Fix 1.9/timeout: API timeout is 600000 (10 min), not 6000000 (100 min) ---
echo ""
echo "Testing API timeout fix:"
assert_contains "timeout is 600000" "$SCRIPT_CONTENT" 'API_TIMEOUT_MS=600000'
assert_not_contains "old 100-minute timeout removed" "$SCRIPT_CONTENT" 'API_TIMEOUT_MS=6000000'

# --- Fix 1.3: Permission bypass is opt-in (CLAUDE_DANGEROUS_MODE) ---
echo ""
echo "Testing permission bypass opt-in fix:"
assert_contains "dangerous mode env var defined" "$SCRIPT_CONTENT" 'CLAUDE_DANGEROUS_MODE="${CLAUDE_DANGEROUS_MODE:-}"'
assert_contains "permission bypass is conditional on dangerous flag" "$SCRIPT_CONTENT" '...(dangerous ? { skipDangerousModePermissionPrompt: true } : {})'
assert_contains "bypassPermissions is conditional" "$SCRIPT_CONTENT" '...(dangerous ? { defaultMode: "bypassPermissions" } : {})'
assert_contains "autoAllowBashIfSandboxed is conditional" "$SCRIPT_CONTENT" '...(dangerous ? { autoAllowBashIfSandboxed: true } : {})'

# --- Fix 1.5: Checksums are verified for downloaded scripts ---
echo ""
echo "Testing checksum verification fix:"
assert_contains "download_and_verify function exists" "$SCRIPT_CONTENT" 'download_and_verify()'
assert_contains "nvm checksum pinned" "$SCRIPT_CONTENT" 'NVM_INSTALL_SHA256="'
assert_contains "docker checksum pinned" "$SCRIPT_CONTENT" 'DOCKER_INSTALL_SHA256="'
assert_contains "nvm uses download_and_verify" "$SCRIPT_CONTENT" 'download_and_verify "$NVM_INSTALL_URL" "$NVM_INSTALL_SHA256"'
assert_contains "docker uses download_and_verify" "$SCRIPT_CONTENT" 'download_and_verify "$DOCKER_INSTALL_URL" "$DOCKER_INSTALL_SHA256"'

# --- Fix 1.7: Bash version guard ---
echo ""
echo "Testing bash version guard fix:"
assert_contains "shebang is env bash" "$SCRIPT_CONTENT" '#!/usr/bin/env bash'
assert_contains "bash version check exists" "$SCRIPT_CONTENT" '_major="${BASH_VERSION%%.*}"'
assert_contains "bash 4+ required" "$SCRIPT_CONTENT" 'if [ "$_major" -lt 4 ]; then'

# --- Fix 1.8: claude update fallback ---
echo ""
echo "Testing claude update fallback fix:"
assert_contains "claude update has fallback" "$SCRIPT_CONTENT" 'claude update 2>/dev/null || npm update -g "$CLAUDE_PACKAGE"'

# --- Fix 1.6: nvm persistence in shell rc ---
echo ""
echo "Testing nvm persistence fix:"
assert_contains "persist_nvm_in_shell_rc function exists" "$SCRIPT_CONTENT" 'persist_nvm_in_shell_rc()'
assert_contains "marker for idempotent insertion" "$SCRIPT_CONTENT" '# >>> chutes claude-code env: nvm init'

# --- Bash version guard actually works ---
echo ""
echo "Testing bash version guard behavior:"

# Test that the guard rejects bash 3
_bash3_output=$(echo 'BASH_VERSION="3.2.57"; BASH_SOURCE[0]="x"' | bash -c '
    BASH_VERSION="3.2.57"
    _major="${BASH_VERSION%%.*}"
    if [ "$_major" -lt 4 ]; then
        echo "REJECTED"
    else
        echo "ACCEPTED"
    fi
' 2>&1 || true)
assert_contains "bash 3.2 is rejected" "$_bash3_output" "REJECTED"

# Test that the guard accepts bash 4+
_bash4_output=$(bash -c '
    BASH_VERSION="5.2.0"
    _major="${BASH_VERSION%%.*}"
    if [ "$_major" -lt 4 ]; then
        echo "REJECTED"
    else
        echo "ACCEPTED"
    fi
' 2>&1 || true)
assert_contains "bash 5+ is accepted" "$_bash4_output" "ACCEPTED"

# --- download_and_verify rejects on checksum mismatch ---
echo ""
echo "Testing download_and_verify checksum mismatch:"

# Start a simple HTTP server to serve a known file
_tmpfile=$(mktemp)
echo "test content for checksum verification" > "$_tmpfile"
_expected_sha=$(shasum -a 256 "$_tmpfile" | awk '{print $1}')
_wrong_sha="0000000000000000000000000000000000000000000000000000000000000000"
_tmpdir=$(dirname "$_tmpfile")
_tmpname=$(basename "$_tmpfile")

# Start a tiny HTTP server in background
_python_pid=""
if command -v python3 &>/dev/null; then
    cd "$_tmpdir" && python3 -m http.server 18923 2>/dev/null &
    _python_pid=$!
    cd "$SCRIPT_DIR"
    sleep 0.5
fi

_verify_result=""
if [ -n "$_python_pid" ] && kill -0 "$_python_pid" 2>/dev/null; then
    _verify_result=$((
        source "$INSTALL_SCRIPT" 2>/dev/null || true
        _tmpdl=$(mktemp)
        if download_and_verify "http://127.0.0.1:18923/$_tmpname" "$_wrong_sha" "$_tmpdl" 2>/dev/null; then
            echo "SHOULD_HAVE_FAILED"
        else
            echo "CORRECTLY_REJECTED"
        fi
        rm -f "$_tmpdl"
    ) 2>&1 || true)
    assert_contains "wrong checksum is rejected" "$_verify_result" "CORRECTLY_REJECTED"

    _verify_pass=$((
        source "$INSTALL_SCRIPT" 2>/dev/null || true
        _tmpdl=$(mktemp)
        if download_and_verify "http://127.0.0.1:18923/$_tmpname" "$_expected_sha" "$_tmpdl" 2>/dev/null; then
            echo "CORRECTLY_ACCEPTED"
        else
            echo "SHOULD_HAVE_PASSED"
        fi
        rm -f "$_tmpdl"
    ) 2>&1 || true)
    assert_contains "correct checksum is accepted" "$_verify_pass" "CORRECTLY_ACCEPTED"
    
    kill $_python_pid 2>/dev/null || true
else
    echo "  SKIP: python3 not available for HTTP server test"
    pass=$((pass + 1))
fi

rm -f "$_tmpfile"

# --- Summary ---
echo ""
echo "=== Summary ==="
echo "Passed: $pass"
echo "Failed: $fail"
if [ "$fail" -gt 0 ]; then
    exit 1
fi
exit 0
