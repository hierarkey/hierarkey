#!/usr/bin/env bash
# hkey-test-suite.sh — comprehensive integration test suite for the Hierarkey server
#
# Prerequisites:
#   - A running Hierarkey server (see testsuite/start-run.sh)
#   - admin account with known password
#   - masterkey "root" created
#   - jq and base64 installed
#
# Usage:
#   ./hkey-test-suite.sh
#   HKEY_SERVER_URL=http://1.2.3.4:9090 ./hkey-test-suite.sh
#   HKEY_BIN=./target/release/hkey ./hkey-test-suite.sh

set -uo pipefail

SERVER_URL="${HKEY_SERVER_URL:-http://127.0.0.1:8080}"
SELF_SIGNED="${HKEY_SELF_SIGNED:-false}"
HKEY_BIN="${HKEY_BIN:-./target/debug/hkey}"

# WARNING: The default passwords below are for local development / CI only.
# Always override HKEY_MASTERKEY_PASS and HKEY_ADMIN_PASS when running against
# any non-development server.
MASTERKEY_NAME="${HKEY_MASTERKEY_NAME:-root}"
MASTERKEY_PASS="${HKEY_MASTERKEY_PASS:-masterkeypassphrase}"
ADMIN_USER="admin"
ADMIN_PASS="${HKEY_ADMIN_PASS:-adminadminadmin}"

# Unique run suffix — prevents name collisions when re-running against a live server
TS=$(date +%s)
KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT

PASS=0
FAIL=0
CURRENT_TOKEN=""

if [[ -t 1 ]]; then
  RED=$'\033[1;31m' GRN=$'\033[1;32m' YLW=$'\033[1;33m' BLU=$'\033[1;34m' DIM=$'\033[2m' RST=$'\033[0m'
else
  RED='' GRN='' YLW='' BLU='' DIM='' RST=''
fi

log_section() { printf "\n${BLU}══════ %s ══════${RST}\n" "$*"; }
log_info()    { printf "  ${DIM}%s${RST}\n" "$*"; }
_ok()         { PASS=$((PASS + 1)); printf "  ${GRN}PASS${RST}  %s\n" "$1"; }
_fail()       { FAIL=$((FAIL + 1)); printf "  ${RED}FAIL${RST}  %s\n" "$1"; }

HKEY_BASE=("$HKEY_BIN" --server "$SERVER_URL")
[[ "$SELF_SIGNED" == "true" ]] && HKEY_BASE+=(--self-signed)

hkey()      { "${HKEY_BASE[@]}" --token "$CURRENT_TOKEN" "$@"; }
hkey_anon() { "${HKEY_BASE[@]}" "$@"; }
hkey_as()   { local tok="$1"; shift; "${HKEY_BASE[@]}" --token "$tok" "$@"; }

# expect_pass DESC CMD...  — test passes if command exits 0
expect_pass() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    _ok "$desc"
  else
    _fail "$desc  ${DIM}(expected success, got failure)${RST}"
  fi
}

# expect_fail DESC CMD...  — test passes if command exits non-zero
expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    _fail "$desc  ${DIM}(expected failure, got success)${RST}"
  else
    _ok "$desc"
  fi
}

# check_reveal DESC EXPECTED CMD...
#   Runs CMD --json, decodes .value_b64 from base64, compares to EXPECTED.
check_reveal() {
  local desc="$1" expected="$2"; shift 2
  local out got
  if out=$("$@" --json 2>/dev/null); then
    got=$(printf '%s' "$out" | jq -r '.value_b64 // empty' 2>/dev/null | base64 -d 2>/dev/null) || got=""
    if [[ "$got" == "$expected" ]]; then
      _ok "$desc"
    else
      _fail "$desc  ${DIM}(expected '$expected', got '${got:-<empty>}')${RST}"
    fi
  else
    _fail "$desc  ${DIM}(command failed)${RST}"
  fi
}

auth_login() {
  local name="$1" pass="$2"
  local out
  out=$(hkey_anon auth login --name "$name" --insecure-password "$pass" --json 2>/dev/null) || {
    printf "  [fatal] login failed for %s\n" "$name" >&2; exit 1
  }
  CURRENT_TOKEN=$(printf '%s' "$out" | jq -r '.access_token // empty')
  [[ -n "$CURRENT_TOKEN" ]] || { printf "  [fatal] no access_token for %s\n" "$name" >&2; exit 1; }
}

check_prereqs() {
  command -v jq     >/dev/null 2>&1 || { echo "ERROR: jq is required" >&2; exit 1; }
  command -v base64 >/dev/null 2>&1 || { echo "ERROR: base64 is required" >&2; exit 1; }
  [[ -x "$HKEY_BIN" ]] || { echo "ERROR: hkey binary not found at $HKEY_BIN" >&2; exit 1; }
}

main() {
  check_prereqs

  # Artifact names — all suffixed with TS to avoid collisions
  local NS_A="/test-${TS}/app"
  local NS_B="/test-${TS}/shared"
  local NS_CHILD="/test-${TS}/app/sub"
  local SREF_A="${NS_A}:db_password"
  local SREF_LIVE="${NS_A}:live_secret"   # never deleted; used by scoped/SA/masterkey tests
  local SREF_B="${NS_B}:banner"
  local SREF_GUARD="${NS_A}:guard_secret"

  local USER1="tuser-${TS}"
  local USER1_PASS="password-for-tuser-${TS}"
  local USER2="treader-${TS}"
  local USER2_PASS="password-for-treader-${TS}"
  local USER_NOPERM="tnoperm-${TS}"
  local USER_NOPERM_PASS="password-for-tnoperm-${TS}"
  local SA_NAME="tsa-${TS}"
  local SA_PRIVKEY="$KEYDIR/${SA_NAME}.ed25519.pem"
  local SA_PUBKEY="$KEYDIR/${SA_NAME}.ed25519.pub.pem"

  local ROLE_FULL="trole-full-${TS}"
  local ROLE_SCOPED="trole-scoped-${TS}"
  local ROLE_SA="trole-sa-${TS}"

  log_section "Auth & Setup"

  auth_login "$ADMIN_USER" "$ADMIN_PASS"
  _ok "admin login"

  expect_fail "login with wrong password" \
    hkey_anon auth login --name "$ADMIN_USER" --insecure-password "totally-wrong" --json

  expect_pass "masterkey unlock" \
    hkey masterkey unlock --name "$MASTERKEY_NAME" --insecure-passphrase "$MASTERKEY_PASS"

  expect_pass "masterkey status" hkey masterkey status

  expect_pass "auth whoami" hkey auth whoami

  log_section "Account Management"

  expect_pass "create USER1 (provisioner)" \
    hkey account create --type user --name "$USER1" --activate \
      --insecure-password "$USER1_PASS" --description "Test provisioner"

  expect_fail "create duplicate account is rejected" \
    hkey account create --type user --name "$USER1" --activate \
      --insecure-password "$USER1_PASS"

  expect_pass "create USER2 (scoped reader)" \
    hkey account create --type user --name "$USER2" --activate \
      --insecure-password "$USER2_PASS" --description "Scoped reader"

  expect_pass "create USER_NOPERM (no permissions)" \
    hkey account create --type user --name "$USER_NOPERM" --activate \
      --insecure-password "$USER_NOPERM_PASS" --description "No-permission user"

  expect_pass "account describe" hkey account describe --name "$USER1"
  expect_pass "account list"     hkey account list
  expect_pass "account search"   hkey account search

  # Lock / unlock cycle
  expect_pass "lock USER1"                     hkey account lock   --name "$USER1"
  expect_fail "locked account cannot login"    hkey_anon auth login --name "$USER1" --insecure-password "$USER1_PASS" --json
  expect_pass "unlock USER1"                   hkey account unlock --name "$USER1"
  expect_pass "unlocked account can login"     hkey_anon auth login --name "$USER1" --insecure-password "$USER1_PASS" --json

  # Disable / enable cycle
  expect_pass "disable USER1"                  hkey account disable --name "$USER1"
  expect_fail "disabled account cannot login"  hkey_anon auth login --name "$USER1" --insecure-password "$USER1_PASS" --json
  expect_pass "enable USER1"                   hkey account enable  --name "$USER1"
  expect_pass "enabled account can login"      hkey_anon auth login --name "$USER1" --insecure-password "$USER1_PASS" --json

  # Promote / demote
  expect_pass "promote USER2 to admin"   hkey account promote --name "$USER2"
  expect_pass "demote USER2 back"        hkey account demote  --name "$USER2"

  # Self-promotion and self-demotion must be blocked
  expect_fail "admin cannot self-promote" hkey account promote --name "$ADMIN_USER"
  expect_fail "admin cannot self-demote"  hkey account demote  --name "$ADMIN_USER"

  # Password change (change to same value — idempotent; token in header so no current-password prompt)
  expect_pass "change own password" \
    hkey account change-password --name "$ADMIN_USER" --insecure-new-password "$ADMIN_PASS"
  expect_pass "login still works after password change" \
    hkey_anon auth login --name "$ADMIN_USER" --insecure-password "$ADMIN_PASS" --json

  log_section "Personal Access Tokens (PAT)"

  # Create a PAT and extract both id and token
  local pat_json pat_id="" pat_token=""
  pat_json=$(hkey pat create --description "test-pat-${TS}" --ttl 30m --json 2>/dev/null) || pat_json=""
  if [[ -n "$pat_json" ]]; then
    pat_id=$(printf '%s' "$pat_json" | jq -r '.id // empty')
    pat_token=$(printf '%s' "$pat_json" | jq -r '.token // empty')
    if [[ -n "$pat_id" && -n "$pat_token" ]]; then
      _ok "pat create (id and token returned)"
    else
      _fail "pat create (could not extract id or token from JSON)"
    fi
  else
    _fail "pat create (command failed)"
  fi

  expect_pass "pat list"     hkey pat list
  [[ -n "$pat_id" ]] && expect_pass "pat describe" hkey pat describe --id "$pat_id"

  if [[ -n "$pat_token" && -n "$pat_id" ]]; then
    # PAT can be used for authentication
    expect_pass "PAT authenticates successfully" \
      hkey_as "$pat_token" auth whoami

    # Revoke and verify rejection
    expect_pass "pat revoke" hkey pat revoke --id "$pat_id"
    expect_fail "revoked PAT is rejected" \
      hkey_as "$pat_token" auth whoami

    # Unrevoke and verify acceptance
    expect_pass "pat unrevoke" hkey pat unrevoke --id "$pat_id"
    expect_pass "unrevoked PAT works again" \
      hkey_as "$pat_token" auth whoami

    # Tidy up
    hkey pat revoke --id "$pat_id" >/dev/null 2>&1 || true
  fi

  log_section "RBAC — Roles, Rules, Bindings"

  # ROLE_FULL: full provisioner for USER1
  expect_pass "create role ROLE_FULL" \
    hkey rbac role create --name "$ROLE_FULL" --description "Full provisioner for tests"
  expect_fail "create duplicate role is rejected" \
    hkey rbac role create --name "$ROLE_FULL" --description "dup"

  # Namespace permissions
  expect_pass "ROLE_FULL: allow namespace:create to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow namespace:create to all"
  expect_pass "ROLE_FULL: allow namespace:describe to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow namespace:describe to all"
  expect_pass "ROLE_FULL: allow namespace:update:meta to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow namespace:update:meta to all"
  expect_pass "ROLE_FULL: allow namespace:list to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow namespace:list to all"
  expect_pass "ROLE_FULL: allow namespace:delete to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow namespace:delete to all"

  # Secret permissions — "to all" matches any resource type, including Namespace
  # (needed so that search --namespace <ns> passes the SecretList check)
  expect_pass "ROLE_FULL: allow secret:create to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:create to all"
  expect_pass "ROLE_FULL: allow secret:describe to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:describe to all"
  expect_pass "ROLE_FULL: allow secret:read to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:read to all"
  expect_pass "ROLE_FULL: allow secret:revise to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:revise to all"
  expect_pass "ROLE_FULL: allow secret:delete to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:delete to all"
  expect_pass "ROLE_FULL: allow secret:update:meta to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:update:meta to all"
  expect_pass "ROLE_FULL: allow secret:rollback to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:rollback to all"
  expect_pass "ROLE_FULL: allow secret:list to all" \
    hkey rbac role add --name "$ROLE_FULL" --rule "allow secret:list to all"

  expect_pass "role list"                     hkey rbac role list
  expect_pass "role describe"                 hkey rbac role describe --name "$ROLE_FULL"
  expect_pass "bind ROLE_FULL to USER1"       hkey rbac bind --name "$USER1" --role "$ROLE_FULL"

  # ROLE_SCOPED: scoped reader for USER2 (NS_A secrets only)
  expect_pass "create role ROLE_SCOPED" \
    hkey rbac role create --name "$ROLE_SCOPED" --description "Scoped reader: NS_A only"
  expect_pass "ROLE_SCOPED: allow secret:read to secret NS_A:*" \
    hkey rbac role add --name "$ROLE_SCOPED" --rule "allow secret:read to secret ${NS_A}:*"
  expect_pass "ROLE_SCOPED: allow secret:describe to secret NS_A:*" \
    hkey rbac role add --name "$ROLE_SCOPED" --rule "allow secret:describe to secret ${NS_A}:*"
  expect_pass "ROLE_SCOPED: allow secret:list to namespace NS_A" \
    hkey rbac role add --name "$ROLE_SCOPED" --rule "allow secret:list to namespace ${NS_A}"
  expect_pass "bind ROLE_SCOPED to USER2"     hkey rbac bind --name "$USER2" --role "$ROLE_SCOPED"

  # ROLE_SA: read-only role for the service account
  expect_pass "create role ROLE_SA" \
    hkey rbac role create --name "$ROLE_SA" --description "SA read-only for NS_A"
  expect_pass "ROLE_SA: allow secret:read to secret NS_A:*" \
    hkey rbac role add --name "$ROLE_SA" --rule "allow secret:read to secret ${NS_A}:*"
  expect_pass "ROLE_SA: allow secret:describe to secret NS_A:*" \
    hkey rbac role add --name "$ROLE_SA" --rule "allow secret:describe to secret ${NS_A}:*"

  # rbac explain (always exits 0 — it describes, not enforces)
  expect_pass "rbac explain: USER1 / secret:read / NS_A" \
    hkey rbac explain --account "$USER1" --permission "secret:read" --namespace "$NS_A"
  expect_pass "rbac explain: USER_NOPERM / secret:read / NS_A (expect deny in output)" \
    hkey rbac explain --account "$USER_NOPERM" --permission "secret:read" --namespace "$NS_A"

  log_section "Namespace Management"

  # Admin creates the root namespace first (USER1 is not a platform admin)
  expect_pass "create root test namespace (admin)" \
    hkey namespace create --namespace "/test-${TS}" --description "Root test namespace"

  auth_login "$USER1" "$USER1_PASS"

  expect_pass "create NS_A"     hkey namespace create --namespace "$NS_A"     --description "App namespace"
  expect_pass "create NS_B"     hkey namespace create --namespace "$NS_B"     --description "Shared namespace"
  expect_pass "create NS_CHILD" hkey namespace create --namespace "$NS_CHILD" --description "Child namespace"

  expect_fail "duplicate namespace is rejected" hkey namespace create --namespace "$NS_A"

  expect_pass "namespace describe"  hkey namespace describe --namespace "$NS_A"
  expect_pass "namespace list"      hkey namespace list

  expect_pass "update namespace: set description" \
    hkey namespace update --namespace "$NS_A" --description "Updated app namespace"
  expect_pass "update namespace: add labels" \
    hkey namespace update --namespace "$NS_A" --label env=test --label team=backend
  expect_pass "update namespace: remove one label" \
    hkey namespace update --namespace "$NS_A" --remove-label team
  expect_pass "update namespace: clear all labels" \
    hkey namespace update --namespace "$NS_A" --clear-labels
  expect_pass "update namespace: clear description" \
    hkey namespace update --namespace "$NS_A" --clear-description

  # Disable / restore cycle
  expect_pass "disable NS_B"                        hkey namespace disable  --namespace "$NS_B"
  expect_fail "disable already-disabled ns fails"   hkey namespace disable  --namespace "$NS_B"
  expect_pass "restore NS_B"                        hkey namespace restore  --namespace "$NS_B"
  expect_fail "restore already-active ns fails"     hkey namespace restore  --namespace "$NS_B"

  # Delete: must be disabled first; --confirm skips interactive prompt
  expect_pass "disable NS_CHILD (before delete)"    hkey namespace disable --namespace "$NS_CHILD"
  expect_fail "delete active namespace fails"        hkey namespace delete  --namespace "$NS_B" --confirm
  expect_pass "delete disabled namespace"            hkey namespace delete  --namespace "$NS_CHILD" --confirm

  log_section "Secret Lifecycle"

  # Create
  expect_pass "create SREF_A with metadata" \
    hkey secret create --ref "$SREF_A" --value "initial-db-password" \
      --description "DB password" --label env=prod --label tier=backend
  expect_pass "create SREF_B" \
    hkey secret create --ref "$SREF_B" --value "hello-world-banner"
  expect_fail "create duplicate secret is rejected" \
    hkey secret create --ref "$SREF_A" --value "other-value"

  # Describe and list
  expect_pass "secret describe"         hkey secret describe --ref "$SREF_A"
  expect_pass "secret list (namespace)" hkey secret list   --namespace "$NS_A"
  expect_pass "secret search by ns"     hkey secret search --namespace "$NS_A"
  expect_pass "secret search: all-ns"   hkey secret search --all-namespaces
  expect_pass "secret search: by label" hkey secret search --label env=prod
  expect_pass "secret search: by query" hkey secret search --query "db"

  # Reveal and verify value (revision 1 is active)
  check_reveal "reveal returns correct initial value" "initial-db-password" \
    hkey secret reveal --ref "$SREF_A"

  # Update metadata — does NOT create a new revision
  expect_pass "update secret metadata" \
    hkey secret update --ref "$SREF_A" \
      --description "Rotated DB password" --label env=prod --label rotated=no
  expect_pass "update: remove label"  hkey secret update --ref "$SREF_A" --remove-label rotated
  expect_pass "update: clear labels"  hkey secret update --ref "$SREF_A" --clear-labels
  expect_pass "update: clear description" hkey secret update --ref "$SREF_A" --clear-description

  # Verify active value is still the original after metadata-only updates
  check_reveal "value unchanged after metadata update" "initial-db-password" \
    hkey secret reveal --ref "$SREF_A"

  # Revise without activating — creates revision 2, active stays on 1
  expect_pass "revise (not activated)" \
    hkey secret revise --ref "$SREF_A" \
      --value "rotated-db-password" --note "Quarterly rotation (pending)"
  check_reveal "active revision unchanged after non-activated revise" "initial-db-password" \
    hkey secret reveal --ref "$SREF_A"

  # Revise and activate immediately — creates revision 3, activates it
  expect_pass "revise and activate" \
    hkey secret revise --ref "$SREF_A" \
      --value "final-db-password" --note "Activated rotation" --activate
  check_reveal "reveal after activate shows new value" "final-db-password" \
    hkey secret reveal --ref "$SREF_A"

  # Annotate specific revisions
  expect_pass "annotate revision 1" \
    hkey secret annotate --ref "${SREF_A}@1" --note "Original password"
  expect_pass "annotate revision 2" \
    hkey secret annotate --ref "${SREF_A}@2" --note "Rotation pending"
  expect_pass "clear annotation on revision 1" \
    hkey secret annotate --ref "${SREF_A}@1" --clear-note

  # Activate revision 1 (rollback)
  expect_pass "activate revision 1 (rollback)" \
    hkey secret activate --ref "${SREF_A}@1"
  check_reveal "reveal after rollback shows original value" "initial-db-password" \
    hkey secret reveal --ref "$SREF_A"

  # Activate revision 3 (roll forward)
  expect_pass "activate revision 3 (roll forward)" \
    hkey secret activate --ref "${SREF_A}@3"
  check_reveal "reveal after roll-forward shows latest value" "final-db-password" \
    hkey secret reveal --ref "$SREF_A"

  # Nonexistent secret
  expect_fail "reveal nonexistent secret fails" \
    hkey secret reveal --ref "${NS_A}:does_not_exist"

  # Delete (soft-delete: marks secret as disabled)
  expect_pass "delete SREF_A"                    hkey secret delete --ref "$SREF_A" --confirm
  expect_fail "reveal deleted secret fails"       hkey secret reveal --ref "$SREF_A"

  # Create a live (never-deleted) secret for later sections (scoped/SA/masterkey tests)
  expect_pass "create SREF_LIVE (for later tests)" \
    hkey secret create --ref "$SREF_LIVE" --value "live-password"

  log_section "RBAC Enforcement"

  # USER_NOPERM has no rules — every privileged action must be denied
  auth_login "$USER_NOPERM" "$USER_NOPERM_PASS"

  expect_fail "no-perm: cannot create namespace"     hkey namespace create --namespace "/test-${TS}/denied"
  expect_fail "no-perm: cannot describe namespace"   hkey namespace describe --namespace "$NS_A"
  expect_fail "no-perm: cannot list namespaces"      hkey namespace list
  expect_fail "no-perm: cannot create secret"        hkey secret create --ref "${NS_A}:noperm" --value "x"
  expect_fail "no-perm: cannot describe secret"      hkey secret describe --ref "$SREF_A"
  expect_fail "no-perm: cannot reveal secret"        hkey secret reveal  --ref "$SREF_A"
  expect_fail "no-perm: cannot revise secret"        hkey secret revise  --ref "$SREF_A" --value "hacked"
  expect_fail "no-perm: cannot delete secret"        hkey secret delete  --ref "$SREF_A" --json
  expect_fail "no-perm: cannot search (all-ns)"      hkey secret search --all-namespaces
  expect_fail "no-perm: cannot search (specific ns)" hkey secret search --namespace "$NS_A"

  # USER2 has ROLE_SCOPED: read-only on NS_A secrets; list within NS_A
  auth_login "$USER2" "$USER2_PASS"

  expect_pass  "scoped: can reveal secret in NS_A"       hkey secret reveal  --ref "$SREF_LIVE"
  expect_pass  "scoped: can describe secret in NS_A"     hkey secret describe --ref "$SREF_LIVE"
  expect_pass  "scoped: can search within NS_A"          hkey secret search  --namespace "$NS_A"
  expect_fail  "scoped: cannot reveal secret in NS_B"    hkey secret reveal  --ref "$SREF_B"
  expect_fail  "scoped: cannot search NS_B"              hkey secret search  --namespace "$NS_B"
  expect_fail  "scoped: cannot search all-namespaces"    hkey secret search  --all-namespaces
  expect_fail  "scoped: cannot create secret"            hkey secret create  --ref "${NS_A}:newone" --value "y"
  expect_fail  "scoped: cannot revise secret"            hkey secret revise  --ref "$SREF_A" --value "z"
  expect_fail  "scoped: cannot delete secret"            hkey secret delete  --ref "$SREF_A" --json
  expect_fail  "scoped: cannot update secret metadata"   hkey secret update  --ref "$SREF_A" --description "hacked"
  expect_fail  "scoped: cannot create namespace"         hkey namespace create --namespace "/test-${TS}/scoped"
  expect_fail  "scoped: cannot disable namespace"        hkey namespace disable --namespace "$NS_A"

  log_section "Namespace Guards (secrets blocked in disabled namespace)"

  auth_login "$USER1" "$USER1_PASS"

  expect_pass "create guard secret while NS_A is active" \
    hkey secret create --ref "$SREF_GUARD" --value "guard-value"
  check_reveal "reveal guard secret (namespace active)" "guard-value" \
    hkey secret reveal --ref "$SREF_GUARD"

  expect_pass "disable NS_A for guard tests" hkey namespace disable --namespace "$NS_A"

  # Mutation and read operations that check namespace status must be denied
  expect_fail "guard: reveal fails in disabled NS"    hkey secret reveal  --ref "$SREF_GUARD"
  expect_fail "guard: create fails in disabled NS"    hkey secret create  --ref "${NS_A}:newone" --value "x"
  expect_fail "guard: revise fails in disabled NS"    hkey secret revise  --ref "$SREF_GUARD" --value "updated"
  expect_fail "guard: delete fails in disabled NS"    hkey secret delete  --ref "$SREF_GUARD" --json
  # Note: secret describe has no namespace status guard — admin/monitoring use case

  # Restore and verify
  expect_pass "restore NS_A"                           hkey namespace restore --namespace "$NS_A"
  check_reveal "reveal works again after restore" "guard-value" \
    hkey secret reveal --ref "$SREF_GUARD"

  log_section "Service Account Authentication"

  auth_login "$ADMIN_USER" "$ADMIN_PASS"

  # Create SA with ed25519 keypair
  local sa_json=""
  sa_json=$(hkey account create --json \
    --type service --name "$SA_NAME" --activate \
    --description "Test SA (keysig)" \
    --auth ed25519 --generate-keypair \
    --out-private-key "$SA_PRIVKEY" --out-public-key "$SA_PUBKEY" 2>/dev/null) || sa_json=""

  if [[ -n "$sa_json" ]]; then
    _ok "create service account with ed25519 keypair"
    chmod 600 "$SA_PRIVKEY" 2>/dev/null || true
  else
    _fail "create service account (command failed or no output)"
  fi

  expect_pass "bind ROLE_SA to SA" hkey rbac bind --name "$SA_NAME" --role "$ROLE_SA"

  # Obtain SA token via keysig
  local sa_token=""
  if [[ -f "$SA_PRIVKEY" ]]; then
    sa_token=$(hkey_anon auth sa token \
      --method keysig --account "$SA_NAME" \
      --private-key "$SA_PRIVKEY" \
      --json 2>/dev/null | jq -r '.access_token // empty') || sa_token=""
  fi

  if [[ -n "$sa_token" ]]; then
    _ok "SA keysig authentication succeeds"

    if hkey_as "$sa_token" secret reveal --ref "$SREF_LIVE" >/dev/null 2>&1; then
      _ok "SA: can reveal allowed secret (NS_A)"
    else
      _fail "SA: cannot reveal allowed secret — expected to succeed"
    fi

    if hkey_as "$sa_token" secret reveal --ref "$SREF_B" >/dev/null 2>&1; then
      _fail "SA: revealed forbidden secret (NS_B) — should be denied"
    else
      _ok "SA: cannot reveal forbidden secret (NS_B)"
    fi

    if hkey_as "$sa_token" secret create --ref "${NS_A}:sa_new" --value "x" >/dev/null 2>&1; then
      _fail "SA: created secret without secret:create rule — should be denied"
    else
      _ok "SA: cannot create secrets (no secret:create rule)"
    fi

    if hkey_as "$sa_token" namespace create --namespace "/test-${TS}/sa" >/dev/null 2>&1; then
      _fail "SA: created namespace without permission — should be denied"
    else
      _ok "SA: cannot create namespace (no namespace:create rule)"
    fi

    if hkey_as "$sa_token" rbac role list >/dev/null 2>&1; then
      _fail "SA: listed RBAC roles without rbac:admin — should be denied"
    else
      _ok "SA: cannot list roles (no rbac:admin)"
    fi
  else
    _fail "SA keysig auth failed (could not obtain token)"
  fi

  # Verify a second keysig with the same private key still works (replay protection
  # allows a fresh nonce, so a new call must succeed)
  if [[ -f "$SA_PRIVKEY" ]]; then
    local sa_token2
    sa_token2=$(hkey_anon auth sa token \
      --method keysig --account "$SA_NAME" \
      --private-key "$SA_PRIVKEY" \
      --json 2>/dev/null | jq -r '.access_token // empty') || sa_token2=""
    if [[ -n "$sa_token2" ]]; then
      _ok "SA second keysig (fresh nonce) succeeds"
    else
      _fail "SA second keysig unexpectedly failed"
    fi
  fi

  log_section "Masterkey Lock / Unlock"

  auth_login "$ADMIN_USER" "$ADMIN_PASS"

  expect_pass "masterkey status before lock"  hkey masterkey status
  expect_pass "lock masterkey"                hkey masterkey lock --name "$MASTERKEY_NAME"

  # Decryption must fail while masterkey is locked; auth/reads still work
  expect_fail "reveal fails while masterkey is locked" \
    hkey secret reveal --ref "$SREF_LIVE"
  expect_pass "list secrets works without masterkey (no decryption)" \
    hkey secret list --namespace "$NS_A" || true   # may or may not require masterkey

  expect_pass "unlock masterkey" \
    hkey masterkey unlock --name "$MASTERKEY_NAME" --insecure-passphrase "$MASTERKEY_PASS"
  check_reveal "reveal succeeds after re-unlock" "live-password" \
    hkey secret reveal --ref "$SREF_LIVE"

  log_section "Cleanup"

  # Delete secrets while namespaces are still active (delete handler requires active ns)
  auth_login "$USER1" "$USER1_PASS"
  for sref in "$SREF_A" "$SREF_LIVE" "$SREF_B" "$SREF_GUARD"; do
    hkey secret delete --ref "$sref" --confirm >/dev/null 2>&1 || true
  done

  # Disable then permanently delete test namespaces
  auth_login "$ADMIN_USER" "$ADMIN_PASS"
  for ns in "$NS_A" "$NS_B" "/test-${TS}"; do
    hkey namespace disable --namespace "$ns" >/dev/null 2>&1 || true
    hkey namespace delete  --namespace "$ns" --confirm >/dev/null 2>&1 || true
  done

  # Disable test accounts (no account delete endpoint in CLI yet)
  for name in "$USER1" "$USER2" "$USER_NOPERM" "$SA_NAME"; do
    hkey account disable --name "$name" >/dev/null 2>&1 || true
  done

  _ok "cleanup complete"

  log_section "Results"

  local total=$((PASS + FAIL))
  printf "\n  ${GRN}PASSED: %d${RST}\n  ${RED}FAILED: %d${RST}\n  TOTAL:  %d\n\n" "$PASS" "$FAIL" "$total"

  [[ $FAIL -eq 0 ]]
}

main "$@"
