#!/usr/bin/env bash
# scripts/demo/lib.sh — helpers shared by scripts/demo/up.sh (SQLite) and
# scripts/demo/check.sh (--postgres seeds its own stack). Source it, don't run it.
#
# Why this exists: Keyorix ships with security.require_mfa ON (ADR-112), so a
# freshly bootstrapped admin is refused (HTTP 403 MFAEnrollmentRequired) on
# everything but MFA enrolment until it enrols TOTP. up.sh learnt that in #2982;
# check.sh's Postgres seed did not (#3034). Both now call demo_enroll_admin_mfa
# and demo_login_mfa below instead of carrying their own copies.
#
# Everything goes through the public HTTP API (curl) with the secrets on stdin /
# in the process environment only, never as command-line arguments, so no
# "passing --password on the command line is insecure" warnings reach the
# presenter's terminal (#3034 finding 2). The TOTP codes come from
# scripts/totpgen (bin/totpgen), which stands in for an authenticator app.
#
# Contract for the caller: TOTPGEN_BIN must point at the built helper.
# Results are returned in DEMO_* globals (documented per function).

# shellcheck disable=SC2034  # DEMO_MFA_*/DEMO_RECOVERY_CODES/DEMO_TOKEN are read by the sourcing script
DEMO_HTTP_CODE=""
DEMO_BODY=""
DEMO_LAST_TOTP_STEP=0

# demo_json '<python expr over d>' '<json>' — prints the value, '' on any error.
demo_json() {
  python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
    v = $1
    print(v if v is not None else '')
except Exception:
    print('')
" "$2"
}

# demo_api METHOD BASE_URL PATH [TOKEN] [JSON_BODY]
# Sets DEMO_HTTP_CODE / DEMO_BODY. The JSON body is fed on stdin so credentials
# never appear in the curl command line.
demo_api() {
  local method="$1" base="$2" path="$3" token="${4:-}" body="${5:-}"
  local args=(-s --max-time 15 -X "$method" -w '\n%{http_code}' "${base}${path}")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  local out
  if [ -n "$body" ]; then
    out="$(printf '%s' "$body" | curl "${args[@]}" -H "Content-Type: application/json" --data-binary @-)"
  else
    out="$(curl "${args[@]}")"
  fi
  DEMO_HTTP_CODE="${out##*$'\n'}"
  DEMO_BODY="${out%$'\n'*}"
}

# demo_totp_code SECRET — a code for the next unused 30 s step. Every accepted
# code is single-use (anti-replay), so successive logins must each use a later
# step than the previous one; when the next free step is more than one step
# ahead of the clock (the server tolerates one), wait for the clock to catch up.
demo_totp_code() {
  local secret="$1" now step offset
  now=$(date +%s)
  step=$((now / 30))
  [ "$step" -le "$DEMO_LAST_TOTP_STEP" ] && step=$((DEMO_LAST_TOTP_STEP + 1))
  if [ "$step" -gt $((now / 30 + 1)) ]; then
    sleep $(((step - 1) * 30 - now + 1))
    now=$(date +%s)
  fi
  offset=$(((step - now / 30) * 30))
  DEMO_LAST_TOTP_STEP=$step
  "$TOTPGEN_BIN" "$secret" "$offset"
}

# demo_login_mfa BASE_URL USER PASSWORD [TOTP_SECRET]
# Logs in over the API; if the account is challenged for a second factor, answers
# it with TOTP_SECRET. Sets DEMO_TOKEN (empty + non-zero return on failure, with
# the reason on stderr).
demo_login_mfa() {
  local base="$1" user="$2" password="$3" secret="${4:-}" challenge code
  DEMO_TOKEN=""
  demo_api POST "$base" /auth/login "" "$(python3 -c 'import json,sys; print(json.dumps({"username":sys.argv[1],"password":sys.argv[2]}))' "$user" "$password")"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "login ($user) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  if [ "$(demo_json 'd["data"].get("mfa_required")' "$DEMO_BODY")" = "True" ]; then
    [ -n "$secret" ] || { echo "login ($user) needs a second factor but no TOTP secret is known" >&2; return 1; }
    challenge="$(demo_json 'd["data"]["mfa_challenge"]' "$DEMO_BODY")"
    code="$(demo_totp_code "$secret")"
    demo_api POST "$base" /auth/mfa/verify "" "{\"mfa_challenge\":\"$challenge\",\"code\":\"$code\"}"
    [ "$DEMO_HTTP_CODE" = "200" ] || { echo "MFA verify ($user) returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  fi
  DEMO_TOKEN="$(demo_json 'd["data"].get("token","")' "$DEMO_BODY")"
  [ -n "$DEMO_TOKEN" ] || { echo "login ($user) succeeded but returned no token: $DEMO_BODY" >&2; return 1; }
}

# demo_enroll_admin_mfa BASE_URL USER PASSWORD
# Enrols TOTP for a freshly bootstrapped admin (the one-shot login that is still
# allowed before MFA exists), then logs in again with a code. Sets
#   DEMO_MFA_SECRET, DEMO_MFA_URI, DEMO_RECOVERY_CODES (space-separated),
#   DEMO_TOKEN (a full, post-MFA session).
demo_enroll_admin_mfa() {
  local base="$1" user="$2" password="$3" pre_token code
  DEMO_MFA_SECRET="" DEMO_MFA_URI="" DEMO_RECOVERY_CODES=""
  demo_login_mfa "$base" "$user" "$password" || return 1
  pre_token="$DEMO_TOKEN"

  demo_api POST "$base" /api/v1/auth/mfa/enroll "$pre_token" "{}"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "MFA enroll returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  DEMO_MFA_SECRET="$(demo_json 'd["data"]["secret"]' "$DEMO_BODY")"
  DEMO_MFA_URI="$(demo_json 'd["data"]["otpauth_uri"]' "$DEMO_BODY")"
  [ -n "$DEMO_MFA_SECRET" ] && [ -n "$DEMO_MFA_URI" ] || { echo "MFA enroll returned no secret / otpauth URI" >&2; return 1; }

  code="$(demo_totp_code "$DEMO_MFA_SECRET")"
  demo_api POST "$base" /api/v1/auth/mfa/activate "$pre_token" \
    "$(python3 -c 'import json,sys; print(json.dumps({"code":sys.argv[1],"password":sys.argv[2]}))' "$code" "$password")"
  [ "$DEMO_HTTP_CODE" = "200" ] || { echo "MFA activate returned $DEMO_HTTP_CODE: $DEMO_BODY" >&2; return 1; }
  DEMO_RECOVERY_CODES="$(demo_json '" ".join(d["data"].get("recovery_codes") or [])' "$DEMO_BODY")"

  # Activation signs the pre-MFA session out and consumed this 30 s step.
  demo_login_mfa "$base" "$user" "$password" "$DEMO_MFA_SECRET"
}
