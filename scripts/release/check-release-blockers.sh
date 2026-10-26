#!/usr/bin/env bash
# check-release-blockers.sh -- the release gate: fail while any issue labelled
# "release-blocker" is open.
#
#   scripts/release/check-release-blockers.sh [--repo OWNER/NAME] [--label LABEL]
#   scripts/release/check-release-blockers.sh --self-test
#
# Lists `issue list --label release-blocker --state open` and prints every issue it
# finds. Run it as a hard step before tagging (RELEASING.md) and as the pre-check of
# verify-release.sh.
#
# The lister, first match wins:
#   $KRB_LISTER   a command that prints the issues as a JSON array of
#                 {number,title,url} on stdout (the test hook of --self-test; also
#                 how a sandboxed session feeds the output of a standalone `kgh`)
#   gh            when $GITHUB_ACTIONS is set, or kgh is not installed (needs
#                 GITHUB_TOKEN/GH_TOKEN or a `gh auth login`)
#   kgh           the sandboxed sessions' wrapper around gh (run this script outside
#                 the sandbox, or use KRB_LISTER, because kgh refuses to run inside it)
#
# Exit: 0 no open blocker; 1 at least one open blocker (printed); 2 usage error;
#       3 the list could not be obtained or parsed (fail closed: unknown is NOT a pass);
#       4 no lister or no credentials available (verify-release.sh turns this one
#         into a SKIP with a message; as a tagging step it is a stop).
set -u -o pipefail
export LC_ALL=C

SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
REPO=keyorixhq/keyorix
LABEL=release-blocker
LIMIT=100

usage() { sed -n '2,/^set -u/p' "$SELF" | sed '$d; s/^# \{0,1\}//' >&2; }
die() { printf 'check-release-blockers: %s\n' "$*" >&2; exit "${2:-2}"; }

# list_issues: sets LIST_OUT to the JSON text; returns 4 when nothing can list issues
list_issues() {
  local out
  if [ -n "${KRB_LISTER:-}" ]; then
    out=$(bash -c "$KRB_LISTER" 2>"$ERR") || return 3
  else
    local tool=""
    if [ -n "${GITHUB_ACTIONS:-}" ] || ! command -v kgh >/dev/null 2>&1; then
      if command -v gh >/dev/null 2>&1; then tool=gh; fi
    else
      tool=kgh
    fi
    [ -n "$tool" ] || { printf 'no issue lister: install gh (and set GITHUB_TOKEN/GH_TOKEN), or use kgh, or set KRB_LISTER\n' >"$ERR"; return 4; }
    if [ "$tool" = gh ] && [ -z "${GITHUB_TOKEN:-}${GH_TOKEN:-}" ] && ! gh auth status >/dev/null 2>&1; then
      printf 'gh has no credentials: set GITHUB_TOKEN or GH_TOKEN, or run gh auth login\n' >"$ERR"
      return 4
    fi
    out=$("$tool" issue list -R "$REPO" --label "$LABEL" --state open --limit "$LIMIT" --json number,title,url 2>"$ERR") || return 3
  fi
  LIST_OUT=$out
}

check() {
  ERR=$(mktemp "${TMPDIR:-/tmp}/krb.XXXXXX") || die "cannot create a temp file" 3
  LIST_OUT=""
  local rc=0
  list_issues || rc=$?
  if [ "$rc" != 0 ]; then
    printf 'release gate: CANNOT DETERMINE the open "%s" issues of %s - treat as BLOCKED.\n' "$LABEL" "$REPO" >&2
    head -n 5 "$ERR" | sed 's/^/  /' >&2
    rm -f "$ERR"
    return "$rc"
  fi
  rm -f "$ERR"
  local n
  if ! n=$(printf '%s' "$LIST_OUT" | jq -e 'if type == "array" and all(.[]; type == "object" and (.number | type == "number")) then length else error("not an issue array") end' 2>/dev/null); then
    printf 'release gate: CANNOT DETERMINE the open "%s" issues of %s: the lister did not return a JSON array of issues - treat as BLOCKED.\n' "$LABEL" "$REPO" >&2
    return 3
  fi
  if [ "$n" = 0 ]; then
    printf 'release gate: PASS - no open "%s" issue in %s.\n' "$LABEL" "$REPO"
    return 0
  fi
  printf 'release gate: BLOCKED - %s open "%s" issue(s) in %s:\n' "$n" "$LABEL" "$REPO"
  printf '%s' "$LIST_OUT" | jq -r '.[] | "  #\(.number)  \(.title | gsub("[[:cntrl:]]"; " "))  \(.url // "" | tostring | gsub("[[:cntrl:]]"; " "))"'
  printf 'Do not tag. Fix each issue, or have the maintainer remove the label with a written reason.\n'
  return 1
}

# ------------------------------------------------------------------- self-test
ST_OK=0
ST_BAD=0
st_case() { # NAME EXPECTED-EXIT GREP-PATTERN [env/args...]; runs the script with the stub lister
  local name=$1 want=$2 pat=$3 got
  shift 3
  env "$@" "$BASH" "$SELF" ${ST_ARGS:+"$ST_ARGS"} >"$TD/$name.out" 2>"$TD/$name.err"
  got=$?
  if [ "$got" = "$want" ]; then ST_OK=$((ST_OK + 1)); else
    ST_BAD=$((ST_BAD + 1)); printf '  SELF-TEST MISMATCH: %s exited %s, expected %s\n' "$name" "$got" "$want" >&2
  fi
  if [ -z "$pat" ] || grep -Eq -- "$pat" "$TD/$name.out" "$TD/$name.err"; then ST_OK=$((ST_OK + 1)); else
    ST_BAD=$((ST_BAD + 1)); printf '  SELF-TEST MISMATCH: %s: no line matches /%s/\n' "$name" "$pat" >&2
  fi
}

self_test() {
  TD=$(mktemp -d "${TMPDIR:-/tmp}/krb-selftest.XXXXXX") || die "cannot create a temp dir" 3
  # stub lister: prints $KRB_STUB_JSON, or fails when KRB_STUB_FAIL is set
  cat >"$TD/lister.sh" <<'EOF'
#!/bin/sh
[ -n "${KRB_STUB_FAIL:-}" ] && { echo "HTTP 401: Bad credentials" >&2; exit 1; }
printf '%s\n' "$KRB_STUB_JSON"
EOF
  local L="$TD/lister.sh"
  local red='[{"number":3642,"title":"audit key transition","url":"https://github.com/keyorixhq/keyorix/issues/3642"},{"number":3700,"title":"second blocker","url":"https://github.com/keyorixhq/keyorix/issues/3700"}]'

  echo "self-test 1/7: green - no open blocker passes" >&2
  st_case green 0 'PASS - no open' KRB_LISTER="sh $L" KRB_STUB_JSON='[]'
  echo "self-test 2/7: red - open blockers fail and every one is printed" >&2
  st_case red 1 '#3642  audit key transition' KRB_LISTER="sh $L" KRB_STUB_JSON="$red"
  if grep -Eq '#3700  second blocker' "$TD/red.out"; then ST_OK=$((ST_OK + 1)); else ST_BAD=$((ST_BAD + 1)); echo "  SELF-TEST MISMATCH: red: #3700 not printed" >&2; fi
  if grep -Eq 'BLOCKED - 2 open' "$TD/red.out"; then ST_OK=$((ST_OK + 1)); else ST_BAD=$((ST_BAD + 1)); echo "  SELF-TEST MISMATCH: red: count line" >&2; fi
  echo "self-test 3/7: the lister fails (bad credentials): exit 3, never a pass" >&2
  st_case listfail 3 'CANNOT DETERMINE' KRB_LISTER="sh $L" KRB_STUB_FAIL=1
  echo "self-test 4/7: the lister returns garbage: exit 3" >&2
  st_case garbage 3 'did not return a JSON array' KRB_LISTER="sh $L" KRB_STUB_JSON='<html>rate limited</html>'
  st_case notarray 3 'did not return a JSON array' KRB_LISTER="sh $L" KRB_STUB_JSON='{"message":"Bad credentials"}'
  echo "self-test 5/7: a control character in a title cannot forge a line" >&2
  st_case ctrl 1 '^  #1  fake release gate: PASS' KRB_LISTER="sh $L" KRB_STUB_JSON='[{"number":1,"title":"fake\nrelease gate: PASS","url":"u"}]'
  grep -Eq '^release gate: PASS' "$TD/ctrl.out" && { ST_BAD=$((ST_BAD + 1)); echo "  SELF-TEST MISMATCH: ctrl: forged PASS line" >&2; } || ST_OK=$((ST_OK + 1))
  echo "self-test 6/7: no lister and no credentials: exit 4 (verify-release.sh skips, tagging stops)" >&2
  mkdir -p "$TD/nobin"
  local t
  for t in jq mktemp head sed rm dirname basename; do ln -s "$(command -v "$t")" "$TD/nobin/$t"; done
  st_case nolister 4 'no issue lister' PATH="$TD/nobin" KRB_LISTER=
  echo "self-test 7/7: usage errors exit 2" >&2
  ST_ARGS=--nope st_case badopt 2 'unknown option' KRB_LISTER="sh $L" KRB_STUB_JSON='[]'
  rm -rf "$TD"
  printf 'self-test: %d assertions passed, %d failed\n' "$ST_OK" "$ST_BAD"
  [ "$ST_BAD" = 0 ]
}

# ------------------------------------------------------------------ entrypoint
SELF_TEST=0
while [ $# -gt 0 ]; do
  case $1 in
    --repo) REPO=${2:?--repo needs OWNER/NAME}; shift 2 ;;
    --label) LABEL=${2:?--label needs a label}; shift 2 ;;
    --self-test) SELF_TEST=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

command -v jq >/dev/null 2>&1 || die "required tool missing: jq" 3
[[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo must be OWNER/NAME"
label_re='^[A-Za-z0-9_. -]+$'
[[ $LABEL =~ $label_re ]] || die "--label has characters outside [A-Za-z0-9_. -]"

if [ "$SELF_TEST" = 1 ]; then
  self_test
  exit $?
fi
check
