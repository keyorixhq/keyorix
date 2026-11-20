#!/usr/bin/env bash
# rc-gate.sh -- the release-candidate gate: one command that proves a RELEASED candidate can be
# upgraded to from the previous release and rolled back by restore, on SQLite and PostgreSQL.
#
#   scripts/release/rc-gate.sh [options] CANDIDATE-TAG [PREVIOUS-TAG]     e.g. v0.97.0-rc.1
#   scripts/release/rc-gate.sh --check-result FILE [--allow-skip] [CANDIDATE-TAG]
#
# What it does, in this order (it stops before the drills if a step before them fails):
#   1. download     both tags' host-platform server and CLI binaries and checksums.txt (+ .sig/.pem),
#                   and every other asset of the candidate (verify-release.sh wants the full set),
#                   into OUT/<tag>/. A file already there is reused, never trusted: step 2 and 3
#                   hash it. --refresh downloads again.
#   2. verify-release   scripts/release/verify-release.sh against the candidate with --assets-dir.
#   3. previous.checksum  the previous server and CLI binaries hashed against the previous
#                   checksums.txt (the signature of the previous release is NOT checked here).
#   4. four drill legs with DRILL_OLD_SERVER_BIN = previous release server, DRILL_SERVER_BIN and
#      DRILL_CLI_BIN = the candidate's release binaries:
#        upgrade.sqlite  upgrade.postgres        scripts/drills/upgrade.sh (downgrade probe and
#                                                restore-as-rollback included)
#        backup-restore.sqlite  backup-restore.postgres   scripts/drills/backup-restore.sh
#
# Output: one "PASS|FAIL|SKIP  <leg>  <detail>" line per leg on stdout, progress on stderr, and the
# same legs as TSV in OUT/rc-gate-result.tsv (comment lines start with #; columns leg, status,
# detail). Every drill log is OUT/legs/<leg>.log.
#
# Exit: 0 no FAIL (and, with --strict, no SKIP either), 1 at least one FAIL, 2 no FAIL but a SKIP
# under --strict, 3 usage or missing tool. A SKIP always names its reason in the detail column.
# --check-result re-reads a TSV and exits 0 only if it names every leg, has no FAIL and no SKIP
# (--allow-skip tolerates SKIP): that is what the release checklist asks for before a final tag.
#
# PostgreSQL legs need RC_GATE_PG_DSN_DIR: a directory holding dsn1.txt .. dsn4.txt, each a
# postgres://user:password@host:port/db URL of its own EMPTY database (the drills never create or
# drop a database; `kpg dsn <name>` or CREATE DATABASE, one per file). upgrade uses dsn1,
# backup-restore uses dsn2 (source), dsn3 (restore target) and dsn4 (tamper leg; without it that
# leg says SKIP inside the drill). Without the directory the PostgreSQL legs are SKIP.
#
# --cli-bin FILE (RC_GATE_CLI_BIN): drive the drills with this CLI instead of the candidate's own
# release CLI. Needed only when the candidate is OLDER than the drills in this checkout (the drills
# pass the password through KEYORIX_PASSWORD, which the v0.96.3 CLI does not read). The servers stay
# the released binaries. The result records `# cli-override` and --check-result refuses it.
#
# Environment: RC_GATE_PG_DSN_DIR, RC_GATE_PLATFORM (default: this host, e.g. linux_amd64),
# RC_GATE_VERIFY_ARGS (extra verify-release.sh arguments, e.g. "--skip-images --skip-charts"),
# RC_GATE_REPO (default keyorixhq/keyorix), GITHUB_TOKEN (API rate limit only), RC_GATE_CURL_TIMEOUT
# (seconds per download). Test hooks used by rc-gate-selftest.sh: RC_GATE_ASSET_BASE (a directory
# laid out <base>/<tag>/<asset>, or an https base URL), RC_GATE_RELEASES_JSON, RC_GATE_VERIFY_SCRIPT,
# RC_GATE_DRILLS_DIR.
set -u -o pipefail
export LC_ALL=C

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SELF_DIR/../.." && pwd)
REPO=${RC_GATE_REPO:-keyorixhq/keyorix}
VERIFY=${RC_GATE_VERIFY_SCRIPT:-$SELF_DIR/verify-release.sh}
DRILLS=${RC_GATE_DRILLS_DIR:-$REPO_ROOT/scripts/drills}
ASSET_BASE=${RC_GATE_ASSET_BASE:-https://github.com/$REPO/releases/download}
API_BASE=${RC_GATE_API_BASE:-https://api.github.com}
CURL_TIMEOUT=${RC_GATE_CURL_TIMEOUT:-900}

REFRESH=0
CLI_OVERRIDE=${RC_GATE_CLI_BIN:-}
STRICT=0
ALLOW_SKIP=0
OUT=""
TSV=""
CAND=""
PREV=""
CHECK_FILE=""
N_PASS=0
N_FAIL=0
N_SKIP=0
GATE_BLOCK=""

usage() {
  sed -n '2,/^set -u/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

log() { printf '%s\n' "$*" >&2; }
die() { printf 'rc-gate: %s\n' "$*" >&2; exit 3; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- result lines
emit() { # LEG STATUS DETAIL
  local detail
  detail=$(printf '%s' "$3" | tr '\t\n' '  ')
  case $2 in
    PASS) N_PASS=$((N_PASS + 1)) ;;
    FAIL) N_FAIL=$((N_FAIL + 1)) ;;
    SKIP) N_SKIP=$((N_SKIP + 1)) ;;
  esac
  printf '%-4s  %-26s %s\n' "$2" "$1" "$detail"
  printf '%s\t%s\t%s\n' "$1" "$2" "$detail" >>"$TSV"
}

# ------------------------------------------------------------------- platform
host_platform() {
  local os arch
  if [ -n "${RC_GATE_PLATFORM:-}" ]; then printf '%s\n' "$RC_GATE_PLATFORM"; return; fi
  case $(uname -s) in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) return 1 ;;
  esac
  case $(uname -m) in
    arm64 | aarch64) arch=arm64 ;;
    x86_64 | amd64) arch=amd64 ;;
    *) return 1 ;;
  esac
  printf '%s_%s\n' "$os" "$arch"
}

sha256_of() { # FILE -> hex
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ------------------------------------------------------------- previous release
# semver_lt A B: both X.Y.Z (no v, no pre-release); true if A < B
semver_lt() {
  local a1 a2 a3 b1 b2 b3
  IFS=. read -r a1 a2 a3 <<<"$1"
  IFS=. read -r b1 b2 b3 <<<"$2"
  [ "$a1" -lt "$b1" ] && return 0
  [ "$a1" -gt "$b1" ] && return 1
  [ "$a2" -lt "$b2" ] && return 0
  [ "$a2" -gt "$b2" ] && return 1
  [ "$a3" -lt "$b3" ]
}

# pick_previous CANDIDATE RELEASES-JSON: the newest published FINAL release (no draft, no
# pre-release) whose version is below the candidate's X.Y.Z core. A candidate v0.97.0-rc.2 therefore
# upgrades from v0.96.3, not from v0.97.0-rc.1: the question is what customers run today.
pick_previous() {
  local core=${1#v} t sorted
  core=${core%%-*}
  sorted=$(jq -r '.[] | select((.draft | not) and (.prerelease | not)) | .tag_name' "$2" |
    grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' | sort -t. -k1,1nr -k2,2nr -k3,3nr) || true
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    if semver_lt "$t" "$core"; then printf 'v%s\n' "$t"; return 0; fi
  done <<EOF
$sorted
EOF
  return 1
}

releases_json() { # OUT -> the releases of $REPO, newest first
  if [ -n "${RC_GATE_RELEASES_JSON:-}" ]; then cp "$RC_GATE_RELEASES_JSON" "$1"; return; fi
  local tok=${GITHUB_TOKEN:-${GH_TOKEN:-}} code
  if [ -n "$tok" ]; then
    code=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" |
      curl -K - -sS --proto '=https' -m 60 -o "$1" -w '%{http_code}' -H 'Accept: application/vnd.github+json' "$API_BASE/repos/$REPO/releases?per_page=100") || return 1
  else
    code=$(curl -sS --proto '=https' -m 60 -o "$1" -w '%{http_code}' -H 'Accept: application/vnd.github+json' "$API_BASE/repos/$REPO/releases?per_page=100") || return 1
  fi
  [ "$code" = 200 ]
}

# ------------------------------------------------------------------- download
# fetch_asset TAG NAME DIR: put the release asset NAME of TAG into DIR (0 = now present).
# ASSET_BASE is a directory laid out <base>/<tag>/<name> (fixtures, an air-gap transfer) or an
# https URL. A file already in DIR is kept unless --refresh; the transfer goes to a .part file, so a
# partial file never looks complete.
fetch_asset() {
  local tag=$1 name=$2 dir=$3
  [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { log "  refusing asset name '$name'"; return 1; }
  mkdir -p "$dir" || return 1
  if [ -f "$dir/$name" ] && [ "$REFRESH" = 0 ]; then return 0; fi
  rm -f "$dir/$name.part"
  case $ASSET_BASE in
    https://*)
      log "  download $tag/$name"
      curl -fsSL --retry 2 --retry-delay 2 -m "$CURL_TIMEOUT" --proto '=https' -o "$dir/$name.part" "$ASSET_BASE/$tag/$name" || { rm -f "$dir/$name.part"; return 1; }
      ;;
    *)
      log "  copy $tag/$name from $ASSET_BASE"
      cp "$ASSET_BASE/$tag/$name" "$dir/$name.part" 2>/dev/null || { rm -f "$dir/$name.part"; return 1; }
      ;;
  esac
  mv "$dir/$name.part" "$dir/$name"
}

# check_sum DIR NAME: sha256 of DIR/NAME against DIR/checksums.txt (0 = equal)
check_sum() {
  local want got
  want=$(awk -v n="$2" '$2 == n { print $1 }' "$1/checksums.txt")
  [ -n "$want" ] || return 1
  got=$(sha256_of "$1/$2")
  [ "$got" = "$want" ]
}

download_candidate() { # -> 0 when every asset named in checksums.txt, plus the signature files, is present
  local dir=$OUT/$CAND n bad=0 count=0
  fetch_asset "$CAND" checksums.txt "$dir" || { DL_ERR="checksums.txt of $CAND not available from $ASSET_BASE (is the tag released?)"; return 1; }
  for n in checksums.txt.sig checksums.txt.pem; do
    fetch_asset "$CAND" "$n" "$dir" || { DL_ERR="$n of $CAND not available"; return 1; }
  done
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    count=$((count + 1))
    fetch_asset "$CAND" "$n" "$dir" || { bad=$((bad + 1)); DL_ERR="$n of $CAND not available"; }
  done <<EOF
$(awk '{ print $2 }' "$dir/checksums.txt")
EOF
  [ "$bad" = 0 ] && DL_N=$((count + 3)) # the listed files, checksums.txt, .sig and .pem
}

download_previous() {
  local dir=$OUT/$PREV n
  for n in checksums.txt checksums.txt.sig checksums.txt.pem "keyorix-server_$PLATFORM" "keyorix_$PLATFORM"; do
    fetch_asset "$PREV" "$n" "$dir" || { DL_ERR="$n of $PREV not available from $ASSET_BASE"; return 1; }
  done
}

# ---------------------------------------------------------------------- drills
run_verify() {
  local rc=0 out=$OUT/verify-release.txt ids n args=()
  # shellcheck disable=SC2206 # deliberate word splitting of the operator's argument string
  [ -n "${RC_GATE_VERIFY_ARGS:-}" ] && args=($RC_GATE_VERIFY_ARGS)
  log "==> verify-release.sh $CAND (assets: $OUT/$CAND)"
  bash "$VERIFY" --repo "$REPO" --assets-dir "$OUT/$CAND" ${args[@]+"${args[@]}"} "$CAND" >"$out" 2>"$OUT/verify-release.err" || rc=$?
  case $rc in
    0)
      n=$(grep -c '^PASS' "$out" || true)
      emit verify-release PASS "all $n checks passed (log: $out)"
      ;;
    2)
      ids=$(awk '$1 == "SKIP" { printf "%s ", $2 }' "$out")
      emit verify-release SKIP "INCOMPLETE, not a pass: checks that could not run: ${ids:-unknown} (log: $out)"
      ;;
    1)
      ids=$(awk '$1 == "FAIL" { printf "%s ", $2 }' "$out")
      emit verify-release FAIL "failed checks: ${ids:-unknown} (log: $out)"
      ;;
    *)
      emit verify-release FAIL "verify-release.sh exited $rc: $(tail -1 "$OUT/verify-release.err" | cut -c1-160)"
      ;;
  esac
  return "$rc"
}

# run_drill LEG SCRIPT BACKEND [VAR=value ...]: one drill; the verdict comes from its exit status AND
# its last line, so a script that exits 0 without saying PASSED or SKIP is a FAIL (fail closed).
run_drill() {
  local leg=$1 script=$2 backend=$3 logf rc=0 last skips
  shift 3
  logf=$OUT/legs/$leg.log
  mkdir -p "$OUT/legs" "$OUT/drills"
  log "==> $leg ($script, $backend); log: $logf"
  (
    cd "$REPO_ROOT" || exit 3
    env -u DRILL_PG_DSN_FILE -u DRILL_PG_DSN_FILE2 -u DRILL_PG_DSN_FILE3 \
      DRILL_BACKEND="$backend" DRILL_ROOT="$OUT/drills" \
      DRILL_OLD_SERVER_BIN="$OUT/$PREV/keyorix-server_$PLATFORM" \
      DRILL_SERVER_BIN="$OUT/$CAND/keyorix-server_$PLATFORM" \
      DRILL_CLI_BIN="${CLI_OVERRIDE:-$OUT/$CAND/keyorix_$PLATFORM}" \
      "$@" bash "$DRILLS/$script"
  ) >"$logf" 2>&1 || rc=$?
  last=$(awk 'NF { l = $0 } END { print l }' "$logf")
  skips=$(grep '^SKIP ' "$logf" | cut -c1-110 | tr '\n' ';' || true)
  if [ "$rc" -ne 0 ]; then
    emit "$leg" FAIL "exit $rc: $(grep 'DRILL FAILED' "$logf" | tail -1 | cut -c1-200 || true) (log: $logf)"
  elif [[ $last == *" PASSED" ]]; then
    emit "$leg" PASS "$last${skips:+; partial SKIP: $skips}"
  elif [ -n "$skips" ]; then
    emit "$leg" SKIP "$skips"
  else
    emit "$leg" FAIL "exit 0 but the last line is neither '... PASSED' nor a SKIP line: '$(printf '%s' "$last" | cut -c1-120)' (log: $logf)"
  fi
}

pg_files_ok() { # N...: every dsnN.txt readable in RC_GATE_PG_DSN_DIR
  local n
  [ -n "${RC_GATE_PG_DSN_DIR:-}" ] || return 1
  for n in "$@"; do [ -r "$RC_GATE_PG_DSN_DIR/dsn$n.txt" ] || return 1; done
}

run_all_drills() {
  local d=${RC_GATE_PG_DSN_DIR:-}
  run_drill upgrade.sqlite upgrade.sh sqlite
  if pg_files_ok 1; then
    run_drill upgrade.postgres upgrade.sh postgres "DRILL_PG_DSN_FILE=$d/dsn1.txt"
  else
    emit upgrade.postgres SKIP "postgres SKIP: RC_GATE_PG_DSN_DIR unset or $d/dsn1.txt not readable (needs an EMPTY database)"
  fi
  run_drill backup-restore.sqlite backup-restore.sh sqlite
  if pg_files_ok 2 3; then
    if pg_files_ok 4; then
      run_drill backup-restore.postgres backup-restore.sh postgres "DRILL_PG_DSN_FILE=$d/dsn2.txt" "DRILL_PG_DSN_FILE2=$d/dsn3.txt" "DRILL_PG_DSN_FILE3=$d/dsn4.txt"
    else
      run_drill backup-restore.postgres backup-restore.sh postgres "DRILL_PG_DSN_FILE=$d/dsn2.txt" "DRILL_PG_DSN_FILE2=$d/dsn3.txt"
    fi
  else
    emit backup-restore.postgres SKIP "postgres SKIP: RC_GATE_PG_DSN_DIR unset or dsn2.txt/dsn3.txt not readable (needs two EMPTY databases)"
  fi
}

skip_drills() { # REASON
  emit upgrade.sqlite SKIP "not run: $1"
  emit upgrade.postgres SKIP "not run: $1"
  emit backup-restore.sqlite SKIP "not run: $1"
  emit backup-restore.postgres SKIP "not run: $1"
}

# ------------------------------------------------------------- result checking
REQUIRED_LEGS="download verify-release previous.checksum upgrade.sqlite upgrade.postgres backup-restore.sqlite backup-restore.postgres"

# check_result FILE [CANDIDATE]: 0 only for a complete TSV with no FAIL (and no SKIP unless allowed)
check_result() {
  local f=$1 want=${2:-} leg st bad=0 head
  [ -r "$f" ] || { log "rc-gate: cannot read $f"; return 1; }
  head=$(head -n 1 "$f")
  case $head in "# rc-gate"*) ;; *) log "rc-gate: $f is not an rc-gate result (first line: ${head:-empty})"; return 1 ;; esac
  if grep -q '^# cli-override' "$f"; then
    log "rc-gate: $f was made with --cli-bin (not the candidate's release CLI); rerun without it"
    return 1
  fi
  if [ -n "$want" ]; then
    case $head in *"candidate=$want"$'\t'*) ;; *) log "rc-gate: $f is for another candidate (header: $head)"; return 1 ;; esac
  fi
  for leg in $REQUIRED_LEGS; do
    st=$(awk -F'\t' -v l="$leg" '$1 == l { s = $2 } END { print s }' "$f")
    case $st in
      PASS) ;;
      SKIP) if [ "$ALLOW_SKIP" = 1 ]; then log "  $leg: SKIP (allowed)"; else log "  $leg: SKIP"; bad=1; fi ;;
      FAIL) log "  $leg: FAIL"; bad=1 ;;
      *) log "  $leg: missing from the result"; bad=1 ;;
    esac
  done
  if awk -F'\t' '$1 !~ /^#/ && $2 == "FAIL" { f = 1 } END { exit !f }' "$f"; then log "  the result holds a FAIL row"; bad=1; fi
  [ "$bad" = 0 ]
}

# ------------------------------------------------------------------------ main
main() {
  while [ $# -gt 0 ]; do
    case $1 in
      --dir) OUT=${2:?--dir needs DIR}; shift 2 ;;
      --refresh) REFRESH=1; shift ;;
      --cli-bin) CLI_OVERRIDE=${2:?--cli-bin needs FILE}; shift 2 ;;
      --strict) STRICT=1; shift ;;
      --allow-skip) ALLOW_SKIP=1; shift ;;
      --check-result) CHECK_FILE=${2:?--check-result needs FILE}; shift 2 ;;
      -h | --help) usage; exit 0 ;;
      -*) usage >&2; die "unknown option: $1" ;;
      *)
        if [ -z "$CAND" ]; then CAND=$1
        elif [ -z "$PREV" ]; then PREV=$1
        else die "at most two tags: CANDIDATE [PREVIOUS]"; fi
        shift
        ;;
    esac
  done

  if [ -n "$CHECK_FILE" ]; then
    if check_result "$CHECK_FILE" "$CAND"; then log "rc-gate: $CHECK_FILE is green"; exit 0; fi
    log "rc-gate: $CHECK_FILE is NOT green"
    exit 1
  fi

  [ -n "$CAND" ] || { usage >&2; die "CANDIDATE-TAG is required (for example v0.97.0-rc.1)"; }
  local tagre='^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'
  [[ $CAND =~ $tagre ]] || die "tag must look like v1.2.3 or v1.2.3-rc.1, got '$CAND'"
  [ -z "$PREV" ] || [[ $PREV =~ $tagre ]] || die "previous tag must look like v1.2.3, got '$PREV'"
  [ "$CAND" != "$PREV" ] || die "candidate and previous are the same tag"
  [[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "RC_GATE_REPO must be OWNER/NAME"
  local t
  for t in curl jq awk bash; do have "$t" || die "required tool missing: $t"; done
  have sha256sum || have shasum || die "required tool missing: sha256sum (or shasum)"
  [ -f "$VERIFY" ] || die "verify-release script not found: $VERIFY"
  [ -d "$DRILLS" ] || die "drills directory not found: $DRILLS"
  PLATFORM=$(host_platform) || die "unsupported host $(uname -sm); set RC_GATE_PLATFORM (linux_amd64, linux_arm64, darwin_amd64, darwin_arm64)"

  [ -n "$OUT" ] || OUT=$REPO_ROOT/tmp/rc-gate-$CAND
  mkdir -p "$OUT" || die "cannot create $OUT"
  OUT=$(cd "$OUT" && pwd)
  TSV=$OUT/rc-gate-result.tsv

  if [ -z "$PREV" ]; then
    log "==> finding the previous release below $CAND in $REPO"
    releases_json "$OUT/releases.json" || die "cannot list the releases of $REPO (GitHub API); name the previous tag as the second argument"
    PREV=$(pick_previous "$CAND" "$OUT/releases.json") || die "no published final release below $CAND in $REPO; name the previous tag as the second argument"
    log "    previous release: $PREV"
  fi

  printf '# rc-gate\tcandidate=%s\tprevious=%s\tplatform=%s\tutc=%s\n' "$CAND" "$PREV" "$PLATFORM" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$TSV"
  printf 'leg\tstatus\tdetail\n' >>"$TSV"
  printf 'rc-gate: candidate %s, previous %s, platform %s, results in %s\n' "$CAND" "$PREV" "$PLATFORM" "$OUT" >&2

  DL_ERR=""
  DL_N=0
  if download_candidate && download_previous; then
    emit download PASS "$DL_N assets of $CAND and the $PLATFORM server/CLI of $PREV in $OUT"
  else
    emit download FAIL "${DL_ERR:-download failed}"
    skip_drills "download FAILED"
    summary # exits
  fi

  local vrc=0
  run_verify || vrc=$?
  if [ "$vrc" = 1 ] || [ "$vrc" -gt 2 ]; then GATE_BLOCK="verify-release FAILED"; fi

  local bad=""
  for t in "keyorix-server_$PLATFORM" "keyorix_$PLATFORM"; do
    check_sum "$OUT/$PREV" "$t" || bad="$bad $t"
  done
  if [ -z "$bad" ]; then
    emit previous.checksum PASS "$PLATFORM server and CLI of $PREV match its checksums.txt (its signature is not checked here)"
  else
    emit previous.checksum FAIL "sha256 differs from $PREV checksums.txt:$bad - do NOT run them"
    GATE_BLOCK="${GATE_BLOCK:+$GATE_BLOCK, }previous.checksum FAILED"
  fi

  if [ -n "$GATE_BLOCK" ]; then
    skip_drills "$GATE_BLOCK, no drill started"
    summary # exits
  fi

  chmod +x "$OUT/$PREV/keyorix-server_$PLATFORM" "$OUT/$CAND/keyorix-server_$PLATFORM" "$OUT/$CAND/keyorix_$PLATFORM"
  printf '# old-server\t%s\n# new-server\t%s\n' \
    "$("$OUT/$PREV/keyorix-server_$PLATFORM" --version 2>&1 | head -n 1)" \
    "$("$OUT/$CAND/keyorix-server_$PLATFORM" --version 2>&1 | head -n 1)" >>"$TSV"
  if [ -n "$CLI_OVERRIDE" ]; then
    printf '# cli-override\t%s\n' "$CLI_OVERRIDE" >>"$TSV"
    log "NOTE: the drills drive the servers with $CLI_OVERRIDE, not the candidate's release CLI; this result is not eligible for the final-tag check"
  fi
  run_all_drills
  summary
}

summary() {
  local verdict code
  if [ "$N_FAIL" -gt 0 ]; then verdict=FAILED; code=1
  elif [ "$N_SKIP" -gt 0 ] && [ "$STRICT" = 1 ]; then verdict="INCOMPLETE (--strict: a SKIP is not a pass)"; code=2
  elif [ "$N_SKIP" -gt 0 ]; then verdict="PASSED with $N_SKIP SKIP (each names its reason; NOT a full pass)"; code=0
  else verdict=PASSED; code=0; fi
  printf '\nRC GATE %s: %s pass, %s fail, %s skip; candidate %s, previous %s; result %s\n' "$verdict" "$N_PASS" "$N_FAIL" "$N_SKIP" "$CAND" "$PREV" "$TSV"
  exit "$code"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
