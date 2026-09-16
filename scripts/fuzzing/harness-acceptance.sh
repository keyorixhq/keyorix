#!/usr/bin/env bash
# harness-acceptance.sh — reach-check + coverage-delta acceptance gate for "in-wall" fuzz
# harnesses (the ones that pour the fuzzer PAST a signature/JSON wall).
#
# Runs where `go build ./...` works (a fuzz rig or a CI clone) — NOT the egress-restricted
# Cowork sandbox. From the repo root:
#
#     bash scripts/fuzzing/harness-acceptance.sh            # fast, deterministic (seed corpus)
#     bash scripts/fuzzing/harness-acceptance.sh --fuzz 60s # also fold in fuzz-found inputs (rig)
#
# WHY (state-of-the-art alignment):
#   The water/pour-point model says fuzzing can't climb walls (a signature/MAC the fuzzer
#   can't forge). An in-wall harness starts the pour INSIDE the wall with a valid fixture —
#   but nothing proves it actually cleared the wall. A harness can run millions of execs while
#   silently DRY, every input dying at the signature check, and still look healthy. This is the
#   reach-check OSS-Fuzz-Gen and QuartetFuzz ("entry-point adequacy / reach checks") call for.
#
# WHAT IT ASSERTS, per target:
#   1. REACH: coverage of the specific POST-WALL functions clears a floor. If a byte-level
#      sibling exists, the in-wall harness must also cover MORE of them than the sibling — the
#      code the sibling can't reach is exactly the point of the in-wall harness.
#   2. COVERAGE DELTA: the numbers are printed (reach% / sibling% / delta) so "this harness adds
#      coverage" is measured, not asserted — the acceptance side of target selection.
#
# HOW REACH IS MEASURED:
#   By default from the SEED corpus (`go test -run='^Target$'`, no -fuzz): deterministic and
#   CI-safe. Our in-wall harnesses are valid-by-construction (every input is freshly re-signed),
#   and their seeds span accept + each rejection reason, so a seed replay already drives the
#   post-wall branches. `--fuzz Ns` additionally folds the on-disk fuzz cache corpus into the
#   replay for a deeper (rig) measurement.
set -uo pipefail

FUZZTIME=""
if [ "${1:-}" = "--fuzz" ]; then FUZZTIME="${2:?--fuzz needs a duration, e.g. 60s}"; fi

# target ; pkg ; coverpkg(empty=pkg) ; post-wall focus regex ; byte-level sibling(empty=none) ; floor%
#
# The focus regex names the functions that only run AFTER the wall is cleared:
#   OIDC  -> everything past the signature check lives in OIDCVerifier.Verify (aud/azp/exp/iat);
#            the byte-level sibling enters Verify but dies at the parse, leaving the tail cold.
#   SAML  -> assertion extraction + attribute mapping (extractAssertion/attrMatches/
#            attributeValues) only run once XML-DSig verifies.
#   WebAuthn -> not behind a keyorix wall; the "wall" is the JSON envelope, and the target code
#            is in the go-webauthn library, so we instrument that package via coverpkg.
# NOTE on the focus regex: it is grepped against `go tool cover -func` output, whose function
# column prints a METHOD as its bare name (`Verify`), not receiver-qualified (`OIDCVerifier.Verify`).
# Match a method by its file path instead (the -func line carries the full path). Free functions
# (extractAssertion, the go-webauthn ParseCredential*…) match by name directly.
#
# The floor is a REACH proxy — "did the fuzzer get past the wall into the target code at all",
# not full branch coverage. The sibling/delta comparison is only meaningful under --fuzz (in
# seed-only mode both a valid-fixture seed and the byte-level sibling's valid seed cover the same
# lines), so it is computed and enforced only when --fuzz is given.
TARGETS=(
  'FuzzOIDCVerifierClaims;./internal/core;;internal/core/oidc\.go:[0-9]+:.*Verify;FuzzOIDCVerifierVerify;50'
  'FuzzParseResponseContent;./internal/saml;;extractAssertion|attrMatches|attributeValues;FuzzParseResponse;1'
  'FuzzWebAuthnCredentialResponse;./server/http/handlers;github.com/go-webauthn/webauthn/protocol;ParseCredential(Creation|Request)ResponseBytes;;1'
)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# stage_fuzz_corpus copies fuzz-cache inputs for <target> into <pkg>/testdata/fuzz/<target>/ so a
# plain `go test -run` replay (which does NOT read the cache) will execute them. Records what it
# added so it can be removed afterwards — never leaves fuzz spew in the tree.
declare -a STAGED=()
stage_fuzz_corpus() {
  local tgt="$1" pkg="$2"
  [ -n "$FUZZTIME" ] || return 0
  local importpath cachedir dest f
  importpath="$(go list "$pkg" 2>/dev/null)" || return 0
  cachedir="$(go env GOCACHE)/fuzz/${importpath}/${tgt}"
  [ -d "$cachedir" ] || return 0
  dest="${pkg}/testdata/fuzz/${tgt}"
  mkdir -p "$dest"
  for f in "$cachedir"/*; do
    [ -e "$f" ] || continue
    local base; base="$(basename "$f")"
    if [ ! -e "$dest/$base" ]; then cp "$f" "$dest/$base"; STAGED+=("$dest/$base"); fi
  done
}
unstage_fuzz_corpus() {
  local f
  for f in "${STAGED[@]:-}"; do [ -n "$f" ] && rm -f "$f"; done
  STAGED=()
}

# reach_pct <target> <pkg> <coverpkg> <focus_regex> -> prints max coverage % across focus funcs
reach_pct() {
  local tgt="$1" pkg="$2" cov="$3" focus="$4"
  local prof="$WORK/${tgt}.cov"
  if [ -n "$FUZZTIME" ]; then
    go test -run='^$' -fuzz="^${tgt}$" -fuzztime="$FUZZTIME" "$pkg" >/dev/null 2>&1 || true
    stage_fuzz_corpus "$tgt" "$pkg"
  fi
  go test -run="^${tgt}$" -coverpkg="$cov" -coverprofile="$prof" "$pkg" >/dev/null 2>&1
  local rc=$?
  [ -n "$FUZZTIME" ] && unstage_fuzz_corpus
  [ $rc -eq 0 ] && [ -s "$prof" ] || { echo "-1"; return; }
  go tool cover -func="$prof" \
    | grep -E "$focus" \
    | awk 'BEGIN{m=0} {p=$NF; gsub(/%/,"",p); if(p+0>m) m=p+0} END{printf "%.1f", m}'
}

printf '%-34s %8s %10s %8s %6s  %s\n' TARGET REACH% SIBLING% DELTA FLOOR RESULT
printf '%s\n' '---------------------------------------------------------------------------------'
status=0
for row in "${TARGETS[@]}"; do
  IFS=';' read -r tgt pkg cov focus sib floor <<<"$row"
  [ -n "$cov" ] || cov="$pkg"
  rp="$(reach_pct "$tgt" "$pkg" "$cov" "$focus")"
  sp="n/a"; delta="n/a"
  # Sibling comparison only under --fuzz: in seed-only mode both harnesses' valid seeds cover
  # the same post-wall lines, so the delta is uninformative (and can even invert, since the
  # byte-level sibling's malformed seeds cover error paths the in-wall harness never signs).
  if [ -n "$sib" ] && [ -n "$FUZZTIME" ]; then
    sp="$(reach_pct "$sib" "$pkg" "$cov" "$focus")"
    delta="$(awk -v a="$rp" -v b="$sp" 'BEGIN{printf "%+.1f", a-b}')"
  fi
  result="PASS"
  if [ "$rp" = "-1" ]; then
    result="ERROR(build/run)"; status=1
  elif awk -v r="$rp" -v f="$floor" 'BEGIN{exit !(r+0 < f+0)}'; then
    result="FAIL<floor"; status=1                       # never reached the post-wall code
  elif [ "$sp" != "n/a" ] && [ "$sp" != "-1" ] && awk -v r="$rp" -v s="$sp" 'BEGIN{exit !(r+0 <= s+0)}'; then
    result="WARN=sibling"                                # cleared floor but no better than byte-level
  fi
  printf '%-34s %8s %10s %8s %6s  %s\n' "$tgt" "$rp" "$sp" "$delta" "$floor" "$result"
done

echo
if [ $status -ne 0 ]; then
  echo "FAIL: at least one in-wall harness did not demonstrably clear its wall (see above)."
  echo "A FAIL<floor means the fuzzer never reached the post-wall functions — the harness is"
  echo "effectively dry; fix the in-wall fixture/seeds before trusting the target."
else
  echo "OK: every in-wall harness exercises its post-wall code above the floor."
fi
exit $status
