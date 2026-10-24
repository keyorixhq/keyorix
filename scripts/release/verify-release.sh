#!/usr/bin/env bash
# verify-release.sh -- verify a published Keyorix release the way a customer would.
#
#   scripts/release/verify-release.sh [options] TAG        e.g. v0.96.3
#   scripts/release/verify-release.sh --self-test
#
# Needs read access only: no registry login, no GitHub token (GITHUB_TOKEN is used
# if set, purely to avoid the anonymous API rate limit). Required tools: curl, jq,
# sha256sum (or shasum). Optional: cosign (signature checks), openssl (certificate
# and offline signature checks), gh (cryptographic SLSA check). A check whose tool
# is missing is reported SKIP, never PASS.
#
# cosign versions: the image and Helm chart signatures were made by cosign v3, which
# stores them as OCI referrers (new bundle format); cosign v2 only looks for the old
# sha256-<digest>.sig tag and reports "no signatures found" on a perfectly good
# release. So the image and chart signature checks REQUIRE cosign >= 3; with an older
# cosign they are SKIPped with an explicit precondition message (INCOMPLETE, exit 2),
# never reported as FAIL. checksums.txt is signed by cosign v2.5.2 (release.yml pins
# it, because v3 changes the sign-blob flags); cosign v2 and v3 both verify it.
#
# What a release is supposed to contain is taken from .github/workflows/release.yml
# and docker-publish.yml (see docs/operator/verifying-releases.md for the table):
#   * GitHub Release: 14 binaries, 15 CycloneDX SBOMs, checksums.txt (+ .sig/.pem,
#     keyless cosign signature by release.yml), SLSA provenance of the 14 binaries.
#   * 6 images: keyorix-server, keyorix-server:<v>-airgap, keyorix-k8s-sync,
#     keyorix-operator, keyorix-mcp, keyorix-web, each tagged <v> and sha-<7>,
#     cosign-signed by docker-publish.yml, with BuildKit SBOM + provenance
#     attestations and a GitHub SLSA attestation.
#   * 3 Helm charts under <registry>/charts/, version = appVersion = <v>, cosign-
#     signed by release.yml.
#   * Both workflow runs concluded success, including every Trivy gate step.
#
# Output: one "PASS|FAIL|SKIP  <check-id>  <message>" line per check on stdout,
# progress on stderr. Exit 0 = every check passed; 1 = at least one FAIL;
# 2 = no FAIL but some checks were SKIPped (incomplete, NOT a pass); 3 = usage or
# missing required tool.
set -u -o pipefail
export LC_ALL=C

SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")

REPO=keyorixhq/keyorix
REGISTRY=ghcr.io/keyorixhq
GH_API=https://api.github.com
ISSUER=https://token.actions.githubusercontent.com
ASSETS_DIR=""
ASSETS_GIVEN=0
FIXTURES=""
OFFLINE=0
SKIP_BINARIES=0
SKIP_IMAGES=0
SKIP_CHARTS=0
PLAIN_HTTP=0
NO_COSIGN=0
NO_GH=0
ALLOW_SKIP=0
COMMIT=""
COSIGN_ARGS=""
SELF_TEST=0
TAG=""
CURL_TIMEOUT=${KVR_CURL_TIMEOUT:-900} # per request; the binaries are tens of MB each

N_PASS=0
N_FAIL=0
N_SKIP=0
HTTP_STATUS=000
HTTP_USERPWD=""
if [ -n "${REGISTRY_USER:-}" ]; then HTTP_USERPWD="${REGISTRY_USER}:${REGISTRY_PASSWORD:-}"; fi

usage() {
  cat <<'EOF'
Usage: verify-release.sh [options] TAG
       verify-release.sh --self-test

Verifies the GitHub Release, the 6 container images and the 3 Helm charts of TAG
(for example v0.96.3). Read access only; nothing is installed or modified.

Options:
  --repo OWNER/NAME     source repository (default keyorixhq/keyorix); the expected
                        signing identity is derived from it
  --registry HOST/PATH  where images/charts live (default ghcr.io/keyorixhq); set
                        it to your mirror, e.g. registry.example.com:5000/keyorix
  --plain-http          the registry/mirror speaks http, not https
  --assets-dir DIR      use release assets already in DIR (air-gapped transfer)
                        instead of downloading them
  --offline             do not call api.github.com (CI-run and attestation checks
                        become SKIP); implied nowhere, pass it explicitly
  --commit SHA          commit the tag points to (needed for the sha-<7> tag check
                        with --offline)
  --skip-binaries       do not download/hash the 14 binaries (SBOMs still checked)
  --skip-images         do not check images
  --skip-charts         do not check Helm charts
  --cosign-args "..."   extra arguments for every cosign call (see the operator
                        guide; note that neither "--offline" nor
                        "--insecure-ignore-tlog=true" makes checksums.txt
                        verifiable without network today)
  --no-cosign|--no-gh   behave as if the tool were not installed
  --allow-skip          exit 0 even if some checks were SKIPped (never hides FAIL)
  --self-test           run the built-in tests (fixtures; no network)
  -h, --help            this text

Needs cosign >= 3 for the image and chart signature checks (older cosign cannot
see their referrer signatures: those checks are SKIPped, exit 2, not FAILed).

Environment: REGISTRY_USER/REGISTRY_PASSWORD (only for a mirror that needs
read credentials), GITHUB_TOKEN (rate limit only), KVR_CURL_TIMEOUT (seconds).

Exit: 0 all passed, 1 a check FAILED, 2 incomplete (SKIPs), 3 usage/tool error.
EOF
}

die() { printf 'verify-release: %s\n' "$*" >&2; exit 3; }
log() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------- result lines
emit() { # STATUS ID MESSAGE
  case $1 in
    PASS) N_PASS=$((N_PASS + 1)) ;;
    FAIL) N_FAIL=$((N_FAIL + 1)) ;;
    SKIP) N_SKIP=$((N_SKIP + 1)) ;;
  esac
  printf '%-4s  %-40s %s\n' "$1" "$2" "$3"
}
pass() { emit PASS "$1" "$2"; }
fail() { emit FAIL "$1" "$2"; }
skip() { emit SKIP "$1" "$2"; }
detail() { # indented follow-up lines for the previous result, from a file
  [ -s "$1" ] || return 0
  head -n "${2:-6}" "$1" | sed 's/^/        /'
}

# ----------------------------------------------------------------------- tools
have() { command -v "$1" >/dev/null 2>&1; }
have_cosign() { [ "$NO_COSIGN" = 0 ] && have cosign; }

# cosign version, detected once (detect_cosign). COSIGN_MAJOR stays empty when it
# cannot be parsed (a dev build); then the image/chart checks are attempted anyway.
COSIGN_VERSION=""
COSIGN_MAJOR=""
COSIGN_OLD_SKIPS=0
COSIGN_MIN_MAJOR=3
detect_cosign() {
  have_cosign || return 0
  COSIGN_VERSION=$(cosign version 2>&1 | sed -n 's/^GitVersion:[[:space:]]*//p' | head -n 1)
  COSIGN_MAJOR=$(printf '%s\n' "$COSIGN_VERSION" | sed -n 's/^v\{0,1\}\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/p')
  if [ -z "$COSIGN_MAJOR" ]; then
    log "  cosign version not recognised (${COSIGN_VERSION:-no output}): assuming it can read referrer signatures"
  else
    log "  cosign $COSIGN_VERSION"
  fi
  if ! cosign_reads_referrers; then
    log "  NOTE: cosign $COSIGN_VERSION is older than v3: checksums.txt can be verified, but the image and chart signature checks will be SKIPped (precondition, not a failure). Install cosign >= 3."
  fi
}
# cosign_reads_referrers: false only for a cosign known to be older than v3
cosign_reads_referrers() { [ -z "$COSIGN_MAJOR" ] || [ "$COSIGN_MAJOR" -ge "$COSIGN_MIN_MAJOR" ]; }

# cosign_too_old ID: the precondition message for an image/chart signature check
cosign_too_old() {
  COSIGN_OLD_SKIPS=$((COSIGN_OLD_SKIPS + 1))
  skip "$1" "PRECONDITION NOT MET, not a verification failure: cosign $COSIGN_VERSION is too old to see referrer signatures (images and charts are signed with cosign v3). Install cosign >= 3 and re-run."
}
have_gh_auth() { [ "$NO_GH" = 0 ] && have gh && gh auth status >/dev/null 2>&1; }

sha256_of() { # FILE -> hex
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

b64d() { # base64 FILE -> stdout (portable: openssl handles single-line input)
  openssl base64 -d -A -in "$1"
}

# ------------------------------------------------------------------------ HTTP
# http_get URL OUT [ACCEPT] [BEARER]: status in $HTTP_STATUS, headers in OUT.hdr.
# Returns 0 only for HTTP 200. With --fixtures the URL is looked up in
# $FIXTURES/index.tsv (URL<TAB>file[<TAB>status[<TAB>headerfile]]) instead.
http_get() {
  local url=$1 out=$2 accept=${3-} bearer=${4-}
  HTTP_STATUS=000
  : >"$out.hdr"
  if [ -n "$FIXTURES" ]; then
    fixture_get "$url" "$out"
    return
  fi
  local proto='=https'
  [ "$PLAIN_HTTP" = 1 ] && proto='=http,https'
  local -a a=(-sS -L --retry 2 --retry-delay 2 -m "$CURL_TIMEOUT" --proto "$proto" -D "$out.hdr" -o "$out" -w '%{http_code}')
  [ -n "$accept" ] && a+=(-H "Accept: $accept")
  [ -n "$bearer" ] && a+=(-H "Authorization: Bearer $bearer")
  if [ -n "$HTTP_USERPWD" ]; then
    # credentials via stdin config so they never show up in `ps`
    HTTP_STATUS=$(printf 'user = "%s"\n' "$HTTP_USERPWD" | curl -K - "${a[@]}" "$url" 2>"$out.err") || HTTP_STATUS=000
  else
    HTTP_STATUS=$(curl "${a[@]}" "$url" 2>"$out.err") || HTTP_STATUS=000
  fi
  [ "$HTTP_STATUS" = 200 ]
}

fixture_get() {
  local url=$1 out=$2 line f st hf
  line=$(awk -F'\t' -v u="$url" '$1 == u { print; exit }' "$FIXTURES/index.tsv")
  if [ -z "$line" ]; then
    HTTP_STATUS=404
    return 1
  fi
  f=$(printf '%s\n' "$line" | cut -f2)
  st=$(printf '%s\n' "$line" | cut -f3)
  hf=$(printf '%s\n' "$line" | cut -f4)
  HTTP_STATUS=${st:-200}
  if [ -n "$f" ] && [ "$f" != "-" ]; then cp "$FIXTURES/$f" "$out"; else : >"$out"; fi
  if [ -n "$hf" ]; then cp "$FIXTURES/$hf" "$out.hdr"; fi
  [ "$HTTP_STATUS" = 200 ]
}

gh_get() { # API-PATH OUT -> 0 on 200. Never sends registry credentials.
  local HTTP_USERPWD=""
  local tok=${GITHUB_TOKEN:-${GH_TOKEN:-}}
  http_get "$GH_API/$1" "$2" "application/vnd.github+json" "$tok"
}

# gh_limited OUT: true if the last gh_get was refused by the GitHub API rate limit (60
# anonymous requests per hour per IP; one full run needs about 12). That says nothing
# about the release, so the callers SKIP instead of FAIL.
gh_limited() {
  case $HTTP_STATUS in
    429) return 0 ;;
    403) grep -qi 'rate limit' "$1" 2>/dev/null || grep -qi '^x-ratelimit-remaining: *0' "$1.hdr" 2>/dev/null ;;
    *) return 1 ;;
  esac
}
gh_limited_skip() { # ID OUT
  skip "$1" "GitHub API rate limit reached (HTTP $HTTP_STATUS): this check did not run - NOT a verification failure. Set GITHUB_TOKEN (any token, no scopes needed) or wait for the limit to reset, then re-run."
}

# ------------------------------------------------------------- registry client
SCHEME=https
REG_HOST=""
REG_PREFIX=""
REG_MODE=""     # none | bearer | basic | down
REG_REALM=""
REG_SERVICE=""
MANIFEST_ACCEPT="application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json"

reg_discover() {
  [ -n "$REG_MODE" ] && return 0
  local hdr ch
  if http_get "$SCHEME://$REG_HOST/v2/" "$WORK/v2.root"; then
    REG_MODE=none
    return 0
  fi
  case $HTTP_STATUS in
    401)
      hdr="$WORK/v2.root.hdr"
      ch=$(grep -i '^www-authenticate:' "$hdr" | tail -n 1)
      REG_REALM=$(printf '%s\n' "$ch" | sed -n 's/.*[Rr]ealm="\([^"]*\)".*/\1/p')
      REG_SERVICE=$(printf '%s\n' "$ch" | sed -n 's/.*[Ss]ervice="\([^"]*\)".*/\1/p')
      if printf '%s\n' "$ch" | grep -qi 'bearer' && [ -n "$REG_REALM" ]; then
        REG_MODE=bearer
      else
        REG_MODE=basic
      fi
      ;;
    000) REG_MODE=down ;;
    *) REG_MODE="http-$HTTP_STATUS" ;;
  esac
}

reg_token() { # REPO-PATH -> bearer token on stdout (cached)
  local cache url
  cache="$WORK/tok.$(printf '%s' "$1" | tr '/:' '__')"
  if [ ! -s "$cache" ]; then
    url="${REG_REALM}?service=${REG_SERVICE}&scope=repository:$1:pull"
    if http_get "$url" "$WORK/tok.json"; then
      jq -r '.token // .access_token // empty' "$WORK/tok.json" >"$cache"
    fi
  fi
  cat "$cache" 2>/dev/null
}

# reg_get REPO-PATH KIND(manifests|blobs) REF OUT [ACCEPT] -> 0 on HTTP 200
reg_get() {
  local tok=""
  reg_discover
  case $REG_MODE in
    none | basic) ;;
    bearer) tok=$(reg_token "$1") ;;
    *) HTTP_STATUS=000; return 1 ;;
  esac
  http_get "$SCHEME://$REG_HOST/v2/$1/$2/$3" "$4" "${5-}" "$tok"
}

# registry_ok ID-PREFIX: emit a SKIP/FAIL and return 1 if the registry cannot be used
registry_ok() {
  reg_discover
  case $REG_MODE in
    none | bearer | basic) return 0 ;;
    down)
      skip "$1" "registry $REG_HOST unreachable from this host (no HTTP answer; blocked network or DNS) - run this check where the registry is reachable"
      return 1
      ;;
    *)
      fail "$1" "registry $REG_HOST answered ${REG_MODE#http-} on /v2/ - wrong --registry, or it requires credentials (REGISTRY_USER/REGISTRY_PASSWORD)"
      return 1
      ;;
  esac
}

# --------------------------------------------------------------- expected sets
gen_expected() {
  local b oa
  : >"$WORK/exp.bins"
  for b in keyorix keyorix-server keyorix-migrate; do
    for oa in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do echo "${b}_${oa}"; done
  done >>"$WORK/exp.bins"
  for oa in linux_amd64 linux_arm64; do echo "keyorix-server-airgap_${oa}"; done >>"$WORK/exp.bins"
  sort -o "$WORK/exp.bins" "$WORK/exp.bins"
  { sed 's/$/_sbom.cdx.json/' "$WORK/exp.bins"; echo keyorix-server_frontend_sbom.cdx.json; } | sort >"$WORK/exp.sboms"
  sort -m "$WORK/exp.bins" "$WORK/exp.sboms" >"$WORK/exp.files"
  { cat "$WORK/exp.files"; printf '%s\n' checksums.txt checksums.txt.sig checksums.txt.pem; } | sort >"$WORK/exp.assets"
}

# name|repo|tag suffix|platforms (docker-publish.yml: 6 jobs, 5 repositories)
IMAGES="server|keyorix-server||linux/amd64 linux/arm64
server-airgap|keyorix-server|-airgap|linux/amd64 linux/arm64
k8s-sync|keyorix-k8s-sync||linux/amd64
operator|keyorix-operator||linux/amd64
mcp|keyorix-mcp||linux/amd64
web|keyorix-web||linux/amd64 linux/arm64"
CHARTS="keyorix keyorix-k8s-sync keyorix-operator"

# --------------------------------------------------------------------- helpers
cosign_verify() { # ID REF IDENTITY -> emits nothing, returns cosign status; output in $WORK/cosign.{out,err}
  local -a extra=()
  # shellcheck disable=SC2206 # deliberate word splitting of the user's argument string
  [ -n "$COSIGN_ARGS" ] && extra=($COSIGN_ARGS)
  if [ "${#extra[@]}" -gt 0 ]; then
    cosign verify --certificate-identity "$3" --certificate-oidc-issuer "$ISSUER" "${extra[@]}" "$2" >"$WORK/cosign.out" 2>"$WORK/cosign.err"
  else
    cosign verify --certificate-identity "$3" --certificate-oidc-issuer "$ISSUER" "$2" >"$WORK/cosign.out" 2>"$WORK/cosign.err"
  fi
}

# ------------------------------------------------------------ release asset I/O
fetch_asset() { # NAME -> 0 if now present in $ASSETS_DIR
  local n=$1
  [ -f "$ASSETS_DIR/$n" ] && return 0
  [ "$ASSETS_GIVEN" = 1 ] && return 1
  http_get "https://github.com/$REPO/releases/download/$TAG/$n" "$ASSETS_DIR/$n" || { rm -f "$ASSETS_DIR/$n"; return 1; }
}

check_source() {
  local sha=""
  if [ -n "$COMMIT" ]; then
    SHA=$COMMIT
    pass source.commit "tag $TAG -> $SHA (given with --commit)"
    return
  fi
  if [ "$OFFLINE" = 1 ]; then
    skip source.commit "--offline and no --commit: CI-run, provenance and sha-tag checks cannot run"
    return
  fi
  if gh_get "repos/$REPO/commits/$TAG" "$WORK/commit.json"; then
    sha=$(jq -r '.sha // empty' "$WORK/commit.json")
  fi
  if printf '%s\n' "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
    SHA=$sha
    pass source.commit "tag $TAG -> $SHA"
  elif gh_limited "$WORK/commit.json"; then
    gh_limited_skip source.commit
  else
    fail source.commit "tag $TAG does not exist in $REPO (GitHub API HTTP $HTTP_STATUS) - wrong TAG or --repo"
  fi
}

check_release_assets() {
  local id=release.assets f
  if [ "$ASSETS_GIVEN" = 1 ]; then
    : >"$WORK/act.assets"
    for f in "$ASSETS_DIR"/*; do
      [ -f "$f" ] && basename "$f" >>"$WORK/act.assets"
    done
    sort -o "$WORK/act.assets" "$WORK/act.assets"
  elif [ "$OFFLINE" = 1 ]; then
    skip $id "--offline without --assets-dir: nothing to check"
    return 1
  else
    if ! gh_get "repos/$REPO/releases/tags/$TAG" "$WORK/release.json"; then
      if gh_limited "$WORK/release.json"; then gh_limited_skip $id; return 1; fi
      fail $id "no published GitHub Release for $TAG (HTTP $HTTP_STATUS) - the release job did not publish, or the release is still a draft"
      return 1
    fi
    if [ "$(jq -r '.draft' "$WORK/release.json")" = true ]; then
      fail $id "release $TAG is still a DRAFT - not consumable"
      return 1
    fi
    jq -r '.assets[].name' "$WORK/release.json" | sort >"$WORK/act.assets"
  fi
  comm -23 "$WORK/exp.assets" "$WORK/act.assets" >"$WORK/missing.assets"
  comm -13 "$WORK/exp.assets" "$WORK/act.assets" >"$WORK/extra.assets"
  if [ -s "$WORK/missing.assets" ] || [ -s "$WORK/extra.assets" ]; then
    fail $id "$(wc -l <"$WORK/missing.assets" | tr -d ' ') missing, $(wc -l <"$WORK/extra.assets" | tr -d ' ') unexpected of $(wc -l <"$WORK/exp.assets" | tr -d ' ') expected assets"
    { sed 's/^/missing: /' "$WORK/missing.assets"; sed 's/^/unexpected (not covered by checksums.txt; update EXPECTED if intentional): /' "$WORK/extra.assets"; } >"$WORK/d.txt"
    detail "$WORK/d.txt" 8
    return 1
  fi
  pass $id "all $(wc -l <"$WORK/exp.assets" | tr -d ' ') expected assets present (14 binaries, 15 SBOMs, checksums.txt, .sig, .pem)"
}

check_checksums() {
  local n i total bad=0 got want
  fetch_asset checksums.txt || { fail release.checksums.listing "checksums.txt not available"; return 1; }
  if ! grep -Eq '^[0-9a-f]{64}  [^ /]+$' "$ASSETS_DIR/checksums.txt" || grep -Evq '^[0-9a-f]{64}  [^ /]+$' "$ASSETS_DIR/checksums.txt"; then
    fail release.checksums.listing "checksums.txt has lines that are not '<sha256>  <name>'"
    return 1
  fi
  awk '{print $2}' "$ASSETS_DIR/checksums.txt" | sort >"$WORK/chk.names"
  comm -23 "$WORK/exp.files" "$WORK/chk.names" >"$WORK/chk.missing"
  comm -13 "$WORK/exp.files" "$WORK/chk.names" >"$WORK/chk.extra"
  if [ -s "$WORK/chk.missing" ] || [ -s "$WORK/chk.extra" ]; then
    fail release.checksums.listing "checksums.txt does not list exactly the 29 expected files"
    { sed 's/^/not listed: /' "$WORK/chk.missing"; sed 's/^/unexpected: /' "$WORK/chk.extra"; } >"$WORK/d.txt"
    detail "$WORK/d.txt"
    return 1
  fi
  pass release.checksums.listing "checksums.txt lists exactly the 29 expected files"

  # SBOMs (always) then binaries (unless --skip-binaries)
  : >"$WORK/bad.sums"
  i=0
  total=$(wc -l <"$WORK/exp.sboms" | tr -d ' ')
  while IFS= read -r n; do
    i=$((i + 1))
    log "  [$i/$total] sbom $n"
    if ! fetch_asset "$n"; then echo "$n: cannot obtain" >>"$WORK/bad.sums"; continue; fi
    got=$(sha256_of "$ASSETS_DIR/$n")
    want=$(awk -v n="$n" '$2 == n {print $1}' "$ASSETS_DIR/checksums.txt")
    [ "$got" = "$want" ] || echo "$n: sha256 $got != checksums.txt $want" >>"$WORK/bad.sums"
  done <"$WORK/exp.sboms"
  if [ -s "$WORK/bad.sums" ]; then
    fail release.checksums.sboms "$(wc -l <"$WORK/bad.sums" | tr -d ' ') of $total SBOM files do not match checksums.txt"
    detail "$WORK/bad.sums"
  else
    pass release.checksums.sboms "all $total SBOMs match checksums.txt"
  fi

  if [ "$SKIP_BINARIES" = 1 ]; then
    skip release.checksums.binaries "--skip-binaries: 14 binaries not downloaded or hashed"
    return 0
  fi
  : >"$WORK/bad.sums"
  i=0
  total=$(wc -l <"$WORK/exp.bins" | tr -d ' ')
  while IFS= read -r n; do
    i=$((i + 1))
    log "  [$i/$total] binary $n"
    if ! fetch_asset "$n"; then echo "$n: cannot obtain" >>"$WORK/bad.sums"; bad=$((bad + 1)); continue; fi
    got=$(sha256_of "$ASSETS_DIR/$n")
    want=$(awk -v n="$n" '$2 == n {print $1}' "$ASSETS_DIR/checksums.txt")
    [ "$got" = "$want" ] || { echo "$n: sha256 $got != checksums.txt $want" >>"$WORK/bad.sums"; bad=$((bad + 1)); }
  done <"$WORK/exp.bins"
  if [ "$bad" -gt 0 ]; then
    fail release.checksums.binaries "$bad of $total binaries do not match checksums.txt - do NOT run them"
    detail "$WORK/bad.sums"
  else
    pass release.checksums.binaries "all $total binaries match checksums.txt"
  fi
}

check_signature() {
  local want_id="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
  local n ok=1
  for n in checksums.txt.sig checksums.txt.pem; do
    fetch_asset "$n" || ok=0
  done
  if [ "$ok" = 0 ] || [ ! -f "$ASSETS_DIR/checksums.txt" ]; then
    fail release.signature.files "checksums.txt, checksums.txt.sig or checksums.txt.pem not available"
    return 1
  fi

  if have_cosign; then
    log "  cosign verify-blob checksums.txt"
    local -a extra=()
    # shellcheck disable=SC2206 # deliberate word splitting of the user's argument string
    [ -n "$COSIGN_ARGS" ] && extra=($COSIGN_ARGS)
    local -a cmd=(cosign verify-blob --certificate "$ASSETS_DIR/checksums.txt.pem" --signature "$ASSETS_DIR/checksums.txt.sig"
      --certificate-identity "$want_id" --certificate-oidc-issuer "$ISSUER")
    [ "${#extra[@]}" -gt 0 ] && cmd+=("${extra[@]}")
    cmd+=("$ASSETS_DIR/checksums.txt")
    if "${cmd[@]}" >"$WORK/cosign.out" 2>"$WORK/cosign.err"; then
      pass release.signature.cosign "checksums.txt signed by $want_id (issuer $ISSUER)"
    else
      fail release.signature.cosign "cosign verify-blob FAILED for checksums.txt - do not trust this release"
      detail "$WORK/cosign.err" 4
    fi
  else
    skip release.signature.cosign "cosign not installed (or --no-cosign): signature chain/Rekor NOT verified. Run: cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig --certificate-identity $want_id --certificate-oidc-issuer $ISSUER checksums.txt"
  fi

  if ! have openssl; then
    skip release.signature.cert "openssl not installed: certificate identity not inspected"
    skip release.signature.offline "openssl not installed: raw signature not checked"
    return 0
  fi
  # Partial checks that need no network or sigstore root: they prove WHO the
  # certificate names and that the signature matches the certificate's key. They
  # do not prove the certificate chains to Fulcio or was logged in Rekor (cosign does).
  if grep -q 'BEGIN CERTIFICATE' "$ASSETS_DIR/checksums.txt.pem"; then
    cp "$ASSETS_DIR/checksums.txt.pem" "$WORK/cert.pem"
  else
    b64d "$ASSETS_DIR/checksums.txt.pem" >"$WORK/cert.pem" 2>/dev/null
  fi
  if ! openssl x509 -in "$WORK/cert.pem" -noout -text >"$WORK/cert.txt" 2>"$WORK/cert.err"; then
    fail release.signature.cert "checksums.txt.pem is not a readable certificate"
    detail "$WORK/cert.err" 3
    return 0
  fi
  local san iss_line
  san=$(grep -A1 'Subject Alternative Name' "$WORK/cert.txt" | grep -o 'URI:[^ ,]*' | head -n 1 | sed 's/^URI://')
  iss_line=$(grep -A1 -E '^[[:space:]]*1\.3\.6\.1\.4\.1\.57264\.1\.1:' "$WORK/cert.txt" | tail -n 1)
  if [ "$san" != "$want_id" ]; then
    fail release.signature.cert "certificate identity is '${san:-<none>}', expected '$want_id' - signed by a different workflow or tag"
  elif [ -z "$iss_line" ]; then
    skip release.signature.cert "identity matches ($san) but this openssl does not print the OIDC-issuer extension; cosign verifies it"
  elif ! printf '%s\n' "$iss_line" | grep -qF "$ISSUER"; then
    fail release.signature.cert "certificate OIDC issuer is '$(printf '%s' "$iss_line" | tr -d '[:space:]')', expected $ISSUER"
  else
    pass release.signature.cert "certificate names $san, issuer $ISSUER (partial: chain/Rekor need cosign)"
  fi
  if openssl x509 -in "$WORK/cert.pem" -pubkey -noout >"$WORK/pub.pem" 2>/dev/null &&
    b64d "$ASSETS_DIR/checksums.txt.sig" >"$WORK/sig.der" 2>/dev/null &&
    openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/sig.der" "$ASSETS_DIR/checksums.txt" >"$WORK/dgst.out" 2>&1; then
    pass release.signature.offline "checksums.txt.sig matches the certificate key over checksums.txt (partial: chain/Rekor need cosign)"
  else
    fail release.signature.offline "checksums.txt.sig does NOT verify against the certificate key - checksums.txt was altered or the signature is wrong"
    detail "$WORK/dgst.out" 2
  fi
}

check_sboms() {
  if ! have jq; then skip release.sbom "jq missing"; return; fi
  local n bad=0 total=0
  : >"$WORK/bad.sbom"
  while IFS= read -r n; do
    total=$((total + 1))
    [ -f "$ASSETS_DIR/$n" ] || { echo "$n: not available" >>"$WORK/bad.sbom"; bad=$((bad + 1)); continue; }
    if ! jq -e '.bomFormat == "CycloneDX" and (.specVersion | type == "string") and ((.components // []) | length > 0)' "$ASSETS_DIR/$n" >/dev/null 2>&1; then
      echo "$n: not a CycloneDX document with components" >>"$WORK/bad.sbom"
      bad=$((bad + 1))
    fi
  done <"$WORK/exp.sboms"
  if [ "$bad" -gt 0 ]; then
    fail release.sbom "$bad of $total release SBOMs missing or unparsable"
    detail "$WORK/bad.sbom"
  else
    pass release.sbom "all $total CycloneDX SBOMs parse and list components"
  fi
}

# statements_of FILE -> one decoded in-toto statement (compact JSON) per line
statements_of() {
  jq -c '.attestations[]?.bundle.dsseEnvelope.payload | @base64d | fromjson' "$1" 2>/dev/null
}

check_binary_provenance() {
  local id=release.provenance d match
  if [ "$OFFLINE" = 1 ]; then skip $id "--offline: GitHub attestations API not queried"; return; fi
  if ! have jq || ! have openssl; then skip $id "jq/openssl missing"; return; fi
  [ -f "$ASSETS_DIR/checksums.txt" ] || { skip $id "checksums.txt not available"; return; }
  d=$(awk '$2 == "keyorix-server_linux_amd64" {print $1}' "$ASSETS_DIR/checksums.txt")
  if ! gh_get "repos/$REPO/attestations/sha256:$d" "$WORK/att.bin.json"; then
    if gh_limited "$WORK/att.bin.json"; then gh_limited_skip $id; return; fi
    fail $id "no GitHub attestation found for keyorix-server_linux_amd64 (sha256:$d, HTTP $HTTP_STATUS) - attest-build-provenance did not run or lacked 'attestations: write'"
    return
  fi
  statements_of "$WORK/att.bin.json" >"$WORK/att.bin.stmts"
  match=$(jq -c --arg path ".github/workflows/release.yml" --arg ref "refs/tags/$TAG" --arg repo "https://github.com/$REPO" \
    'select(.predicateType | startswith("https://slsa.dev/provenance"))
     | select(.predicate.buildDefinition.externalParameters.workflow | .path == $path and .ref == $ref and .repository == $repo)' \
    "$WORK/att.bin.stmts" | head -n 1)
  if [ -z "$match" ]; then
    fail $id "attestation exists but is not SLSA provenance of release.yml at refs/tags/$TAG in $REPO"
    return
  fi
  # every one of the 14 binaries must be a subject with the digest checksums.txt lists
  printf '%s\n' "$match" | jq -r '.subject[] | "\(.digest.sha256)  \(.name)"' | sort -k2 >"$WORK/att.subjects"
  while IFS= read -r n; do awk -v n="$n" '$2 == n' "$ASSETS_DIR/checksums.txt"; done <"$WORK/exp.bins" | sort -k2 >"$WORK/att.expected"
  if diff "$WORK/att.expected" "$WORK/att.subjects" >"$WORK/att.diff"; then
    pass $id "SLSA provenance (release.yml @ refs/tags/$TAG) names all 14 binaries with the checksums.txt digests"
  else
    fail $id "provenance subjects differ from the 14 binaries in checksums.txt (< expected, > attested)"
    detail "$WORK/att.diff"
  fi
  if have_gh_auth && [ -f "$ASSETS_DIR/keyorix-server_linux_amd64" ]; then
    log "  gh attestation verify keyorix-server_linux_amd64"
    if gh attestation verify "$ASSETS_DIR/keyorix-server_linux_amd64" --repo "$REPO" >"$WORK/gh.out" 2>&1; then
      pass release.provenance.gh "gh attestation verify keyorix-server_linux_amd64 --repo $REPO succeeded (cryptographic)"
    else
      fail release.provenance.gh "gh attestation verify FAILED for keyorix-server_linux_amd64"
      detail "$WORK/gh.out" 4
    fi
  else
    skip release.provenance.gh "gh not installed/logged in or binary not downloaded: provenance checked by presence and content only. Run: gh attestation verify keyorix-server_linux_amd64 --repo $REPO"
  fi
}

# check_run ID WORKFLOW-PATH "JOB JOB ..." MIN-SCAN-STEPS-PER-JOB
check_run() {
  local id=$1 wf=$2 jobs_expected=$3 need_scan=$4 runid conc
  if [ "$OFFLINE" = 1 ] || [ -z "${SHA:-}" ]; then skip "$id" "needs the GitHub API and the tag commit (--offline / commit unknown)"; return; fi
  if ! gh_get "repos/$REPO/actions/runs?head_sha=$SHA&event=push&per_page=100" "$WORK/runs.json"; then
    if gh_limited "$WORK/runs.json"; then gh_limited_skip "$id"; return; fi
    fail "$id" "cannot list workflow runs for $SHA (HTTP $HTTP_STATUS)"
    return
  fi
  runid=$(jq -r --arg p "$wf" --arg t "$TAG" '[.workflow_runs[] | select(.path == $p and .head_branch == $t)] | sort_by(.id) | last | .id // empty' "$WORK/runs.json")
  conc=$(jq -r --arg p "$wf" --arg t "$TAG" '[.workflow_runs[] | select(.path == $p and .head_branch == $t)] | sort_by(.id) | last | .conclusion // empty' "$WORK/runs.json")
  if [ -z "$runid" ]; then
    fail "$id" "no $wf run for tag $TAG at $SHA - the workflow never ran"
    return
  fi
  if [ "$conc" != success ]; then
    fail "$id" "$wf run $runid concluded '${conc:-in progress}', not success"
    return
  fi
  if ! gh_get "repos/$REPO/actions/runs/$runid/jobs?per_page=100" "$WORK/jobs.$runid.json"; then
    if gh_limited "$WORK/jobs.$runid.json"; then gh_limited_skip "$id"; return; fi
    fail "$id" "cannot read the jobs of run $runid (HTTP $HTTP_STATUS)"
    return
  fi
  : >"$WORK/job.bad"
  local j
  for j in $jobs_expected; do
    # job must be success; every 'Scan image' (Trivy gate), 'Sign' and 'Tag image' step must be success
    if ! jq -e --arg j "$j" --argjson ns "$need_scan" '
        [.jobs[] | select(.name == $j)] | length == 1 and (.[0].conclusion == "success") and
        ([.[0].steps[] | select(.name | startswith("Scan image"))] | length >= $ns) and
        ([.[0].steps[] | select(.name | test("^(Scan image|Sign |Tag image|Package \\+ push|Publish to the GitHub)")) | .conclusion] | all(. == "success"))' \
      "$WORK/jobs.$runid.json" >/dev/null 2>&1; then
      echo "job '$j' missing or a scan/sign/tag/publish step did not succeed" >>"$WORK/job.bad"
    fi
  done
  if [ -s "$WORK/job.bad" ]; then
    fail "$id" "run $runid: $(wc -l <"$WORK/job.bad" | tr -d ' ') job(s) not clean"
    detail "$WORK/job.bad"
    return
  fi
  local nscan note=""
  if [ "$need_scan" -gt 0 ]; then
    nscan=$(jq '[.jobs[].steps[] | select(.name | startswith("Scan image")) | select(.conclusion == "success")] | length' "$WORK/jobs.$runid.json")
    note="; Trivy gate (Scan image) steps passed: $nscan"
  fi
  pass "$id" "$wf run $runid succeeded; jobs: $jobs_expected$note"
}

# ------------------------------------------------------------------ OCI images
# index_platforms FILE -> "os/arch" per real platform entry
index_platforms() {
  jq -r '.manifests[]? | select((.platform.os // "unknown") != "unknown") | "\(.platform.os)/\(.platform.architecture)"' "$1" | sort
}

# BuildKit attestation manifest layers carry the in-toto predicate type as an
# annotation. Real values (all six 0.96.3 images on every platform, and
# keyorix-k8s-sync 0.87.0-0.89.0; fixture testdata/real-buildkit-v0.96.3):
# "https://spdx.dev/Document" and "https://slsa.dev/provenance/v1". No published
# image uses "https://spdx.dev/Spdx", so it is not accepted.
SBOM_PREDICATE="https://spdx.dev/Document"
SLSA_PREDICATE="https://slsa.dev/provenance"

# att_layer_digest MANIFEST-FILE PREDICATE-TYPE-PREFIX -> digest of the first matching layer
att_layer_digest() {
  jq -r --arg t "$2" '.layers[]? | select((.annotations["in-toto.io/predicate-type"] // "") | startswith($t)) | .digest' "$1" | head -n 1
}
# att_layer_types MANIFEST-FILE -> comma-separated predicate types present (for error messages)
att_layer_types() {
  jq -r '[.layers[]? | (.annotations["in-toto.io/predicate-type"] // "none")] | join(",")' "$1" 2>/dev/null
}

check_image() { # name repo suffix platforms
  local name=$1 repo=$2 suffix=$3 plats=$4
  local id="image.$name" path="$REG_PREFIX/$repo" ref="$REGISTRY/$repo"
  local vtag="$VER$suffix" stag="" mf="$WORK/img.$name.index" digest p
  [ -n "${SHA:-}" ] && stag="sha-$(printf '%s' "$SHA" | cut -c1-7)$suffix"

  if ! reg_get "$path" manifests "$vtag" "$mf" "$MANIFEST_ACCEPT"; then
    if [ "$HTTP_STATUS" = 000 ]; then
      skip "$id.tag" "$ref:$vtag - registry unreachable"
    else
      fail "$id.tag" "$ref:$vtag not found (HTTP $HTTP_STATUS) - the image was not published, or the pipeline stopped at the Trivy/sign gate before tagging"
    fi
    return
  fi
  digest="sha256:$(sha256_of "$mf")"
  pass "$id.tag" "$ref:$vtag -> $digest"

  if [ -z "$stag" ]; then
    skip "$id.shatag" "commit unknown: sha tag not checked"
  elif reg_get "$path" manifests "$stag" "$WORK/img.$name.shatag" "$MANIFEST_ACCEPT" && [ "sha256:$(sha256_of "$WORK/img.$name.shatag")" = "$digest" ]; then
    pass "$id.shatag" "$ref:$stag -> same digest"
  else
    fail "$id.shatag" "$ref:$stag missing or points to a different digest than :$vtag"
  fi

  # platforms
  index_platforms "$mf" >"$WORK/img.$name.plats"
  printf '%s\n' "$plats" | tr ' ' '\n' | sort >"$WORK/img.$name.wantplats"
  if diff "$WORK/img.$name.wantplats" "$WORK/img.$name.plats" >"$WORK/d.txt"; then
    pass "$id.platforms" "$(tr '\n' ' ' <"$WORK/img.$name.plats")"
  else
    fail "$id.platforms" "platform set differs from expected ($plats); < expected, > found"
    detail "$WORK/d.txt"
  fi

  # BuildKit attestation manifests: one per platform, carrying an SPDX SBOM and SLSA provenance
  local bad_sbom="" bad_prov=""
  jq -r '.manifests[]? | select((.platform.os // "unknown") != "unknown") | .digest' "$mf" >"$WORK/img.$name.pdigests"
  while IFS= read -r p; do
    local am adig atype lay
    am="$WORK/img.$name.att.$(printf '%s' "$p" | cut -c8-19)"
    adig=$(jq -r --arg p "$p" '.manifests[]? | select(.annotations["vnd.docker.reference.type"] == "attestation-manifest" and .annotations["vnd.docker.reference.digest"] == $p) | .digest' "$mf" | head -n 1)
    if [ -z "$adig" ] || ! reg_get "$path" manifests "$adig" "$am" "$MANIFEST_ACCEPT"; then
      bad_sbom="$bad_sbom ${p:7:12}:no-attestation-manifest"
      bad_prov="$bad_prov ${p:7:12}:no-attestation-manifest"
      continue
    fi
    for atype in "$SBOM_PREDICATE" "$SLSA_PREDICATE"; do
      lay=$(att_layer_digest "$am" "$atype")
      if [ -z "$lay" ] || ! reg_get "$path" blobs "$lay" "$am.blob" ""; then
        if [ "$atype" = "$SBOM_PREDICATE" ]; then bad_sbom="$bad_sbom ${p:7:12}:no-sbom-layer(layer types: $(att_layer_types "$am"))"; else bad_prov="$bad_prov ${p:7:12}:no-provenance-layer(layer types: $(att_layer_types "$am"))"; fi
        continue
      fi
      if [ "sha256:$(sha256_of "$am.blob")" != "$lay" ]; then
        if [ "$atype" = "$SBOM_PREDICATE" ]; then bad_sbom="$bad_sbom ${p:7:12}:blob-digest-mismatch"; else bad_prov="$bad_prov ${p:7:12}:blob-digest-mismatch"; fi
      elif [ "$atype" = "$SBOM_PREDICATE" ]; then
        jq -e '(.predicate.spdxVersion | type == "string") and ((.predicate.packages // []) | length > 0)' "$am.blob" >/dev/null 2>&1 || bad_sbom="$bad_sbom ${p:7:12}:sbom-unparsable-or-empty"
      else
        jq -e '(.predicateType | startswith("https://slsa.dev/provenance")) and (.predicate | type == "object")' "$am.blob" >/dev/null 2>&1 || bad_prov="$bad_prov ${p:7:12}:provenance-unparsable"
      fi
    done
  done <"$WORK/img.$name.pdigests"
  if [ -z "$bad_sbom" ]; then pass "$id.sbom" "SPDX SBOM attestation present and parses for every platform"; else fail "$id.sbom" "BuildKit SBOM attestation problem:$bad_sbom"; fi
  if [ -z "$bad_prov" ]; then pass "$id.buildkit-provenance" "BuildKit provenance attestation present and parses for every platform"; else fail "$id.buildkit-provenance" "BuildKit provenance attestation problem:$bad_prov"; fi

  # cosign signature, by digest, against docker-publish.yml at this exact tag
  if have_cosign && ! cosign_reads_referrers; then
    cosign_too_old "$id.signature"
  elif have_cosign; then
    log "  cosign verify $ref@${digest:0:19}..."
    if cosign_verify "$id.signature" "$REGISTRY/$repo@$digest" "https://github.com/$REPO/.github/workflows/docker-publish.yml@refs/tags/$TAG"; then
      pass "$id.signature" "cosign: signed by docker-publish.yml@refs/tags/$TAG (issuer $ISSUER)"
    else
      fail "$id.signature" "cosign verify FAILED for $ref@$digest - unsigned, signed by another identity, or signature not copied to the mirror (a mirror must carry the referrer signature: see the operator guide)"
      detail "$WORK/cosign.err" 4
    fi
  else
    skip "$id.signature" "cosign not installed (or --no-cosign; needs cosign >= 3). Run: cosign verify --certificate-identity https://github.com/$REPO/.github/workflows/docker-publish.yml@refs/tags/$TAG --certificate-oidc-issuer $ISSUER $ref@$digest"
  fi

  # GitHub SLSA attestation for the image digest (digest-addressed, so valid for mirrors too)
  if [ "$OFFLINE" = 1 ]; then
    skip "$id.slsa" "--offline: GitHub attestations API not queried"
  elif gh_get "repos/$REPO/attestations/$digest" "$WORK/att.$name.json"; then
    statements_of "$WORK/att.$name.json" >"$WORK/att.$name.stmts"
    if jq -e --arg path ".github/workflows/docker-publish.yml" --arg ref "refs/tags/$TAG" --arg d "${digest#sha256:}" \
      'select(.predicateType | startswith("https://slsa.dev/provenance"))
       | select(.predicate.buildDefinition.externalParameters.workflow | .path == $path and .ref == $ref)
       | select([.subject[].digest.sha256] | index($d))' "$WORK/att.$name.stmts" >/dev/null 2>&1; then
      pass "$id.slsa" "GitHub SLSA provenance names $digest (docker-publish.yml @ refs/tags/$TAG)"
    else
      fail "$id.slsa" "attestation(s) for $digest exist but none is SLSA provenance of docker-publish.yml @ refs/tags/$TAG"
    fi
  elif gh_limited "$WORK/att.$name.json"; then
    gh_limited_skip "$id.slsa"
  else
    fail "$id.slsa" "no GitHub attestation for $digest (HTTP $HTTP_STATUS) - attest-build-provenance did not run for this image"
  fi
}

check_chart() { # chart
  local c=$1 id="chart.$1" path="$REG_PREFIX/charts/$1" ref="$REGISTRY/charts/$1"
  local mf="$WORK/chart.$c.manifest" cfg="$WORK/chart.$c.config" digest cdig
  if ! reg_get "$path" manifests "$VER" "$mf" "$MANIFEST_ACCEPT"; then
    if [ "$HTTP_STATUS" = 000 ]; then
      skip "$id.version" "$ref:$VER - registry unreachable"
    else
      fail "$id.version" "$ref:$VER not found (HTTP $HTTP_STATUS) - publish-chart job did not push it"
    fi
    return
  fi
  digest="sha256:$(sha256_of "$mf")"
  cdig=$(jq -r 'select(.config.mediaType == "application/vnd.cncf.helm.config.v1+json") | .config.digest // empty' "$mf")
  if [ -z "$cdig" ] || ! reg_get "$path" blobs "$cdig" "$cfg" ""; then
    fail "$id.version" "$ref:$VER is not a Helm chart artifact (no helm config blob)"
    return
  fi
  if [ "sha256:$(sha256_of "$cfg")" != "$cdig" ]; then
    fail "$id.version" "chart config blob does not match its digest $cdig - registry content is corrupt or tampered"
    return
  fi
  local cn cv ca
  cn=$(jq -r '.name // empty' "$cfg")
  cv=$(jq -r '.version // empty' "$cfg")
  ca=$(jq -r '.appVersion // empty' "$cfg")
  if [ "$cn" = "$c" ] && [ "$cv" = "$VER" ] && [ "$ca" = "$VER" ]; then
    pass "$id.version" "$ref:$VER -> $digest; name=$cn version=$cv appVersion=$ca"
  else
    fail "$id.version" "chart metadata mismatch: name='$cn' (want $c) version='$cv' (want $VER) appVersion='$ca' (want $VER)"
  fi
  if have_cosign && ! cosign_reads_referrers; then
    cosign_too_old "$id.signature"
  elif have_cosign; then
    log "  cosign verify $ref@${digest:0:19}..."
    if cosign_verify "$id.signature" "$REGISTRY/charts/$c@$digest" "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"; then
      pass "$id.signature" "cosign: signed by release.yml@refs/tags/$TAG"
    else
      fail "$id.signature" "cosign verify FAILED for $ref@$digest - unsigned, signed by another identity, or signature not copied to the mirror (a mirror must carry the referrer signature, and the chart digest must be unchanged: see the operator guide)"
      detail "$WORK/cosign.err" 4
    fi
  else
    skip "$id.signature" "cosign not installed (or --no-cosign; needs cosign >= 3). Run: cosign verify --certificate-identity https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG --certificate-oidc-issuer $ISSUER $ref@$digest"
  fi
}

# ------------------------------------------------------------------------ main
run_checks() {
  gen_expected
  detect_cosign
  SHA=""
  log "== $REPO $TAG: source commit"
  check_source
  log "== GitHub Release assets"
  check_release_assets # an incomplete asset set is a FAIL, but the checks below still run on what exists
  log "== checksums"
  check_checksums
  log "== checksums.txt signature"
  check_signature
  check_sboms
  log "== binary provenance"
  check_binary_provenance
  log "== CI evidence (workflow runs)"
  check_run ci.release-run ".github/workflows/release.yml" "build-and-release publish-chart" 0
  check_run ci.docker-publish-run ".github/workflows/docker-publish.yml" "build-and-push build-and-push-server-airgap build-and-push-k8s-sync build-and-push-operator build-and-push-mcp build-and-push-web" 1

  if [ "$SKIP_IMAGES" = 1 ]; then
    skip images "--skip-images"
  elif registry_ok image.registry; then
    log "== images"
    local line
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      log "  image ${line%%|*}"
      local name repo rest suffix plats
      name=${line%%|*}; rest=${line#*|}; repo=${rest%%|*}; rest=${rest#*|}; suffix=${rest%%|*}; plats=${rest#*|}
      check_image "$name" "$repo" "$suffix" "$plats"
    done <<EOF
$IMAGES
EOF
  fi
  if [ "$SKIP_CHARTS" = 1 ]; then
    skip charts "--skip-charts"
  elif registry_ok chart.registry; then
    log "== Helm charts"
    local c
    for c in $CHARTS; do check_chart "$c"; done
  fi
}

summary() {
  printf '\n'
  printf 'Summary for %s %s: %d PASS, %d FAIL, %d SKIP\n' "$REPO" "$TAG" "$N_PASS" "$N_FAIL" "$N_SKIP"
  if [ "$COSIGN_OLD_SKIPS" -gt 0 ]; then
    printf 'PRECONDITION NOT MET: cosign %s cannot see the referrer signatures of images and charts, so %d signature check(s) did not run.\n' "$COSIGN_VERSION" "$COSIGN_OLD_SKIPS"
    printf '                      Install cosign >= 3 (https://github.com/sigstore/cosign/releases) and re-run. This is not a verification failure.\n'
  fi
  if [ "$N_FAIL" -gt 0 ]; then
    printf 'RESULT: FAILED - do not deploy this release until every FAIL above is explained.\n'
    return 1
  fi
  if [ "$N_SKIP" -gt 0 ]; then
    printf 'RESULT: INCOMPLETE - %d check(s) did not run (see SKIP lines); this is not a pass.\n' "$N_SKIP"
    [ "$ALLOW_SKIP" = 1 ] && return 0
    return 2
  fi
  printf 'RESULT: VERIFIED - every check passed.\n'
  return 0
}

# ------------------------------------------------------------------- self-test
# Builds a synthetic, internally consistent release (tag v9.9.9 of selftest/keyorix,
# registry registry.test/keyorix) with a throwaway key/certificate, serves it through
# the --fixtures mechanism, then runs the script against it and against mutations of
# it. A last case replays GitHub-side data copied from the real v0.96.3 release.
st_cert() { # DIR SAN -> DIR/key.pem DIR/cert.pem
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$1/key.pem" -out "$1/cert.pem" \
    -subj "/CN=selftest" -days 2 \
    -addext "subjectAltName=critical,URI:$2" \
    -addext "1.3.6.1.4.1.57264.1.1=ASN1:UTF8String:$ISSUER" >/dev/null 2>&1
}

st_blob() { # FIXDIR FILE-CONTENT-PATH -> prints digest; stores as blob-<hex>
  local d
  d=$(sha256_of "$2")
  cp "$2" "$1/blob-$d"
  printf 'sha256:%s' "$d"
}

st_world() { # DIR  (env: ST_SAN, ST_BAD_APPVERSION, ST_NO_TAG, ST_SBOM_TYPE)
  local W=$1 R=selftest/keyorix T=v9.9.9 V=9.9.9 S=0123456789abcdef0123456789abcdef01234567
  local F="$W/fx" A="$W/assets" n oa b
  local RB
  RB="$(dirname "$SELF")/testdata/real-buildkit-v0.96.3"
  mkdir -p "$F" "$A"
  gen_expected
  # assets
  while IFS= read -r n; do printf 'binary %s\n' "$n" >"$A/$n"; done <"$WORK/exp.bins"
  while IFS= read -r n; do
    printf '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"x","version":"1"}]}\n' >"$A/$n"
  done <"$WORK/exp.sboms"
  (cd "$A" && while IFS= read -r n; do printf '%s  %s\n' "$(sha256_of "$n")" "$n"; done <"$WORK/exp.files" >checksums.txt)
  st_cert "$W" "${ST_SAN:-https://github.com/$R/.github/workflows/release.yml@refs/tags/$T}"
  openssl dgst -sha256 -sign "$W/key.pem" "$A/checksums.txt" | openssl base64 -A >"$A/checksums.txt.sig"
  openssl base64 -A -in "$W/cert.pem" >"$A/checksums.txt.pem"
  rm -f "$W/key.pem"

  local idx="$F/index.tsv" api=https://api.github.com/repos/$R
  : >"$idx"
  tsv() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${3-}" "${4-}" >>"$idx"; }
  # GitHub API: commit, runs, jobs, binary attestation
  printf '{"sha":"%s"}\n' "$S" >"$F/commit.json"
  tsv "$api/commits/$T" commit.json
  printf '{"workflow_runs":[{"id":1001,"path":".github/workflows/release.yml","head_branch":"%s","conclusion":"success"},{"id":1002,"path":".github/workflows/docker-publish.yml","head_branch":"%s","conclusion":"success"}]}\n' "$T" "$T" >"$F/runs.json"
  tsv "$api/actions/runs?head_sha=$S&event=push&per_page=100" runs.json
  printf '{"jobs":[{"name":"build-and-release","conclusion":"success","steps":[{"name":"Publish to the GitHub Release","conclusion":"success"}]},{"name":"publish-chart","conclusion":"success","steps":[{"name":"Package + push charts to GHCR (OCI)","conclusion":"success"}]}]}\n' >"$F/jobs1001.json"
  tsv "$api/actions/runs/1001/jobs?per_page=100" jobs1001.json
  printf '{"jobs":[' >"$F/jobs1002.json"
  local first=1 j
  for j in build-and-push build-and-push-server-airgap build-and-push-k8s-sync build-and-push-operator build-and-push-mcp build-and-push-web; do
    [ "$first" = 1 ] || printf ',' >>"$F/jobs1002.json"
    first=0
    printf '{"name":"%s","conclusion":"success","steps":[{"name":"Scan image for vulnerabilities (trivy)","conclusion":"success"},{"name":"Sign image (keyless)","conclusion":"success"},{"name":"Tag image (after scan, attestation and signature)","conclusion":"success"}]}' "$j" >>"$F/jobs1002.json"
  done
  printf ']}\n' >>"$F/jobs1002.json"
  tsv "$api/actions/runs/1002/jobs?per_page=100" jobs1002.json

  st_attest() { # OUTFILE WORKFLOW SUBJECTS-JSON(array of {name,digest:{sha256}})
    jq -nc --arg wf "$2" --arg ref "refs/tags/$T" --arg repo "https://github.com/$R" --argjson subj "$3" \
      '{_type:"https://in-toto.io/Statement/v1",subject:$subj,predicateType:"https://slsa.dev/provenance/v1",predicate:{buildDefinition:{externalParameters:{workflow:{ref:$ref,repository:$repo,path:$wf}}}}}' |
      openssl base64 -A | jq -Rc '{attestations:[{bundle:{dsseEnvelope:{payload:.}}}]}' >"$1"
  }
  local subj
  subj=$(while IFS= read -r n; do jq -nc --arg n "$n" --arg d "$(sha256_of "$A/$n")" '{name:$n,digest:{sha256:$d}}'; done <"$WORK/exp.bins" | jq -sc .)
  st_attest "$F/att-bin.json" .github/workflows/release.yml "$subj"
  tsv "$api/attestations/sha256:$(sha256_of "$A/keyorix-server_linux_amd64")" att-bin.json

  # registry: /v2/ demands a bearer token, tokens are served per repository
  printf 'HTTP/1.1 401 Unauthorized\r\nWww-Authenticate: Bearer realm="https://registry.test/token",service="registry.test"\r\n\r\n' >"$F/hdr401"
  tsv "https://registry.test/v2/" - 401 hdr401
  local regs=""
  addreg() { regs="$regs $1"; }

  local line name repo rest suffix plats idxf idxd cdig pdig adig sdig bdig pl
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name=${line%%|*}; rest=${line#*|}; repo=${rest%%|*}; rest=${rest#*|}; suffix=${rest%%|*}; plats=${rest#*|}
    addreg "keyorix/$repo"
    idxf="$F/index-$name.json"
    jq -nc '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",manifests:[]}' >"$idxf"
    for pl in $plats; do
      printf '{"schemaVersion":2,"note":"platform manifest %s %s"}\n' "$name" "$pl" >"$W/pm.json"
      pdig=sha256:$(sha256_of "$W/pm.json")
      # attestation manifest + layers copied from the real v0.96.3 keyorix-k8s-sync image (BuildKit):
      # only the layer digests/sizes (and the subject) are replaced, because the real SBOM statement
      # is trimmed to a few array elements (see testdata/real-buildkit-v0.96.3/README.md)
      cp "$RB/sbom.blob.trimmed.json" "$W/sbom.json"
      cp "$RB/provenance.blob.json" "$W/prov.json"
      sdig=$(st_blob "$F" "$W/sbom.json")
      bdig=$(st_blob "$F" "$W/prov.json")
      jq -c --arg s "$sdig" --argjson ss "$(wc -c <"$W/sbom.json" | tr -d ' ')" --arg b "$bdig" --argjson bs "$(wc -c <"$W/prov.json" | tr -d ' ')" \
        --arg sub "$pdig" --argjson subs "$(wc -c <"$W/pm.json" | tr -d ' ')" --arg sbomtype "${ST_SBOM_TYPE:-}" \
        '.layers[0].digest = $s | .layers[0].size = $ss | .layers[1].digest = $b | .layers[1].size = $bs
         | .subject.digest = $sub | .subject.size = $subs
         | if $sbomtype != "" then .layers[0].annotations["in-toto.io/predicate-type"] = $sbomtype else . end' \
        "$RB/attestation-manifest.json" >"$W/am.json"
      adig=sha256:$(sha256_of "$W/am.json")
      cp "$W/am.json" "$F/manifest-${adig#sha256:}"
      tsv "https://registry.test/v2/keyorix/$repo/manifests/$adig" "manifest-${adig#sha256:}"
      tsv "https://registry.test/v2/keyorix/$repo/blobs/$sdig" "blob-${sdig#sha256:}"
      tsv "https://registry.test/v2/keyorix/$repo/blobs/$bdig" "blob-${bdig#sha256:}"
      jq -c --arg pd "$pdig" --arg ad "$adig" --arg os "${pl%/*}" --arg ar "${pl#*/}" \
        '.manifests += [{digest:$pd,platform:{os:$os,architecture:$ar}},{digest:$ad,platform:{os:"unknown",architecture:"unknown"},annotations:{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":$pd}}]' "$idxf" >"$idxf.tmp"
      mv "$idxf.tmp" "$idxf"
    done
    idxd=sha256:$(sha256_of "$idxf")
    cp "$idxf" "$F/manifest-${idxd#sha256:}"
    if [ "${ST_NO_TAG:-}" != "$name" ]; then
      tsv "https://registry.test/v2/keyorix/$repo/manifests/$V$suffix" "manifest-${idxd#sha256:}"
      tsv "https://registry.test/v2/keyorix/$repo/manifests/sha-0123456$suffix" "manifest-${idxd#sha256:}"
    fi
    st_attest "$F/att-$name.json" .github/workflows/docker-publish.yml "$(jq -nc --arg d "${idxd#sha256:}" '[{name:"ghcr.io/x",digest:{sha256:$d}}]')"
    tsv "$api/attestations/$idxd" "att-$name.json"
  done <<EOF
$IMAGES
EOF
  local c
  for c in $CHARTS; do
    addreg "keyorix/charts/$c"
    jq -nc --arg n "$c" --arg v "$V" --arg a "${ST_BAD_APPVERSION:-$V}" '{name:$n,version:$v,appVersion:$a}' >"$W/cfg.json"
    cdig=$(st_blob "$F" "$W/cfg.json")
    jq -nc --arg c "$cdig" '{schemaVersion:2,config:{mediaType:"application/vnd.cncf.helm.config.v1+json",digest:$c},layers:[]}' >"$W/cm.json"
    cp "$W/cm.json" "$F/manifest-chart-$c"
    tsv "https://registry.test/v2/keyorix/charts/$c/manifests/$V" "manifest-chart-$c"
    tsv "https://registry.test/v2/keyorix/charts/$c/blobs/$cdig" "blob-${cdig#sha256:}"
  done
  local r
  for r in $regs; do
    printf '{"token":"t"}\n' >"$F/token.json"
    tsv "https://registry.test/token?service=registry.test&scope=repository:$r:pull" token.json
  done
}

st_expect() { # OUTFILE STATUS ID -> 0 if "STATUS  ID " line exists
  if grep -Eq "^$2 +$3( |$)" "$1"; then ST_OK=$((ST_OK + 1)); else
    ST_BAD=$((ST_BAD + 1))
    printf '  SELF-TEST MISMATCH: expected %s %s in %s\n' "$2" "$3" "$1" >&2
  fi
}

st_count() { # OUTFILE REGEX EXPECTED-COUNT
  local got
  got=$(grep -Ec "$2" "$1")
  if [ "$got" = "$3" ]; then
    ST_OK=$((ST_OK + 1))
  else
    ST_BAD=$((ST_BAD + 1))
    printf '  SELF-TEST MISMATCH: %s matched %s lines in %s, expected %s\n' "$2" "$got" "$1" "$3" >&2
  fi
}

st_run() { # NAME EXPECTED-EXIT [args...]  (world in $WORK/st/$NAME)
  local name=$1 want=$2 got
  shift 2
  ST_OUT="$WORK/st/$name.out"
  bash "$SELF" "$@" >"$ST_OUT" 2>"$WORK/st/$name.err"
  got=$?
  if [ "$got" = "$want" ]; then ST_OK=$((ST_OK + 1)); else
    ST_BAD=$((ST_BAD + 1))
    printf '  SELF-TEST MISMATCH: %s exited %s, expected %s\n' "$name" "$got" "$want" >&2
  fi
}

# fake cosign. `cosign version` prints GitVersion: $FAKE_COSIGN_VERSION (default v3.0.6, the
# real format). Like the real thing, a cosign older than v3 verifies blobs but finds no signature
# on an image or chart (they are OCI referrers); FAKE_COSIGN=fail makes every verification fail.
st_fake_cosign() {
  mkdir -p "$WORK/st/bin"
  cat >"$WORK/st/bin/cosign" <<'EOF'
#!/bin/sh
if [ "$1" = version ]; then
  [ -n "${FAKE_COSIGN_VERSION-v3.0.6}" ] && echo "GitVersion:    ${FAKE_COSIGN_VERSION-v3.0.6}"
  exit 0
fi
if [ "${FAKE_COSIGN:-ok}" != ok ]; then
  echo "Error: no matching signatures: fake cosign failure" >&2
  exit 1
fi
case "${FAKE_COSIGN_VERSION-v3.0.6}" in
  v2.* | v1.*)
    if [ "$1" = verify ]; then
      echo "Error: no signatures found" >&2
      exit 10
    fi
    ;;
esac
exit 0
EOF
  chmod +x "$WORK/st/bin/cosign"
}

self_test() {
  have openssl || die "--self-test needs openssl"
  ST_OK=0
  ST_BAD=0
  mkdir -p "$WORK/st"
  st_fake_cosign
  local base=(--repo selftest/keyorix --registry registry.test/keyorix --no-gh)
  local id n

  log "self-test 1/11: consistent synthetic release: every check PASS, only the gh check SKIPped (exit 2)"
  st_world "$WORK/st/ok"
  PATH="$WORK/st/bin:$PATH" st_run ok 2 "${base[@]}" --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  for id in source.commit release.assets release.checksums.listing release.checksums.sboms release.checksums.binaries release.signature.cosign release.signature.cert release.signature.offline release.sbom release.provenance ci.release-run ci.docker-publish-run image.server.tag image.server.shatag image.server.platforms image.server.sbom image.server.buildkit-provenance image.server.signature image.server.slsa image.server-airgap.tag image.k8s-sync.signature image.operator.slsa image.mcp.platforms image.web.platforms chart.keyorix.version chart.keyorix-operator.signature; do
    st_expect "$ST_OUT" PASS "$id"
  done
  st_count "$ST_OUT" '^PASS ' 60
  st_count "$ST_OUT" '^FAIL ' 0
  st_count "$ST_OUT" '^SKIP ' 1 # --no-gh: the cryptographic gh check is the only thing not run
  st_expect "$ST_OUT" SKIP release.provenance.gh
  PATH="$WORK/st/bin:$PATH" st_run ok-allow 0 "${base[@]}" --allow-skip --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_count "$ST_OUT" '^RESULT: INCOMPLETE' 1

  log "self-test 2/11: one altered binary, one missing SBOM, cosign rejecting everything"
  st_world "$WORK/st/mut"
  printf 'tampered\n' >>"$WORK/st/mut/assets/keyorix_linux_amd64"
  rm "$WORK/st/mut/assets/keyorix-migrate_darwin_arm64_sbom.cdx.json"
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN=fail st_run mut 1 "${base[@]}" --assets-dir "$WORK/st/mut/assets" --fixtures "$WORK/st/mut/fx" v9.9.9
  st_expect "$ST_OUT" FAIL release.assets
  st_expect "$ST_OUT" FAIL release.checksums.sboms
  st_expect "$ST_OUT" FAIL release.sbom
  st_expect "$ST_OUT" FAIL release.checksums.binaries
  # complete asset set, only the binary altered
  st_world "$WORK/st/tamper"
  printf 'tampered\n' >>"$WORK/st/tamper/assets/keyorix_linux_amd64"
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN=fail st_run tamper 1 "${base[@]}" --assets-dir "$WORK/st/tamper/assets" --fixtures "$WORK/st/tamper/fx" v9.9.9
  st_expect "$ST_OUT" FAIL release.checksums.binaries
  st_expect "$ST_OUT" PASS release.checksums.sboms
  st_expect "$ST_OUT" FAIL release.signature.cosign
  st_expect "$ST_OUT" FAIL image.web.signature
  st_expect "$ST_OUT" FAIL chart.keyorix.signature
  st_expect "$ST_OUT" PASS image.web.tag

  log "self-test 3/11: checksums.txt altered after signing"
  st_world "$WORK/st/sum"
  awk '{ if ($2 == "keyorix_darwin_arm64") $1 = "0000000000000000000000000000000000000000000000000000000000000000"; print $1 "  " $2 }' "$WORK/st/sum/assets/checksums.txt" >"$WORK/st/sum/c.txt"
  mv "$WORK/st/sum/c.txt" "$WORK/st/sum/assets/checksums.txt"
  PATH="$WORK/st/bin:$PATH" st_run sum 1 "${base[@]}" --assets-dir "$WORK/st/sum/assets" --fixtures "$WORK/st/sum/fx" v9.9.9
  st_expect "$ST_OUT" FAIL release.signature.offline
  st_expect "$ST_OUT" FAIL release.checksums.binaries
  st_expect "$ST_OUT" FAIL release.provenance

  log "self-test 4/11: certificate names a different workflow"
  ST_SAN="https://github.com/selftest/keyorix/.github/workflows/evil.yml@refs/tags/v9.9.9" st_world "$WORK/st/san"
  PATH="$WORK/st/bin:$PATH" st_run san 1 "${base[@]}" --assets-dir "$WORK/st/san/assets" --fixtures "$WORK/st/san/fx" v9.9.9
  st_expect "$ST_OUT" FAIL release.signature.cert
  st_expect "$ST_OUT" PASS release.signature.offline

  log "self-test 5/11: chart appVersion wrong, one image tag missing"
  ST_BAD_APPVERSION=9.9.8 ST_NO_TAG=web st_world "$WORK/st/chart"
  PATH="$WORK/st/bin:$PATH" st_run chart 1 "${base[@]}" --assets-dir "$WORK/st/chart/assets" --fixtures "$WORK/st/chart/fx" v9.9.9
  st_expect "$ST_OUT" FAIL chart.keyorix.version
  st_expect "$ST_OUT" FAIL chart.keyorix-k8s-sync.version
  st_expect "$ST_OUT" FAIL image.web.tag
  st_expect "$ST_OUT" PASS image.server.tag

  log "self-test 6/11: no cosign and unreachable registry must be INCOMPLETE (exit 2), not a pass"
  st_world "$WORK/st/skip"
  printf 'https://registry.test/v2/\t-\t000\t\n' >"$WORK/st/skip/fx/index.tsv.new"
  awk -F'\t' '$1 != "https://registry.test/v2/"' "$WORK/st/skip/fx/index.tsv" >>"$WORK/st/skip/fx/index.tsv.new"
  mv "$WORK/st/skip/fx/index.tsv.new" "$WORK/st/skip/fx/index.tsv"
  st_run skip 2 "${base[@]}" --no-cosign --assets-dir "$WORK/st/skip/assets" --fixtures "$WORK/st/skip/fx" v9.9.9
  st_expect "$ST_OUT" SKIP release.signature.cosign
  st_expect "$ST_OUT" SKIP image.registry
  st_expect "$ST_OUT" SKIP chart.registry
  st_expect "$ST_OUT" PASS release.signature.offline
  st_count "$ST_OUT" '^RESULT: INCOMPLETE' 1

  log "self-test 7/11: replay of GitHub-side data copied from the real v0.96.3 release"
  local real
  real="$(dirname "$SELF")/testdata/real-v0.96.3"
  if [ -d "$real" ]; then
    st_run real 1 --repo keyorixhq/keyorix --no-gh --no-cosign --skip-images --skip-charts --assets-dir "$real/assets" --fixtures "$real" v0.96.3
    st_expect "$ST_OUT" PASS source.commit
    st_expect "$ST_OUT" PASS release.signature.cert
    st_expect "$ST_OUT" PASS release.signature.offline
    st_expect "$ST_OUT" PASS release.checksums.listing
    st_expect "$ST_OUT" PASS ci.release-run
    st_expect "$ST_OUT" PASS ci.docker-publish-run
    st_expect "$ST_OUT" PASS release.provenance
    st_expect "$ST_OUT" FAIL release.assets # the fixture holds only the 3 signed files, not all 32
  else
    log "  real fixtures missing: $real"
    ST_BAD=$((ST_BAD + 1))
  fi

  log "self-test 8/11: cosign v2 verifies checksums.txt but cannot see referrer signatures: SKIP + precondition, never FAIL"
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN_VERSION=v2.5.2 st_run cosign2 2 "${base[@]}" --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_expect "$ST_OUT" PASS release.signature.cosign
  st_expect "$ST_OUT" SKIP image.server.signature
  st_expect "$ST_OUT" SKIP image.web.signature
  st_expect "$ST_OUT" SKIP chart.keyorix.signature
  st_expect "$ST_OUT" SKIP chart.keyorix-operator.signature
  st_expect "$ST_OUT" PASS image.server.sbom
  st_count "$ST_OUT" '^FAIL ' 0
  st_count "$ST_OUT" '^PASS ' 51
  st_count "$ST_OUT" '^SKIP ' 10 # gh + 6 image + 3 chart signatures
  st_count "$ST_OUT" 'too old to see referrer signatures.*Install cosign >= 3' 9
  st_count "$ST_OUT" '^PRECONDITION NOT MET: cosign v2.5.2 cannot see the referrer signatures' 1
  st_count "$ST_OUT" '^RESULT: INCOMPLETE' 1
  st_count "$ST_OUT" 'do not deploy' 0
  # a real problem is still a FAIL with an old cosign: blob verification works there
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN_VERSION=v2.5.2 FAKE_COSIGN=fail st_run cosign2fail 1 "${base[@]}" --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_expect "$ST_OUT" FAIL release.signature.cosign
  st_expect "$ST_OUT" SKIP image.server.signature
  # a cosign that is new enough is asked, and its refusal is a FAIL
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN_VERSION=v3.0.0 FAKE_COSIGN=fail st_run cosign3fail 1 "${base[@]}" --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_expect "$ST_OUT" FAIL image.server.signature
  st_expect "$ST_OUT" FAIL chart.keyorix.signature
  st_count "$ST_OUT" 'too old to see referrer signatures' 0
  # --skip-images/--skip-charts need no v3: no precondition message
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN_VERSION=v2.5.2 st_run cosign2skip 2 "${base[@]}" --skip-images --skip-charts --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_expect "$ST_OUT" PASS release.signature.cosign
  st_count "$ST_OUT" 'PRECONDITION NOT MET' 0

  log "self-test 9/11: unrecognised cosign version string (dev build, no output): the checks are attempted"
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN_VERSION=devel st_run cosigndev 2 "${base[@]}" --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_expect "$ST_OUT" PASS image.server.signature
  st_expect "$ST_OUT" PASS chart.keyorix.signature
  PATH="$WORK/st/bin:$PATH" FAKE_COSIGN_VERSION='' st_run cosignnone 2 "${base[@]}" --assets-dir "$WORK/st/ok/assets" --fixtures "$WORK/st/ok/fx" v9.9.9
  st_expect "$ST_OUT" PASS image.web.signature

  log "self-test 10/11: BuildKit attestation layers as the real registry serves them"
  local RB want got
  RB="$(dirname "$SELF")/testdata/real-buildkit-v0.96.3"
  # verbatim copy of the real v0.96.3 keyorix-k8s-sync attestation manifest (sha256:862b7c3f...)
  got=$(att_layer_digest "$RB/attestation-manifest.json" "$SBOM_PREDICATE")
  want=sha256:545eac42f314e153f360661f272b1215b641de7ef5470caf5eecb5fc78d72fcf
  if [ "$got" = "$want" ]; then ST_OK=$((ST_OK + 1)); else ST_BAD=$((ST_BAD + 1)); printf '  SELF-TEST MISMATCH: real SBOM layer is %s, expected %s\n' "$got" "$want" >&2; fi
  got=$(att_layer_digest "$RB/attestation-manifest.json" "$SLSA_PREDICATE")
  want=sha256:75ca1aea6d23d9123609466e00dfad85e15be5311df9b30e10a315c947b5647b
  if [ "$got" = "$want" ]; then ST_OK=$((ST_OK + 1)); else ST_BAD=$((ST_BAD + 1)); printf '  SELF-TEST MISMATCH: real provenance layer is %s, expected %s\n' "$got" "$want" >&2; fi
  # the invented type the first version of this script expected must not be accepted
  ST_SBOM_TYPE="https://spdx.dev/Spdx" st_world "$WORK/st/sbomtype"
  PATH="$WORK/st/bin:$PATH" st_run sbomtype 1 "${base[@]}" --assets-dir "$WORK/st/sbomtype/assets" --fixtures "$WORK/st/sbomtype/fx" v9.9.9
  st_expect "$ST_OUT" FAIL image.server.sbom
  st_expect "$ST_OUT" FAIL image.web.sbom
  st_expect "$ST_OUT" PASS image.server.buildkit-provenance
  st_count "$ST_OUT" 'no-sbom-layer\(layer types: https://spdx.dev/Spdx,https://slsa.dev/provenance/v1\)' 6

  log "self-test 11/11: GitHub API rate limit (HTTP 403 'API rate limit exceeded') is INCOMPLETE, never FAIL"
  st_world "$WORK/st/rate"
  printf '{"message":"API rate limit exceeded for 203.0.113.7. (But here'"'"'s the good news: Authenticated requests get a higher rate limit.)","documentation_url":"https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting"}\n' >"$WORK/st/rate/fx/ratelimit.json"
  awk -F'\t' -v OFS='\t' '$1 ~ /^https:\/\/api\.github\.com\// { $2 = "ratelimit.json"; $3 = "403" } { print }' "$WORK/st/rate/fx/index.tsv" >"$WORK/st/rate/fx/index.tsv.new"
  mv "$WORK/st/rate/fx/index.tsv.new" "$WORK/st/rate/fx/index.tsv"
  PATH="$WORK/st/bin:$PATH" st_run rate 2 "${base[@]}" --assets-dir "$WORK/st/rate/assets" --fixtures "$WORK/st/rate/fx" v9.9.9
  st_expect "$ST_OUT" SKIP source.commit
  st_expect "$ST_OUT" SKIP release.provenance
  st_expect "$ST_OUT" SKIP ci.release-run
  st_expect "$ST_OUT" SKIP image.server.slsa
  st_expect "$ST_OUT" PASS release.signature.cosign
  st_expect "$ST_OUT" PASS image.server.signature
  st_count "$ST_OUT" '^FAIL ' 0
  st_count "$ST_OUT" 'GitHub API rate limit reached \(HTTP 403\).*NOT a verification failure' 8
  st_count "$ST_OUT" '^RESULT: INCOMPLETE' 1

  printf 'self-test: %d assertions passed, %d failed\n' "$ST_OK" "$ST_BAD"
  [ "$ST_BAD" = 0 ] || { log "outputs kept in $WORK/st"; KEEP_WORK=1; return 1; }
  return 0
}

# ------------------------------------------------------------------ entrypoint
while [ $# -gt 0 ]; do
  case $1 in
    --repo) REPO=${2:?--repo needs OWNER/NAME}; shift 2 ;;
    --registry) REGISTRY=${2:?--registry needs HOST/PATH}; shift 2 ;;
    --plain-http) PLAIN_HTTP=1; SCHEME=http; shift ;;
    --assets-dir) ASSETS_DIR=${2:?--assets-dir needs DIR}; ASSETS_GIVEN=1; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    --commit) COMMIT=${2:?--commit needs SHA}; shift 2 ;;
    --skip-binaries) SKIP_BINARIES=1; shift ;;
    --skip-images) SKIP_IMAGES=1; shift ;;
    --skip-charts) SKIP_CHARTS=1; shift ;;
    --cosign-args) COSIGN_ARGS=${2-}; shift 2 ;;
    --no-cosign) NO_COSIGN=1; shift ;;
    --no-gh) NO_GH=1; shift ;;
    --allow-skip) ALLOW_SKIP=1; shift ;;
    --fixtures) FIXTURES=${2:?--fixtures needs DIR}; shift 2 ;; # test hook, see --self-test
    --self-test) SELF_TEST=1; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) usage >&2; die "unknown option: $1" ;;
    *) [ -z "$TAG" ] || die "only one TAG allowed"; TAG=$1; shift ;;
  esac
done

for t in curl jq; do have "$t" || die "required tool missing: $t"; done
have sha256sum || have shasum || die "required tool missing: sha256sum (or shasum)"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-release.XXXXXX") || die "cannot create a temp dir"
KEEP_WORK=0
cleanup() { [ "$KEEP_WORK" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

if [ "$SELF_TEST" = 1 ]; then
  self_test
  exit $?
fi

[ -n "$TAG" ] || { usage >&2; die "TAG is required (for example v0.96.3)"; }
printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$' || die "TAG must look like v1.2.3, got '$TAG'"
printf '%s\n' "$REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || die "--repo must be OWNER/NAME"
VER=${TAG#v}
REG_HOST=${REGISTRY%%/*}
REG_PREFIX=${REGISTRY#*/}
[ "$REG_PREFIX" != "$REGISTRY" ] || die "--registry must be HOST/PATH (for example ghcr.io/keyorixhq)"
if [ -z "$ASSETS_DIR" ]; then
  ASSETS_DIR="$WORK/assets"
  mkdir -p "$ASSETS_DIR"
elif [ ! -d "$ASSETS_DIR" ]; then
  die "--assets-dir $ASSETS_DIR is not a directory"
fi

log "verify-release: $REPO $TAG against $REGISTRY (read-only; working in $WORK)"
run_checks
summary
