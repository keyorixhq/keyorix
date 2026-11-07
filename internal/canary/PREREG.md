# Pre-registration: secret-leak canary oracle (B1)

Written 2026-11-06, before any campaign run. Do not edit after the first run;
append dated amendments below the line instead.

## Question

Does any secret-class value (planted canary) reach a surface where it must not
be, when the real router/core/storage stack is driven through EVERY registered
HTTP route with canaries injected into every request surface (path, query,
headers, JSON body fields, malformed bodies), including hostile-charset
canaries whose JSON/URL/HTML/base64/hex encodings all differ from the raw form?

This complements, and does not replace, `FuzzCanarySecretLeakage`
(server/http/canary_secret_leakage_fuzz_test.go), which drives a curated
operation set with a fixed-charset canary. Gaps this oracle targets (taken from
docs/secret-canary-leak-harness.md "What it cannot cover"): non-literal value
shapes, request-surface reflection on routes outside the curated set, output
channels other than response/log/DB (stdout/stderr, temp files), minted-token
harvesting.

## Canary classes

- S (secret): password, secret value, token, DSN, credential header, cookie,
  query `token=`/`password=`/`secret=`/`key=`. Allowed NOWHERE except the
  single request that supplied it being stored encrypted/hashed. Not allowed in:
  any response body/header (including the response to the request that carried
  it), any log line, stdout/stderr, metrics, audit rows, any DB cell or raw DB
  file bytes (plaintext or any encoding), temp files.
- M (metadata control): name, description, email, username, ids. Expected in
  DB and in the response to the request carrying it. Never counted as a
  finding; counted and reported so the harness is proven able to see them.
- H (harvested): a credential minted by the server (kx_* token, session token,
  any response JSON field named token/secret/password/key on a non-reveal
  route). First sighting in its minting response is allowed; any later
  sighting on any other surface is a candidate finding.

## What counts as a finding (candidate)

An S or H canary, in ANY encoding variant (raw, JSON-escaped with and without
HTML escaping, URL query/path escaped, double URL escaped, HTML-escaped, Go
%q, base64 std/url/raw at all 3 alignments, hex lower/upper, and any
contiguous run of >= 12 bytes of its unique core), found on a surface where it
is not allowed per above.

Reveal endpoints (GET /secrets/value, GET /secrets/{id}?include_value=true,
export/backup of decrypted values, and their gRPC twins) are allowed to return
the value of a secret the caller may read, in the `value` field only. The sweep
does not read back sweep-created secrets through them with success semantics.

## What counts as a finding (confirmed)

A candidate becomes a finding only if ALL hold:
1. It reproduces on 3 consecutive full replays with the same seed in fresh
   worlds, with the same (route, surface, variant, canary-label) key.
2. It is classified by a human-readable review as `real-leak`,
   `expected-non-secret`, or `harness-bug`. Only `real-leak` is a finding.
   Reflection of an S canary in the response to the request that carried it
   is classified case by case (a value echoed in an error body is real-leak;
   a field the API contract documents as echoed is expected-non-secret).

## What counts as negative

Zero confirmed real-leak after the full budget below, AND the planted-leak
self-test detects every planted leak (response, log, stdout, stderr, DB cell
in a ciphertext-only table, raw DB file, temp file, metrics body) in every
tested encoding variant. If the self-test misses any planted leak the run is
INVALID (not negative) and nothing is claimed.

## Budget

- Deterministic sweep: all routes returned by chi.Walk x {admin, outsider,
  no-auth, canary-bearer} x {path, query, header, json-body, malformed-body}
  injection shapes, seeds 1..3. Single-digit minutes locally.
- Fuzz mode (FuzzCanaryRouteSweep): 30 minutes locally per worker as smoke, plus
  up to 6 hours on pve01 if headroom exists (never during the Tue 2026-11-10
  05:00 UTC mutation window; CT 100 is not touched).
- gRPC: every registered method, canary in every string/bytes field + metadata.
- CLI: build the cli binary, run failure/usage paths with S canary in argv,
  env, stdin and config; scan stdout, stderr, files written.

## Not covered (stated in advance)

Core dumps (macOS dumps disabled by default; panics are covered via recovered
panic text only). Client-side browser logs. Anything outside this process
other than CLI child stdout/stderr. Non-SQLite backends unless PG DSN is set.
