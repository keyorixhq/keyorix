# Hostile-backend record-and-mutate fuzzer: pre-registered rules

Status: PRE-REGISTRATION. This file is committed BEFORE any campaign run. Rules
may be tightened later only by a commit that says so; a rule may not be relaxed
to make a finding go away (a finding is reclassified in the findings log with a
reason, not by editing this file).

## Mechanism

For each connector C the harness (package `hostile`):

1. serves a hand-written VALID response sequence (one `Route` per backend
   endpoint the connector calls) from a local `httptest` server, never a real
   endpoint, never a real credential; all data synthetic;
2. applies a MUTATION PROGRAM (decoded from the fuzz input bytes; every byte
   string is a valid program; the all-zero/empty program is the pristine
   control) to ONE route at selected occurrences: JSON field-level ops (null,
   delete, type swap, duplicate key, huge/deep/odd-unicode values, NUL, CRLF,
   lone surrogates, number extremes, oversized lists, key renames), status and
   Content-Type changes, gzip / gzip bomb / corrupt gzip / unknown
   Content-Encoding, framing oddities (short/long/duplicate Content-Length,
   bad/huge/unterminated chunks, giant chunk extensions, giant headers,
   close-delimited bodies), redirects (to a sentinel "internal" server, to
   self in a loop, same-origin once), and network faults (RST after headers /
   mid-body, close after headers, never respond, slow-drip, garbage bytes,
   TLS-alert bytes, accept-and-close);
3. runs the connector call through `Harness.Run`, then evaluates the oracles.

Not covered in this PR (stated so nobody over-reads it): XML and protobuf
field-level mutation (only JSON is structure-aware; SAML/STS XML and GCP gRPC
remain covered by their existing byte-level targets), real TLS handshake
failures (only TLS-alert-shaped bytes on a plaintext listener), HTTP/2.

## Oracles (all must hold for every input unless a target documents an exemption)

- O1 NO-PANIC. Any panic is a failure (native fuzz recording).
- O2 NO-HANG. The call returns within `CallTimeout + 1s` of start. The call is
  given a context with deadline `CallTimeout` (500 ms); not honouring the
  caller's context is a failure even if the client has its own larger timeout.
- O3 NO-LEAK. After the call and after the harness closes its servers, the
  per-function goroutine census must return to the pre-call census within
  1.2 s (poll), and on Linux the open-FD count must return to the pre-call
  count + 2.
- O4 BOUNDED-WORK. `runtime.MemStats.TotalAlloc` delta over the call is at most
  `256 MiB + 16 x (bytes the server wrote)`. (Gross-amplification tripwire, not
  a fine-grained budget.)
- O5 FAIL-CLOSED. If the call reports success then ALL of: the consumed
  response was completely delivered (framing intact, no network fault, gzip
  intact); its final status is in the target's accepted set; the target's
  independent STRICT decoder accepts the delivered body; the returned
  value/identity/credential equals what the strict decoder extracts (no
  partial or invented value); and the value is not empty/`null` unless the
  strict decoder says the backend really stored an empty value. The strict
  decoder is written from the backend's documented wire format, NOT copied
  from the connector. Where the documented format permits several readings the
  target states which reading it takes; a disagreement on a legitimately
  ambiguous reading is classified `expected`, not hidden.
- O6 LIVENESS (anti-vacuity). The pristine program must succeed and return the
  exact expected value. A target whose control fails is invalid and reports
  `HARNESS` rather than passing.
- O7 NO-LEAKAGE. A synthetic canary (`kx-hostile-canary-...`) placed in hostile
  response fields, and the credential the connector sent, must not appear in
  the returned error text or in captured `log`/`slog` output (`slog.Default`
  is captured; connectors with a private logger are best effort and noted).
- O8 BOUNDED-RETRIES. Requests to the fake backend per call are at most the
  target's declared ceiling (vault 3, JWKS 3, Kubernetes TokenRequest 3,
  Keyorix fetcher 64: a pagination walk longer than 64 pages for a 1-page
  listing is a failure). Repeated pagination tokens / huge `total_pages` count.
- O9 SSRF-ISH. A sentinel server standing for an internal address receives
  zero requests: connectors that declare "never follow redirects" must not
  follow any redirect; connectors that follow same-origin redirects (JWKS)
  must not follow cross-origin ones. Response-controlled URLs are not
  followed. Note: loopback sentinel means this tests redirect policy, not
  address filtering; do not generalise to "SSRF-safe".

## Planted defects (harness validity)

`selftest_test.go` implements toy clients, each with ONE planted defect, plus a
correct control, and requires:

- every planted defect detected by the oracle named in the table below, by a
  directed program AND reported with random-program detection rate;
- the control silent over the same random budget (0 violations).

| id | defect | expected oracle |
|----|--------|-----------------|
| P1 | 200 with missing field returned as empty success | O5 |
| P2 | unchecked type assertion on hostile JSON | O1 |
| P3 | unbounded pagination on repeated token | O8 |
| P4 | follows redirects to attacker address | O9 |
| P5 | error echoes response-controlled secret-like field | O7 |
| P6 | body read error ignored, partial body accepted | O5 |
| P7 | ignores caller context, 30 s client timeout | O2 |
| P8 | goroutine left blocked on failure | O3 |
| P9 | unbounded decompression of gzip response | O4 / O2 |

If a planted defect is not detected, the harness is broken and no campaign
result may be reported as a negative.

## Finding discipline

Each failing input is minimised, replayed at least 3 times from the saved
corpus file, then classified as one of: KEYORIX-BUG, SDK-BUG, EXPECTED
(documented behaviour; note why), HARNESS-ARTIFACT. Security-relevant findings
are recorded only in the private notes file, never in this repository.

## Amendments after the pre-registration commit

Each amendment states what changed and why. None relaxes an oracle to hide a
finding; findings that were reclassified are in the private findings log.

1. O2 slack 1 s -> 4 s. The first campaign hour produced two O2 reports on
   PRISTINE programs (the control path) while the rig host was saturated by
   other jobs; a pristine run cannot hang by construction. The call still gets
   a 500 ms context deadline, and a connector that ignores it (the planted
   P7) is still caught.
2. Duplicate member names. RFC 8259 leaves a JSON object with repeated names
   undefined. Strict decoders skip VALUE-level assertions on a body that has
   duplicate names (`hostile.HasDuplicateKeys`); delivery, status, bounded-work,
   leak, retry and redirect oracles still apply. Reason: a decoder that treats
   `null` as "unset" and one that treats it as "assign" disagree on
   `{"v":"2","v":null}` and both are defensible.
3. `Delivery` classifies a success on an exchange whose transport ended in an
   error AFTER the whole body arrived (declared length longer than sent,
   unterminated chunked body, corrupt gzip trailer) as
   `O5/transport-error-ignored`, separate from `O5/incomplete` (content missing).
   Reason: the first classification lumped both together.
4. `Config.Retries`: for connectors whose SDK or code retries, a success is
   judged on the last exchange only. Earlier failed attempts are expected.
5. `KX_HOSTILE_ALLOW`: suppresses already-triaged violation classes so the
   native fuzzer (which stops at its first failure) can keep exploring. Every
   suppressed hit is still printed as `HOSTILE-KNOWN`.
6. The census ignores goroutines the runtime or the test driver start once and
   keep (`os/signal`, `testing`, pprof, internal/fuzz).
7. O3 poll window 1.2 s -> 4 s. One O3 report (vault target, 4 KB string in
   the secret response) did not reproduce in three standalone replays and
   appeared while the host was saturated; goroutine teardown simply lagged.
   A genuine leak (planted P8) is still caught.
8. Pristine programs get 10x the call deadline. Two O6 (liveness) reports in
   the first hour were pristine calls that hit the 500 ms deadline because the
   rig host was saturated (the request had not even reached the server). A
   pristine run has no injected delay, so a deadline there measures the
   scheduler. Faulted programs keep 500 ms; their oracles are one-directional
   (a starved call turns into an error, which is fail-closed, not a finding).
9. No-response replay (harness bug fix). An exchange closed before a single
   response byte (fault `accept-close`, `Served.NoResponse`) that is followed by
   another exchange on the same route is not a consumed response: net/http
   replays an idempotent request on a reused connection in exactly that case,
   without telling its caller. `Delivery`/`Intact` skip it, and O8 discounts at
   most one such exchange per route. The LAST exchange of a route is never
   skipped, so a success resting on no response still fails O5, and a retry
   loop against an always-closing backend still fails O8 (both checked in
   `known_selftest_test.go`, with red proofs). Found as a Vault `O5/incomplete`
   on `fault=accept-close` (input f11e126cb1ecdb99), where the connector itself
   never retries.
10. `Config.Known`: a target may list triaged, still-open findings with a stable
    ID. A violation is suppressed only when its text starts with the entry's
    Prefix and the optional ErrContains/When narrowing holds; every suppressed
    hit is printed as `HOSTILE-KNOWN[<id>]`, and any other violation in the
    same run is still reported. Each entry has a reproducer test
    (`RequireKnownReproduces`) that goes red when the finding is fixed. This is
    the reviewed in-repo form of `KX_HOSTILE_ALLOW`; entries carry low-severity
    (HARDENING) findings only. Anything security-relevant stays in the private
    findings log, as above.
11. Webhook O8 ceiling 4 -> 12 (harness bug fix). The ceiling counts HTTP
    requests, but the target declares same-host redirects as permitted
    (`AllowRedirect`), and the sink declares `maxAttempts` (4) attempts of up
    to `maxRedirectHops` (3) requests each. The ceiling is now that product,
    taken from the constants. Input 2ab4f73abe7a5198 (`occ=1 status=599
    redirect=same-origin-once-307`, 8 requests) is legal behaviour under both
    declared bounds. Not verified: that 4 x 3 is a sensible bound (that is a
    product decision); that a redirect the sink refused is not retried (it is,
    see the report).
12. Mutated JSON bodies are capped at an estimated 8 MiB (harness bug fix).
    Ops compose multiplicatively and the harness builds the body inside the
    call under test, so its own allocations counted against the connector's
    O4 budget (webhook input 38e9be5f2bd5c91b: 379 MB allocated while the
    server wrote 0 bytes; the webhook never reads the body). An op that would
    take the tree past the cap, and every op after it, is dropped; list growth
    is refused before it is built. The largest single huge string (4.3 MB)
    still gets through. Coverage given up: no mutated JSON body above ~8 MiB
    is served, so a connector read limit above 8 MiB (the largest is 10 MiB)
    is no longer exceeded by a JSON program; the gzip bomb still exercises
    decompressed size past every limit.
13. The mutated body is built once per valid body per Harness (harness bug
    fix). With `occ=1` every request rebuilt it inside the call under test:
    webhook input 0e24d7c1f647b37a (60000-element list, self-loop-307, 12
    requests) reported O4 at 289,613,520 bytes, which is 12 x the 24.1 MB one
    build allocates, while the server wrote 2 KB. Bodies are byte-identical to
    before; only the rebuilds are gone.
14. `O5/bad-status-accepted/2xx-valid-body` (tightening). The AWS SM,
    Kubernetes and fetcher targets judge a success on a final 2xx that is
    not in their documented set (200, or 200/201) like a documented one: every
    value check still runs, and a success that passes all of them on complete
    bodies carries this sub-tag. Any other status acceptance is still plain
    `O5/bad-status-accepted`. The fetcher previously skipped all value checks
    on such a 2xx; it no longer does.
