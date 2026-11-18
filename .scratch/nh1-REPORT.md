# NH1 — report (K10 xml-roundtrip-validator contract differential; K12 timing measurement)

Branch `fuzz/nh1-xmlrt-timing`, standalone clone `/mnt/data/wave4/nh1` on pve01.
Commits land via a linked worktree (`.claude/worktrees/wt`) because the write-guard forbids
committing in the shared checkout; the branch ref advances normally. No production code changed.
Primary report at `/mnt/data/wave4/out/nh1-REPORT.md`; this is the branch-committed copy.

## Reading of the task (unattended; stated and carried on)

- **K10**: "the validator's accept/reject versus a round trip through encoding/xml (parse,
  re-serialise, parse)" → a differential fuzz target whose oracle is the validator's **own
  documented contract**. `go doc github.com/mattermost/xml-roundtrip-validator`:
  *"Validate makes sure the given XML bytes survive round trips through encoding/xml without
  mutations"* and *"CheckToken … returns an error if the newly calculated token differs from
  the original"*. So: `xrv.Validate(data)==nil` **⟹** an independent encoding/xml round trip
  (parse → re-serialise → parse) leaves the document's **element skeleton** and the
  **xml.Unmarshal view** (what the SAML path consumes) unchanged. Additive to the existing
  oracle X1 (see "no prior coverage").
- **K12**: a standalone documented tool under `scripts/`, never in CI, running a dudect-style
  two-class (equal-prefix vs random) leakage test over the live secret-comparison sites, with
  ≥200k interleaved measurements, Welch's t, host-noise caveats, and a 3-run stability bar for
  any finding.

## Result summary

| item | deliverable | status |
|------|-------------|--------|
| K10 | `internal/libconformance/xml_roundtrip_contract_fuzz_test.go` (`FuzzXMLRoundtripContract`, oracle RT1) + red/green proof + INVARIANTS fragment | **built, red/green proven, 63 min fuzz, 0 crashes** |
| K12 | `scripts/timing-constant-time/` (manual tool + README) | **built, 12 sites measured, 3 stable runs, no finding** |

No VULNERABILITY / CANDIDATE / SECURITY-DEFECT found. Classification of both outcomes:
**EXPECTED** (K10: validator honours its contract on every input fuzzed so far; K12: every
measured site is constant-time consistent). See LEFTOVERS for the honest bounds.

---

## K10 — xml-roundtrip-validator contract differential

### Grep: no prior coverage

`xrv.Validate` / `mattermost/xml-roundtrip-validator` call sites:
- `internal/saml/provider.go:534` — the **live guard** (before crewjam unmarshals IdP metadata).
- `internal/libconformance/xml_parser_differential_fuzz_test.go` — **oracle X1**: compares a
  beevik/etree parse against an encoding/xml **parse** of the *same* bytes. No re-serialise.
- `internal/libconformance/xml_parser_differential_redproof_test.go` — X1 red/green.
- `internal/libconformance/etree_roundtrip_fuzz_test.go` — beevik/**etree** parse→serialise→parse
  idempotence; not encoding/xml and not gated on the xrv verdict.
- `internal/saml/response_differential_fuzz_test.go` (R3) + other SAML fuzzers — drive
  `ParseResponse` / signature provenance (S1/S2/S3); none assert the round-trip contract.

None performs the encoding/xml **re-serialise** round trip gated on the validator's verdict.
K10 is additive.

### What the target does

`FuzzXMLRoundtripContract` (oracle RT1), for each input, gates on `xrv.Validate` and asserts:
1. **element-skeleton stability** — the ordered, depth-tagged sequence of element local names is
   identical before and after the encoding/xml round trip. This is the **overflow detector**: a
   token that re-serialises into *extra* elements (the SAML signature-wrapping primitive xrv
   exists to block), or a dropped/renamed/renested element, changes it.
2. **unmarshal-view stability** (the SAML-path tie-in) — `xml.Unmarshal` into a generic
   recursive element (local name + attribute name=value + text + children — the information
   crewjam's structs are populated from) yields the identical structure before and after
   re-serialisation.
3. **re-serialised bytes still parse** — if the round trip destroys well-formedness, that is a
   forbidden mutation.

A violation xrv **accepted** is reported as a VALIDATOR-CONTRACT-VIOLATION CANDIDATE.

### Harness bug found at first contact, fixed (did not weaken the oracle)

The first comparator used strict RawToken token-stream equality. It false-fired on the valid,
extremely common SAML construct `<x:a xmlns:x="urn:x"/>`, which xrv correctly **accepts**:
Go's `encoding/xml` cannot round-trip a namespace *prefix* through RawToken→Encoder→RawToken
(`<x:a>` re-serialises as `<a xmlns="x" xmlns:_xmlns="xmlns" _xmlns:x="urn:x">`), and the
validator itself papers this over with its unexported `fixNamespacePrefixes` before comparing.
Reproducing that limitation would be a harness bug, not a Keyorix finding (and namespace
*skeleton* agreement is already X1's job). Fix: the firing views are the **namespace-robust
element skeleton** and the **semantic unmarshal view**; prefix re-spelling and adjacent-CDATA
coalescing are catalogued representational differences (RT-E1/RT-E2), exactly as X1 catalogues
N1/N2/N3. A 38-vector probe confirmed **zero false positives** under the fixed views while the
raw-token comparator still saw (and was correctly suppressed on) the known-benign classes.

### Red/green proof (`xml_roundtrip_contract_redproof_test.go`, `default-ci`)

- `TestXMLRoundtripContract_Baseline` — GREEN: a genuine SAML Response is accepted by xrv and is
  element-skeleton- and unmarshal-stable across the real round trip; the oracle is quiet.
- `TestXMLRoundtripContract_RedProof_ComparatorFiresOnInjection` — RED: with the xrv gate stubbed
  open and a re-serialiser that forges a duplicate `<saml:Assertion>` (token-level XSW overflow),
  the oracle **fires**; the shipped path (real encoding/xml) is quiet on the same input, so the
  fire is attributable to the planted overflow, not the harness. (The injection is at the token
  level, independent of namespace re-spelling.)
- `TestXMLRoundtripContract_RedProof_XRVGuardLoadBearing` — for a namespace-collision document
  xrv **rejects**, the shipped oracle short-circuits (accepted=false, no finding), while the same
  bytes under the accept-all stub + injection **do** fire — proving the xrv verdict is the
  load-bearing gate.

All three pass; the `FuzzXMLRoundtripContract` seed corpus passes under `go test`.

### Fuzzing performed

Foreground 540 s (9 min) chunks, `-parallel 2`, `GOMAXPROCS=2`, `nice -n 10`, caches on
`/mnt/data/wave4`. **63 minutes of real fuzz wall time, 0 crashes.**

| chunk | wall | result |
|-------|------|--------|
| 1 | 541.6 s | PASS |
| 2 | 541.6 s | PASS |
| 3 | 542.6 s | PASS |
| 4 | 541.8 s | PASS |
| 5 | 541.6 s | PASS |
| 6 | 541.6 s | PASS |
| 7 | 541.8 s | PASS |

**Total 7 × 9 min = 63 min real fuzz wall time, ~27 M executions, 0 crashes.** Corpus grew to
662 interesting inputs with no crasher.

### What oracle RT1 does NOT verify

- **Namespace semantics.** It folds names to local names and drops xmlns declarations (RT-E2),
  because encoding/xml cannot round-trip a prefix and the validator treats that as equivalent.
  A namespace-confusion divergence is **oracle X1's** scope, not RT1's.
- **Attribute order, insignificant whitespace, adjacent-CDATA coalescing** (RT-E1) — normalised.
- **Text / attribute-value changes** are caught by the unmarshal view but compared after XML
  entity decoding, so a purely *representational* re-escaping (`&gt;`↔`>`) is not a finding.
- **One encoding/xml configuration** (Strict=false, identity charset, a single whole-document
  `xml.Encoder`). An encoder that *refuses* a token (e.g. a mid-stream `<?xml?>` ProcInst) is
  treated as "cannot round-trip → nothing to assert", not a finding.
- **Entities / DOCTYPE** are never expanded by encoding/xml, so that class is closed by
  construction, not checked.
- It is a **pure-parser** oracle: no crewjam, no keys, no signature. The signature-wrapping
  provenance checks live at the SAML layer (S1/S2/S3), unchanged.
- Fuzzing is **bounded coverage**: absence of a crash over ~27 M executions is evidence, not
  proof, that the validator honours its contract for all inputs.

---

## K12 — constant-time secret-comparison timing measurement

### Compare-site inventory (grep)

Direct secret comparisons (presented value compared against a stored secret):

| # | site(s) | primitive |
|---|---------|-----------|
| 1 | `server/http/router.go:1645` (metrics bearer), `operator/cmd/main.go:214`, `internal/k8ssync/health.go:139` | `subtle.ConstantTimeCompare` |
| 2 | `internal/core/rules/scim_token.go:95`, `server/middleware/scim.go:28` (SCIM token) | `subtle.ConstantTimeCompare` |
| 3 | `server/middleware/csrf.go:54` (CSRF) | `subtle.ConstantTimeCompare` |
| 4 | `internal/core/auth_bootstrap.go:271` (bootstrap token) | `subtle.ConstantTimeCompare` |
| 5 | `internal/core/mfa.go:828` (MFA/TOTP code) | `subtle.ConstantTimeCompare` |
| 6 | `internal/recoverykey/recoverykey.go:141` (recovery-key hash) | `subtle.ConstantTimeCompare` |
| 7 | `internal/core/secrets.go:765` (rotation no-op value equality) | `subtle.ConstantTimeCompare` |
| 8 | `internal/core/audit_seal.go`, `internal/auditverify/seal.go:109`, `audit_key_transition.go`, `checkpoint.go`, `retention.go`, `verifystate.go` (audit MACs) | `hmac.Equal` |
| 9 | `internal/backupfmt/manifest_sign.go:73` (backup manifest MAC) | `hmac.Equal` |
| 10 | `internal/core/evidence_signing.go:98` (evidence MAC) | `hmac.Equal` |
| 11 | `internal/pqwrap/keyset.go:299,304,485,515`, `internal/crypto/shamir_provider.go:110`, `internal/crypto/azurekms/azurekms.go:314` (keyset/KCV/KEK MACs) | `hmac.Equal` |
| 12 | `internal/core/auth.go:76`, `internal/core/account.go:123,423,596,612`, `mfa.go:1002` (password) | `bcrypt.CompareHashAndPassword` |

**Not comparison sites (no raw-secret timing surface):**
- **PAT / machine-identity tokens** — verified by SHA-256 hashing the presented token and
  **looking it up by hash in the DB** (`GetPersonalAccessTokenByHash`,
  `GetMachineIdentityCredentialByHash`, via `sha256Hex(raw)` in `internal/core/pat.go`,
  `machine_token.go`). No byte comparison of the raw token exists to time. (The auth cache is
  likewise keyed on the SHA-256 hash.)
- **Webhook signing** (`internal/config/config_notifications.go`, `KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET`)
  is **outbound** — Keyorix signs the notifications it sends; there is no inbound
  webhook-signature *verification* path, so no attacker-driven comparison to time.

### Tool

`scripts/timing-constant-time/` (`main.go` + `README.md`), `package main`, never invoked by
`go test` and never in CI. For each site it times the **exact leaf comparison** the production
code uses (`subtle.ConstantTimeCompare`, `hmac.Equal`, `bcrypt.CompareHashAndPassword` — the
same functions, at a representative secret length), under two interleaved classes: **A =
equal-prefix** (differs only in the last byte) and **B = random** (same length, differs near the
front). Welch's two-sample t on the cropped per-batch samples; outliers above the 99th
percentile dropped; `nice -n 19`, `GOMAXPROCS=1`, batching of 400 comparisons per timed sample
to beat the Go monotonic-clock overhead.

### Results — 3 runs, n = 250 000 per ct/hmac site, bcrypt n = 500 at cost 12

All |t| are small and sign-unstable across runs (the hallmark of host noise around a true zero),
and **every site is `ok` in all three runs**. Max |t| observed anywhere: **2.86**. Threshold for
even a *borderline* flag is 4.5; for a *potential leak*, 10. No site is a finding.

| site | prim | len | run1 t | run2 t | run3 t | verdict (stable) |
|------|------|-----|--------|--------|--------|------------------|
| api-bearer-token | ct | 43 | -1.08 | -0.90 | 0.25 | ok |
| scim-token | ct | 43 | -0.79 | 0.75 | -0.62 | ok |
| csrf-token | ct | 64 | 1.54 | -0.74 | 1.12 | ok |
| bootstrap-token | ct | 43 | -1.38 | -0.84 | 2.64 | ok |
| mfa-totp-code | ct | 6 | -0.07 | -0.16 | 1.27 | ok |
| recovery-key-hash | ct | 64 | -1.11 | 0.43 | 0.12 | ok |
| secret-rotation-noop | ct | 32 | -0.76 | -1.76 | -0.20 | ok |
| audit-seal-mac | hmac | 64 | 0.61 | 0.73 | -0.74 | ok |
| backup-manifest-mac | hmac | 64 | -0.87 | -0.54 | 0.61 | ok |
| evidence-signing-mac | hmac | 32 | -2.86 | -2.56 | -0.07 | ok |
| keyset-kcv-mac | hmac | 32 | -0.60 | -1.78 | -1.00 | ok |
| password-bcrypt | bcrypt | — | 0.86 | -0.81 | -0.72 | ok |

Raw logs: `.scratch/k12-run{1,2,3}.txt` (and `k12-run1.txt`).

**Verdict: all measured secret-comparison sites are constant-time consistent. No finding.**
Expected: every site already uses a constant-time primitive (`subtle.ConstantTimeCompare` /
`hmac.Equal` are content-independent by construction; bcrypt hashes the full password and
compares fixed-width digests), so the measurement calibrates that property rather than
discovering a new one.

### What K12 does NOT verify

- **It measures the leaf primitive, not the live request path.** It replicates the exact
  comparison in isolation; it does **not** exercise the surrounding handler, DB lookup, cache,
  or network. Timing channels *above* the comparison are out of scope: e.g. an early `len==0`
  short-circuit before the compare (seen at `server/middleware/scim.go:28`, the bearer checks),
  a DB lookup whose latency depends on whether a token row exists (a user/credential-enumeration
  oracle), or a branch that only runs for valid principals.
- **bcrypt is under-powered** — measured at n=500 (250/class), not 200k, because a single compare
  at cost 12 is ~230 ms (200k ≈ 13 h). Content-independence is structural, so this catches only a
  gross regression. See LEFTOVERS.
- **No CPU pinning in the automated runs.** `taskset` is present on the host but the agent harness
  rejects it as a non-analyzable command; runs used `nice -n 19` + `GOMAXPROCS=1` only. The README
  documents the recommended `taskset -c <core>` invocation for a manual operator.
- **Snapshot, not invariant.** A green result is valid for this binary/host/moment; it is
  deliberately not a CI gate. The durable guarantee is that the sites *call* the constant-time
  primitives — a code fact, not a timing fact.
- **`len`-dependence is held constant, not tested.** Both classes use equal length, so the
  (documented) early return of `ConstantTimeCompare` on a length mismatch is not exercised.

---

## Ranked LEFTOVERS

1. **bcrypt timing is under-powered (K12).** 250 samples/class at cost 12 vs the 200k bar. A
   dedicated long run (overnight, pinned, n≈20k) or measuring at a fixed lower cost with a
   documented extrapolation would close it. Low risk: bcrypt's content-independence is structural.
   *(HARDENING / coverage.)*
2. **Timing channels above the leaf compare are unmeasured (K12).** Highest-value remaining
   question: **credential/user enumeration via DB-lookup latency** (PAT/machine-token hash lookup,
   login user-exists branch) and **early-return short-circuits** before the constant-time compare.
   A request-level timing harness (drive the actual handler with valid-vs-invalid tokens) is the
   right instrument; out of scope for a leaf probe. *(CANDIDATE class to investigate — not a
   finding here.)*
3. **RT1 is single-configuration (K10).** It does not model crewjam's Strict-default unmarshal or
   goxmldsig's etree C14N re-serialise. A round trip through *goxmldsig's* canonicalizer (the
   bytes the signature actually covers) vs the unmarshal view would be a stronger, SAML-specific
   oracle — closer to a real XSW than the pure-parser contract check. *(Next target.)*
4. **RT1 catalogues namespace/CDATA differences rather than asserting over them (K10).** If a
   future encoding/xml change made a *namespace* round-trip genuinely lossy in a way X1 doesn't
   cover, RT1 would stay quiet by design. Periodically re-confirm X1 still covers the
   namespace-skeleton class. *(Low.)*
5. **No conformance-ledger row filed for RT1.** The `INVARIANTS.d/INV-LIBCONF-xml-roundtrip-contract.md`
   fragment IS filed (this session). A `docs/adr-conformance-enforced.tsv` row is discretionary
   (RT1 is a library-property fuzz target, no incident). *(Housekeeping.)*

> Note on the statemap fragment guard: `go test ./internal/statemap/` from this checkout reports
> LEGACY-DUPLICATE / missing-index-row failures, **all** naming `.claude/worktrees/wt/...` paths —
> the linked commit-worktree duplicating files during the filesystem walk. None names the new
> fragment or `internal/libconformance`. CI (no worktree) is unaffected; the worktree is removed
> at session end.

## Commits on this branch (append-only, not pushed)

- `b82db8a65e` — K10 target + red/green proof.
- `245ef30c47` — K12 tool + README.
- _(final)_ — this report + K10 INVARIANTS fragment (SHA printed at end of session).
