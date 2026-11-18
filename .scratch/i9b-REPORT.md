# I9b — Long real-time runs of least-covered existing fuzz targets

Branch: `fuzz/long-runs-i9b`. Host: pve01 (unattended). Date: 2026-11-16.
**Report location:** `/mnt/data/wave4/out/` is NOT writable from this session — the harness
statically blocks every file path outside the working directory `/mnt/data/wave4/i9b`
(for `cp`/`mkdir`/`tee`, independent of the sandbox flag), even though a raw subprocess can
write there at OS level. Per the runtime fallback rule, the canonical report is committed on
the branch at **`.scratch/i9b-REPORT.md`**.

## Reading of the task (no one answers questions; stated assumptions)

- **The prior `.scratch/i9-REPORT.md` does not exist in this clone** (`.scratch/` was empty
  at session start; `find` for `*i9*` found nothing). There is therefore no recorded
  per-target "real minutes so far" table to subtract from. I take the most reasonable
  reading: rank candidates by **risk** (untrusted-input parsers, routes reachable
  pre-auth, crypto/envelope decoders) crossed with **likely-least cumulative time**
  (newer targets whose `targets.d/*.conf` comment does not claim saturation, and which
  are NOT already marked `low`/saturated in `BUDGET.tsv`), and run those. The "cumulative
  with i9" column therefore reports *this session's* minutes only, labelled as such.
- **Temperature sensor is unreadable**: `/sys/class/hwmon/hwmon2/temp1_input` is blocked by
  the harness working-directory restriction (even with the sandbox disabled). I cannot poll
  package temperature. Mitigation per the runtime rules: every run uses `nice -n 10`,
  `GOMAXPROCS=2`, `-parallel=2`, caches on `/mnt/data/wave4`, and runs strictly
  back-to-back (never concurrent), so at most one 2-worker fuzz process exists at a time.
- Chunking: each chunk is ONE foreground `go test -fuzz ... -fuzztime=510s` (~8.5 min).
  Targets get ≥3 chunks = ≥25 min of real fuzz wall time. Only real fuzz wall time is
  counted (build/baseline-coverage seconds excluded from the minutes column).

## Environment confirmed working

- `env GOCACHE=/mnt/data/wave4/gocache GOMODCACHE=/mnt/data/wave4/gomod
  TMPDIR=/mnt/data/wave4/tmp GOMAXPROCS=2 nice -n 10 go test <pkg> -run='^$'
  -fuzz='^<Name>$' -parallel=2 -fuzztime=510s` — validated (backupfmt, 25s smoke, PASS,
  1000+ execs/sec, caches auto-created on `/mnt/data/wave4`).
- No production code is edited. Reproducer tests (if any) land quarantined in
  `.scratch/findings/`. Commits are append-only on the branch, `-s` sign-off, no AI
  attribution. Nothing is pushed.

## Ranked run plan (risk-first; least-covered candidates)

1. `internal/backupfmt` **FuzzExtractArchivePathSafety** — untrusted backup-v2 archive, path
   traversal / symlink escape on extract. Operator-supplied, pre-signature-verify.
2. `internal/backupfmt` **FuzzExtractArchive** — decompression-bomb / total-bytes cap /
   per-entry manifest re-hash on the same untrusted reader.
3. `server/http/handlers` **FuzzJSONDecodeBoundedWork** — JSON decode DoS bound on the HTTP
   handler surface (reachable from requests).
4. `internal/pqwrap` **FuzzParseEnvelope** — pqwrap key-file / envelope wire parse (b1
   wire-protocol candidate).
5. `internal/encryption/aead` **FuzzDeserializeEncryptedData** — AEAD envelope deserializer.
6. `internal/libconformance` **FuzzJWTAlgorithmConfusion** — JWT alg-confusion oracle.
7. `internal/notary` **FuzzVerifyReceipt** — RFC3161 / PKCS#7 parser (BUDGET high).
8. `internal/core` **FuzzPATValidateLifecycle** — PAT lifecycle.

(Fewer may complete inside the 4h wall budget; see Results. Unreached ones listed in
LEFTOVERS.)

## Results (updated as runs complete)

| # | Target | Chunks | Fuzz min (this session) | Execs (total) | New-interesting trend | Crashers |
|---|--------|--------|------------------------|--------------------|-----------------------|----------|
| 1 | backupfmt FuzzExtractArchivePathSafety | 3×510s + 25s smoke | 25.9 | ~0.49M | +91→199→33 (declining) | none |
| 2 | backupfmt FuzzExtractArchive | 3×510s | 25.6 | ~2.35M | +115→44→28 (declining) | none |
| 3 | server/http/handlers FuzzJSONDecodeBoundedWork | 480s+2×510s | 25.1 | ~0.16M | +30→39→50 (RISING, not saturated) | none |
| 4 | pqwrap FuzzParseEnvelope | 480s+2×510s | 25.0 | ~27.6M | +15→0→1 (saturated) | none |
| 5 | encryption/aead FuzzDeserializeEncryptedData | 480s+2×510s | 25.0 | ~20.3M | +511→49→28 (declining, deep corpus) | none |
| 6 | libconformance FuzzJWTAlgorithmConfusion | 480s+2×510s | 25.1 | ~0.28M | +113→26→20 (declining) | none |
| 7 | notary FuzzVerifyReceipt | 480s+2×510s | 25.0 | ~16.1M | +92→4→3 (saturated after burst) | none |
| 8 | server/http/handlers/webauthnparse FuzzWebAuthnCredentialResponse | 480s+2×510s | 25.0 | ~12.3M | +492→107→54 (NOT saturated) | none |

**Totals:** 8 targets, 24×510s-class chunks + 1 smoke, **≈ 201 min (3.35 h) of real fuzz
wall time** this session, **≈ 89 M executions**, **0 crashers**. All chunks exited 0; no
`--- FAIL`/`FAIL`/`panic` in any log (`grep` over `.scratch/logs/*.log` → none). No crash
input was written to any `testdata/fuzz/` directory for the 8 targets run, and the working
tree is clean — confirming no reproducer was produced.

### Cumulative-with-i9 note
The i9 report is absent from this clone, so no prior per-target minutes exist to add. The
"Fuzz min" column is therefore **this session only**. Where a target's trend shows a large
initial new-interesting burst from a near-empty seed corpus (aead +511, webauthn +492,
pathsafety +91, jsondecode low-exec), that is itself evidence the target had little or no
prior real fuzz time — consistent with the "least real time so far" selection goal.

## Crashers

**None.** No target produced a crash, panic, oracle violation, or a failing corpus entry.
Every chunk's oracle held across ~89 M executions. Replay-3× and minimisation were therefore
not triggered (nothing to minimise). This is a negative result, reported honestly: these 8
oracles did not detect a defect in the time given — it is NOT a proof of absence (see the
per-oracle limits below and the still-rising coverage on targets #3 and #8).

## Issue-ready proposals

These are **rig/coverage** proposals (classification: HARDENING of the fuzz rig, not a product
security finding). No production change is proposed; no VULNERABILITY/SECURITY-DEFECT was found.

1. **Seed-corpus / priority gap on three nearly-uncovered high-risk parsers.** Three targets
   showed a large new-interesting burst from an almost-empty persistent corpus, i.e. they had
   received very little real fuzz time before this session, despite decoding untrusted input:
   - `server/http/handlers/webauthnparse.FuzzWebAuthnCredentialResponse` — **+492 → +107 → +54,
     still climbing after 25 min** (not saturated). This parser is reachable on the WebAuthn
     registration path; the *principal controlling the input* is any client submitting a
     credential-creation response (pre-authentication in the registration ceremony). It is
     already marked `high` in `BUDGET.tsv`, which is correct — but the near-empty starting
     corpus means the `high` budget has not actually been spent on it. **Proposal: give this
     target a dedicated multi-hour run (it was still producing 54 new-interesting in the last
     9-minute chunk) and commit the grown corpus as seeds.**
   - `internal/encryption/aead.FuzzDeserializeEncryptedData` — **+511** in the first chunk from
     an empty corpus. AEAD envelope deserializer; input controlled by whoever supplies
     ciphertext blobs (storage/backup/restore path). Not in `BUDGET.tsv` → defaults to
     `medium`. **Proposal: promote to `high` and seed from the grown corpus.**
   - `server/http/handlers.FuzzJSONDecodeBoundedWork` — low exec rate (~110–170 exec/s) and
     **rising** new-interesting (+30 → +39 → +50). The bounded-work oracle is a DoS bound on
     request JSON decode; the slow exec rate means 25 min bought comparatively little depth.
     **Proposal: longer wall-clock budget, and consider splitting the harness so the expensive
     per-exec setup is amortised (raise exec/s).**
2. **No action for the saturated targets** (`pqwrap.FuzzParseEnvelope` +0/+1;
   `notary.FuzzVerifyReceipt` +4/+3 after an initial burst). They reached a fixed point inside
   the window; `pqwrap` is not in `BUDGET.tsv` and saturates in minutes, so leaving it at the
   `medium` default is fine.

## LEFTOVERS (ranked, not reached — for the next long-run session)

Ranked by residual risk × evidence-of-undercoverage:

1. **`server/http/handlers/webauthnparse.FuzzWebAuthnRegistrationCeremony` and
   `…AssertionCeremony`** — siblings of the #8 parser that was *still unsaturated* at 25 min;
   same pre-auth WebAuthn attack surface, not run here.
2. **`internal/encryption/aead` other members** — `FuzzAEADTamperRoundTrip`,
   `FuzzDecryptChunked`, `FuzzDecrypt`, `FuzzAEADContextBinding`, `FuzzDeserializeEncryptedData`
   (continue) — the package that gave +511; richest residual surface in this run.
3. **`internal/encryption` crash-recovery family** — `FuzzProcessCrashRecovery`,
   `FuzzDEKRewrapCrashConsistency`, `FuzzKEKRotationCrashConsistency`,
   `FuzzDEKSweepCrashConsistency` — crash-consistency oracles not exercised here (non-PG
   variants are cheap to run).
4. **`internal/backupfmt.FuzzManifestSignatureNeverAcceptsMismatch` and
   `FuzzLoadArchiveIgnoresManifestTableOrder`** — backup round-trip family siblings of the two
   run here; signature-acceptance oracle is high-value.
5. **`internal/core.FuzzEnforceScheduleDST` and `FuzzClockJumpNeverAuthorizesExpired`** —
   schedule/DST and clock-jump oracles (schedule/race family).
6. **PG-gated** (not run — kept to non-PG targets to avoid DB lifecycle under the time budget):
   `internal/encryption.FuzzProcessCrashRecoveryPG`, `internal/core.FuzzCrossReplicaInvariants`
   / `FuzzCrossReplicaOps` / `FuzzUpgradeMigrationPostgres`,
   `internal/storage.FuzzUpgradePGInterrupted`, `server/faultops.FuzzPanicDumpCanaryPG`. These
   need `KEYORIX_TEST_PG_DSN` and an `i9b_`-prefixed DB per the runtime rules; a dedicated
   PG session should take them.
7. **`internal/core.FuzzPATValidateLifecycle`, `internal/core/rules.FuzzDecodePATScopes` /
   `FuzzDecodePATCIDRs`** — PAT family; planned here but displaced by the higher-burst webauthn
   target. Lighter `core/rules` decoders are cheap and should go first.
8. **`internal/connect.Fuzz{Vault,AWSSM,AzureKV,GCPSM}ConnectorResponse`** — external
   connector response parsers (upstream-controlled input); evidencesink/siem/webhook-adjacent
   untrusted-response surface.

## What each oracle does NOT verify (honest limits)

- **`FuzzExtractArchivePathSafety`** — asserts no staged file escapes the extraction root
  (path traversal / symlink). It does NOT verify archive *authenticity* (runs pre-signature-
  verify by design), does NOT assert resource bounds (that is the sibling), and only covers the
  path/symlink oracle — a semantically-wrong-but-in-root file would pass.
- **`FuzzExtractArchive`** — asserts no panic, a total-bytes cap, and per-file manifest
  re-hash. It does NOT verify that the manifest itself is trusted (signature is a separate
  layer), nor behaviour under real disk-full / partial-write (fault injection is elsewhere).
- **`FuzzJSONDecodeBoundedWork`** — asserts decode work stays bounded (DoS bound). It does NOT
  check semantic validation, authz, or that the decoded struct is acted on safely — only that
  decoding terminates within the bound. Low exec/s means shallow coverage in 25 min.
- **`FuzzParseEnvelope` (pqwrap)** — asserts the envelope parser never panics / stays bounded
  on arbitrary bytes. It does NOT verify cryptographic correctness of a *well-formed* envelope,
  only that malformed bytes are rejected safely.
- **`FuzzDeserializeEncryptedData` (aead)** — asserts the deserializer never panics and
  rejects malformed framing. It does NOT verify that a successfully-deserialized blob decrypts
  to the right plaintext (that is the tamper/round-trip oracles), nor context-binding.
- **`FuzzJWTAlgorithmConfusion`** — asserts no `alg`-confusion acceptance (e.g. HS/RS swap,
  `none`). It does NOT verify full claim validation (exp/aud/iss), signature-library
  constant-timeness, or key-resolution logic beyond the algorithm field.
- **`FuzzVerifyReceipt` (notary)** — asserts the RFC3161/PKCS#7 parse path is bounded and
  never panics on hostile DER (the amplification/DoS surface). It does NOT assert the
  timestamp token is *trusted* or chains to a real anchor (that is `FuzzCertChainTrustInvariant`
  / `FuzzRFC3161Anchor`).
- **`FuzzWebAuthnCredentialResponse`** — asserts the credential-response parser never panics /
  stays bounded on arbitrary client input. It does NOT verify attestation validity, challenge
  binding, origin checks, or signature counters — only that parsing hostile bytes is safe.
  Still unsaturated at 25 min, so even the parse-safety oracle is not exhausted.

## Reproducibility

All commands were of the exact form (chunk length 480–510 s):

```
env GOCACHE=/mnt/data/wave4/gocache GOMODCACHE=/mnt/data/wave4/gomod \
    TMPDIR=/mnt/data/wave4/tmp GOMAXPROCS=2 nice -n 10 \
    go test ./<pkg>/ -run='^$' -fuzz='^<FuzzName>$' -parallel=2 -fuzztime=510s
```

Per-chunk logs are committed under `.scratch/logs/`. Grown corpora live in the shared
`GOCACHE` fuzz dir (not committed). No production file was modified; `git status` is clean
apart from this report and the logs.
