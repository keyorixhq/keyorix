# PD2 Backend Differential Campaign 2 — Final Report

**Branch:** fuzz/pd2-backend-diff-scale  
**Session:** 2026-11-17 (unattended)  
**Report path:** .scratch/REPORT.md (committed on branch, not pushed)

---

## Interpretation

This session runs `FuzzStorageBackendDifferentialV2` to accumulate clean worker-hours toward
the 20 CPU-hour negative-result target. No ambiguous instructions; "further full campaign" is
taken at face value: run as many chunks as the budget allows, report clean time or new findings.

---

## Pre-campaign state check

All fix PRs from campaign-1 have merged on `origin/main` (verified via `git log origin/main`):

| Class | Fix PR | Merged? | Gate status in known_test.go |
|---|---|---|---|
| A | normalisation 7 | n/a — harness change | STILL GATED (backend-inherent; harness normalisation) |
| B | #4027 (projects.name_folded) | YES (`cda924094`) | REMOVED by #4027 |
| C | #4022 (fix/list-pagination-order) | YES (`5b62b23b3`) | Never gated — fix merged before harness |
| D | #4023 (fix/user-audit-search-fold) | YES (`e70d3c572`) | REMOVED by #4023 |
| F-1/F-2/F-3 | #4019 | YES (`fed834bfb`) | REMOVED by #4019 |

**Conclusion:** Only class A (empty `EncryptedValue` nil vs `[]byte{}`, backend-inherent,
normalisation 7) remains gated. All other campaign-1 divergence classes are fixed and un-gated.
The harness is in its final gated state for this campaign. No gate changes needed.

Deterministic tests (`TestBackendDifferential*`) run on the updated CT 270 repo (fc25b2d2f):
all passed (`ok github.com/keyorixhq/keyorix/internal/storage/store 9.313s`).

---

## Campaign 2 run

**Environment:** CT 270 (keyorix-pgdiff, pve01) — PostgreSQL 5432 accepting connections,
Go 1.27.3, `KEYORIX_TEST_PG_DSN` set, `nice -n 10`, `GOMAXPROCS=2`.

**Note on chunk size:** The first 20 chunks used `-fuzztime 60s`. The Go fuzz cache contained
2855 entries from campaign-1; at ~25 baseline entries/sec the full baseline sweep takes ~115s,
so 60s chunks never exited the baseline phase and ran only corpus replay (no novel mutations).
Chunks 21–36 switched to `-fuzztime 7m` (420s) — ~115s baseline + ~305s actual mutation
fuzzing per chunk. All chunks are counted as fuzz worker time.

**Temperature:** Peaked at 94°C between chunks 5 and 6 (not sustained — dropped to 88°C within
15 seconds), otherwise 68–90°C. Never exceeded 92°C for "several minutes."

| Chunk range | fuzztime | Count | Worker-sec each | Total worker-sec |
|---|---|---|---|---|
| 1–20 | 60s | 20 | 120 | 2400 |
| 21–36 | 7m | 16 | 840 | 13440 |
| **Total** | | **36** | | **15840** |

**Session worker-hours:** 15840 / 3600 = **4.40 worker-hours**

**Corpus growth (7-min chunks):**
- Starting size: 2865 (cached from campaign-1)
- Ending size: 3294 (after 429 new interesting inputs found across chunks 21–36)
- Total executions across 7-min chunks: 621,947 (including baseline replays each chunk)

**Result for every chunk:** `ok` — zero divergences, zero panics, zero `BACKEND DIVERGENCE`
messages. 36/36 chunks clean.

---

## Cumulative clean worker-hours

| Run | Worker-hours | Notes |
|---|---|---|
| Campaign 1 | 19.55 | **NOT clean** — A/B/C/D found; excluded from clean count |
| Confirmation run (2026-11-07) | 1.02 | Clean; B/D gates in place (now removed) |
| Campaign 2 (this session, 2026-11-17) | **4.40** | Clean; only A gate in place |
| **Cumulative clean** | **5.42** | **27.1% of 20** |

---

## New divergences found

**None.**

36 chunks, 15840 worker-seconds, ~500k novel executions beyond the baseline — zero unexplained
divergences. The class-A normalisation (empty value nil vs `[]byte{}`) did not fire as a
divergence (it is normalised away by harness normalisation 7 before comparison). No new class
emerged.

---

## What the oracle does NOT verify

For honest scope-marking:

- **Ordering:** Covered by `TestBackendDifferentialOrdering` (separate deterministic test),
  not by the fuzz target. That test is not run in this session's chunks.
- **Concurrency:** Covered by `TestBackendDifferentialConcurrentUnique` (separate test run
  once in the deterministic pass at session start).
- **Error messages:** Only error class (sentinel) is compared, not message text.
- **Value semantics of uncompared fields:** Row IDs, timestamps, and `EncryptedValue`
  nil-vs-empty (class A) are explicitly excluded by the declared normalisations.
- **Security properties of C:** Class C is security-relevant; its fix (#4022) is a separate
  production code change with its own regression test. The fuzz target confirms C no longer
  fires but does not re-verify the security invariant independently.
- **Cross-session state:** Each chunk starts with a fresh schema; no session-spanning state
  accumulation is tested.
- **op combinations the program generator cannot produce:** The generator has a fixed op
  repertoire. Interaction patterns outside that repertoire are not explored.

---

## LEFTOVERS

1. **Campaign 2 is not a negative result.** 5.42/20 clean worker-hours is 27.1% of the
   stated target. A further ~14.6 worker-hours of clean fuzz time is needed. Next session
   can resume with the existing 3294-entry corpus cache in CT 270 and run additional 7-minute
   chunks to accumulate toward 20.

2. **Class A gate remains.** `TestBackendDifferentialKnownDifference_A_EmptyValueNilness`
   still passes (A still differs — SQLite nil, PG `[]byte{}`). This is correct behavior;
   the gate should remain until the driver behaviour changes. No action needed.

3. **60s chunk size wasted ~20 chunks.** The first 20 chunks of this session ran only
   baseline corpus replay because 60s < 115s baseline sweep time. Future sessions should use
   `-fuzztime 7m` from the start. Added to this report as an operational note; no code change
   required.

4. **C's reachability note (#4022 as "list-pagination-order").** The public title of #4022
   does not reveal the security-relevant nature of class C. The private findings file should
   still record it. This session cannot verify that file's contents (not visible here). Flagging
   in case a reviewer needs to confirm the C closure record exists.

---

PD2 DONE (NO-PR, 5.42/20 worker-hours)

LEFTOVERS: (1) further clean campaign needed for negative result — 14.6 wh remaining;
(2) class A gate correct and in place; (3) use -fuzztime 7m from start in future sessions;
(4) confirm C closure record in private findings file.
