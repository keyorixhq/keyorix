# RVF1 — Review vs. Fuzzing: who finds what (talk F, RootedCON)

**Status: IN PROGRESS.** This report is written early and updated as results arrive.
**Report location note:** The mandated path `/mnt/data/wave4/out/rvf1-REPORT.md` is **not writable**
from this session (a filesystem guard confines all tool file access to the working tree
`/mnt/data/wave4/rvf1`). Per the runtime fallback rule, the report is kept **committed on the
branch at `.scratch/rvf1-REPORT.md`** (force-added). Andrei can copy it to the out dir on the Mac.

**Branch:** `fuzz/rvf1-review-vs-fuzz` (worktree on pve01). Append-only commits, DCO sign-off, no push.
(Task text named branch `rvf1-experiment`; the worktree I was started in is on
`fuzz/rvf1-review-vs-fuzz`. Per the runtime rule "stay on its branch", I stay here and do not
create/switch branches. Stated here so the discrepancy is explicit.)

## 0. Most-reasonable-reading decisions (nobody answers questions; stated per runtime rules)

1. **Scope vs. budget.** A faithful 3 arms × 4 targets = 12 fully-independent fuzzing+review
   sessions is not achievable within the ~3.5 h / ~$40 envelope on this shared, throttled host.
   I therefore split the deliverable into two honest parts:
   - **Part A — Historical ground-truth overlap** (fully verifiable): build the answer key from
     `docs/findings/*` + merged PRs, and classify each known defect by the *method that actually
     found it historically* (adversarial review vs. fuzz oracle), since the registry records this.
     This is the "who finds what" evidence the talk needs and it rests on real receipts.
   - **Part B — Live controlled micro-experiment** (fresh data, tiny n): run the R / Z / RZ arms as
     fresh scoped sub-agents on a *subset* of targets at the pre-fix commit, with no access to the
     fix/registry/findings, and measure found/missed, candidates, tokens, wall time. n is tiny;
     this is a method demonstration, not a powered study. Said loudly in the caveats.
2. **Environment limits** (see §Caveats): CPU-temp sensor is unreadable from this session
   (`cat /sys/.../temp1_input` blocked by the FS guard); resource safety relies on `nice -n 10`,
   `-p 2`, `-parallel 2`, and GOMAXPROCS where settable. External cache dirs
   (`/mnt/data/wave4/{gocache,gomod,tmp}`) are the machine `go env` defaults and are used by the
   toolchain, but my own file tools cannot read/write them.
3. **"Fuzz-found" vs "review-found" in the answer key** is taken from the originating artifact's
   own language (a `FINDING` doc authored from a review pass vs. a fuzz-oracle/harness commit),
   not re-derived. Where a defect was found by both, it is marked BOTH.

## 1. Overlap matrix (known defects × method)   — TO BE FILLED

(Matrix first, per instructions. Part A = historical; Part B = live arms.)

_pending_

## 2. Targets and answer key   — IN PROGRESS

| # | Target | Package | Known defect(s) | Fix commit | Pre-fix commit |
|---|--------|---------|-----------------|-----------|----------------|
| 1 | machine-token issuer ceiling (#4332) | `internal/core/machine_token.go` | caller ceiling checked against user-id 0 for a machine caller | `0908fc7a88` | `cd9cc7eb6a` |
| 2 | identity/SSO/SCIM boundary (S4 sweep) | TBD | TBD | TBD | TBD |
| 3 | authzdiff env-scoped grants | `server/authzdiff` | TBD | TBD | TBD |
| 4 | (dual review+fuzz record) | TBD | TBD | TBD | TBD |

## 3. Method   — pending

## 4. Per-arm results (tokens, wall time, found/missed/candidates/FP)   — pending

## 5. Misses and why (short table)   — pending

## 6. Oracles: what each does NOT verify   — pending

## 7. Caveats

- **n is tiny.** Part B is a handful of sessions, not a powered comparison. Do not read effect
  sizes into it. It demonstrates method and yields anecdotal token/time/overlap points.
- CPU-temperature telemetry unavailable this session (sensor path blocked); thermal safety relied
  on nice + capped parallelism only.
- Some packages may not compile/fuzz offline in this sandbox; any such result is marked UNVERIFIED
  for Andrei to confirm on the Mac.
- No embargoed/third-party internals (crewjam/saml, digitorus/pkcs7) are reproduced here beyond
  what is already public.
