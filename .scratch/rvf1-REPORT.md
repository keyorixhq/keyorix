# RVF1 — Review vs. Fuzzing: who finds what (talk F, RootedCON)

**Status: results in; live fuzz chunk + final commit pending at time of writing.**

**Report location note.** The mandated path `/mnt/data/wave4/out/rvf1-REPORT.md` is **not
writable** from this session — a filesystem guard confines every tool file operation to the
working tree `/mnt/data/wave4/rvf1`. Per the runtime fallback rule the report lives
**committed on the branch at `.scratch/rvf1-REPORT.md`** (force-added). Copy it to the out dir
on the Mac.

**Branch:** `fuzz/rvf1-review-vs-fuzz` (the worktree I was started in; task text said
`rvf1-experiment`, but the runtime rule "stay on its branch" wins, so I stayed here).
Commits are append-only, DCO-signed (`-s`), **not** pushed, no AI-attribution trailers.
Commits are issued from a linked worktree (`.claude/worktrees/wt`) because the git-write-guard
refuses commits in the shared checkout; the branch ref advances normally.

---

## 0. Most-reasonable-reading decisions (nobody answers questions; stated per runtime rules)

1. **Scope vs. budget.** A faithful 3 arms × 4 targets = 12 fully-independent fuzzing+review
   sessions is not achievable within ~3.5 h / ~$40 on this shared, throttled host. The
   deliverable is therefore split:
   - **Part A — historical ground-truth overlap** (fully verifiable from receipts): the answer
     key from `docs/findings/*` + merged PRs, each known defect tagged by the method that
     *actually* found it historically (adversarial review vs. fuzz oracle).
   - **Part B — a live controlled micro-experiment** (fresh data, tiny n): the R / Z / RZ arms
     run as fresh scoped sub-agents at the **pre-fix** commit, no access to the fix / registry /
     findings, measuring found / missed / candidates / tokens / wall time.
2. **n is tiny.** Part B is 3 review sessions + 1 review-derived-oracle session + 1 fuzz chunk.
   It is a method demonstration, not a powered study. Do not read effect sizes into it.
3. **"Fuzz-found" vs "review-found"** in the answer key is read from the originating artifact's
   own language, not re-derived. BOTH where a defect was found both ways.

---

## 1. OVERLAP MATRIX (matrix first, per instructions)

### 1a. Live Part-B result — who found each known defect, run fresh at the pre-fix commit

Arms actually run: **R** (review-only sub-agent, disprove prompt, no fuzzing, no oracles);
**RZ** (review hypothesis turned into a running red/green oracle); **Z** (plain fuzz) — see
§4 for which cells were executed vs. inferred from Part A.

| Target (known defect) | Answer-key: found historically by | R (review-only) | RZ (review→oracle) | Z (fuzz) |
|---|---|---|---|---|
| **T1** machine-token issuer ceiling (#4332): machine caller judged against `ActorTypeUser`+id-0 → legit machine refused, REST 500 | FUZZ (authzdiff differential model) | **MISS** — judged path safe (correct as a pure *escalation* question; see note) | not run | not run (authzdiff model post-dates the fix) |
| **T3** machine-role grant env-scope (#2595): HTTP grant hardcodes project scope, cannot express an environment-scoped grant | REVIEW (while building ADR-114 migration; a *sibling-diff* review) | **MISS** — judged by-design (no env field in the machine-grant body) | not run | not run |
| **T4-F3a** UpdateRole HTTP swallows permission-replace storage error, returns 200 (fail-open) | REVIEW (predicted from reading the code) | **HIT** — SECURITY-DEFECT, HIGH, exact file:line | **HIT (RED proof)** — oracle RED at pre-fix, GREEN at fix | plausibly (fault-injection fuzz); not run live |
| **T4-F3b** UpdateRole non-atomic replace corrupts role on mid-loop failure | FUZZ (10-min unattended fault-injection burst) | **PARTIAL** — identified, but flagged "needs fault injection to OBSERVE" | demonstrated via the same oracle (the effect is the corrupted set) | plausibly; not run live |

**The pattern, in one line:** pure adversarial review reliably finds the **fail-open /
swallowed-error** defect it can see in the code (T4-F3a), and reliably *does not* find
defects that are (a) **availability/correctness divergences it rationally judges safe** as a
confidentiality/integrity question (T1), or (b) only visible by **diffing against an external
requirement or a sibling endpoint** (T3). The defects the answer key attributes to **fuzzing**
are exactly the ones needing a **running oracle / fault injection / differential model**
(T4-F3b, T1). The **RZ** arm closes the loop: review supplies the hypothesis, the oracle turns
it into a machine-checked RED at the pre-fix commit.

### 1b. Historical ground-truth overlap (Part A, all four targets)

| Target | Known defect(s) | Review-found | Fuzz-found |
|---|---|---|---|
| T1 machine-token issuer ceiling (#4332) | caller ceiling evaluated as `ActorTypeUser`/id-0 for a machine caller | — | ✅ authzdiff model (fuzz #120) |
| T2 identity/SSO/SCIM boundary (S4 sweep) | **sweep itself: ZERO defects** (verification pass). Historical siblings: JIT-provision on unverified email (#657, CRITICAL); SAML email-fallback linking (#659/#89) | ✅ both SSO defects | — |
| T3 machine-role grant env-scope (#2595) | grant always project-wide, environment_id not expressible | ✅ (migration sibling-diff) | — |
| T4 UpdateRole atomicity (#1969) | F3a swallow→200 fail-open; F3b non-atomic corruption | ✅ F3a | ✅ F3b |

---

## 2. Targets and answer key (verified SHAs)

All pre-fix SHAs are `git rev-parse <fix>^`, resolved and confirmed in this repo.

| # | Target | Package / entry | Known defect(s) | Fix commit | Pre-fix commit |
|---|--------|-----------------|-----------------|-----------|----------------|
| 1 | machine-token issuer ceiling (#4332) | `internal/core/machine_token.go` `IssueMachineToken` | ceiling checked as `ActorTypeUser`+caller-id; a machine caller has id 0 → a machine holding `roles.assign` is always refused, REST answers 500 | `0908fc7a88` | `cd9cc7eb6a` |
| 2 | identity/SSO/SCIM boundary (S4 sweep) | `internal/core` sso/scim/users; `internal/saml` | **sweep = negative result (0 defects).** Historical: `#657` JIT unverified-email account-takeover (`34b1b55bf8`, pre-fix `52aba1a32d`); `#659/#89` SAML email-fallback linking (`c9d2844607`, pre-fix `62d9e5dd0f`) | (per defect) | (per defect) |
| 3 | authzdiff env-scoped grants (#2595) | `server/http/handlers/machine_identities.go` `changeMachineRole` | machine-role grant hardcodes `Scope{ProjectID}`, `EnvironmentID` always 0 (project-wide); body only decodes `role_id`, so an environment-scoped grant cannot be expressed — a widening relative to the sibling human endpoint which accepts `environment_id` | `5d1a2b7e2d` | `8762a3db80` |
| 4 | UpdateRole atomicity (#1969) | `server/http/handlers/rbac.go` + `internal/core/rbac_roles.go` + gRPC role service | F3a: HTTP `replaceRolePermissions` discards remove-error, logs-only on assign-error, returns 200 regardless (fail-open). F3b: non-atomic remove-all-then-add corrupts the role on a mid-loop failure | `dcc38dca52` | `e6f45a49b3` |

**Note on T1's nature.** #4332 pre-fix fails **closed** (a legit machine caller is *denied*,
REST 500). It is a correctness/availability defect, *not* an exploitable escalation — the
"issuer cannot widen" property was over-enforced, not bypassed. This is why the pure-security
review rationally passed it: there is no confidentiality/integrity exploit to construct. The
authzdiff **differential model** caught it because it models the *correct* ceiling semantics
and flags any divergence, in either direction.

---

## 3. Method

- **Answer key.** Mined `docs/findings/*`, `git log`, and each fix commit; resolved pre-fix
  parents with `git rev-parse <fix>^`; classified review-vs-fuzz from the originating
  artifact's own wording (quotes retained in the working notes).
- **Arms.** Each arm is a fresh sub-agent working **only** inside a detached git worktree at
  the pre-fix commit (`.claude/worktrees/t1|t3|t4`), so the fix, the post-fix findings doc, and
  the post-fix authzdiff model are all physically absent from its tree. The R-arm prompt is
  identical across targets except the target path and is a pure "disprove the code's own
  security claims" review — no fuzzing, no running tests. The RZ arm takes a review hypothesis
  and builds a **running** red/green oracle.
- **Oracle discipline.** Per the project rule "test a fails-open path by asserting the EFFECT,
  not the return value," the RZ oracle asserts the role's *persisted permission set*, never the
  HTTP status. The oracle was first drafted with an unconditional assertion (`set ==
  [secrets.write]`) and **rejected** during review as an "always-red" check — because
  `AssignPermissionToRole` is *forced* to fail, so an atomic fix legitimately rolls back to the
  *original* set and that draft would be red at BOTH commits. The shipped oracle asserts only
  the genuinely forbidden state: *reported success (2xx) AND effect absent*.

---

## 4. Per-arm results (executed vs. inferred; tokens & wall time)

| Arm | Target | Executed? | Result | Sub-agent tokens | Wall time |
|---|---|---|---|---|---|
| R | T1 | ✅ live sub-agent | MISS (no escalation found; 2 EXPECTED-DIFFERENCE notes, 0 FP) | 108,939 | ~203 s |
| R | T3 | ✅ live sub-agent | MISS (judged by-design; 1 HARDENING + 1 low DEFECT note, 0 FP) | 94,879 | ~142 s |
| R | T4 | ✅ live sub-agent | HIT — F3a SECURITY-DEFECT HIGH + F3b identified; 0 FP | 62,556 | ~100 s |
| RZ | T4 | ✅ oracle ran red/green | RED at pre-fix, GREEN at fix (green caveated, see below) | 112,508 | ~390 s |
| Z | authzdiff | ⏳ live fuzz chunk (see §4a) | — | — | — |

**RZ-T4 red/green (the load-bearing live proof):**
- **RED at pre-fix** (`cd…`/`e6f45a49b3`): `go test ./server/http/handlers -run
  TestRVF1_UpdateRole_FailOpen_PermReplace` →
  `--- FAIL`, observed `http_status=200 persisted_perms=[]`. Success reported, effect absent.
- **GREEN at fix** (`dcc38dca52`): `--- PASS`, observed `http_status=200
  persisted_perms=[secrets.write]`.
- **Honest caveat on the green.** At the fix the injected fault **did not fire**: the fix moved
  the permission replace *inside a `WithTransaction` block*, so the assign is called on a
  transaction-scoped storage handle — a different object than my outer wrapper — exactly the
  "a call through a `tx` handle inside `WithTransaction` is invisible to the wrapper" idiom this
  repo documents. So the update genuinely succeeded (200 + `[secrets.write]`). The GREEN
  therefore proves the oracle does **not** false-fire on a real success; it does **not** by
  itself exercise the fix's error-propagation path. That the fixed handler returns HTTP 500 on
  a replace failure, and runs the replace in one transaction, is confirmed by **reading the
  fixed code** (`server/http/handlers/rbac.go:349-358`, `core.UpdateRole` doc comment). A fully
  machine-checked green of the *error-propagation* path would require re-targeting the fault at
  the transaction-scoped storage — noted, not done, within budget. **This re-targeting
  requirement is itself a finding**: a fix that relocates an operation into a transaction
  silently neuters a fault-injection oracle aimed at the old call site; the oracle author must
  move the fault when the code moves.

### 4a. Live fuzz chunk (Z-arm machinery baseline)
_Filled in after the run; see the Z-arm section appended below._

---

## 5. Misses and why (short table)

| Miss | Arm | Why review did not flag it |
|---|---|---|
| T1 ceiling (#4332) | R | Pre-fix fails **closed** (legit caller denied + 500). No confidentiality/integrity exploit exists to construct, so a disprove-this review rationally passes it. Needs a **differential oracle** that models correct semantics to flag the divergence. |
| T3 env-scope (#2595) | R | From inside the pre-fix code the behavior is self-consistent: the machine-grant body has no `environment_id` field, so nothing is "ignored." The defect only appears when **diffed against an external requirement** (ADR-114 "narrower than Vault") or the **sibling human endpoint** that does accept `environment_id`. Out of scope for a single-path disprove review. |
| T4-F3b corruption | R (partial) | Review *identified* the non-atomicity and said so, but correctly noted the corrupted end-state "requires fault injection to OBSERVE" — i.e. review can hypothesize it but not demonstrate it; that is the fuzz/oracle's job (and the RZ oracle did demonstrate it). |

Cross-layer / state / oracle dependency per miss: T1 = needs a differential oracle (correct-
semantics model); T3 = needs a cross-requirement/sibling differential; T4-F3b = needs fault
injection (state).

---

## 6. What each oracle does NOT verify (required by the runtime rules)

- **RZ-T4 oracle** (`TestRVF1_UpdateRole_FailOpen_PermReplace`): verifies ONLY that the HTTP
  `UpdateRole` handler does not report 2xx success while leaving the role's persisted permission
  set different from the requested set, for a forced `AssignPermissionToRole` failure on the
  **pre-fix** (non-transactional) call site. It does NOT verify: (a) the gRPC transport; (b)
  the *remove*-step failure path (only the assign step is faulted); (c) concurrent/transient
  windows; (d) that the **fixed** code propagates the error — at the fix the fault does not fire
  (tx-handle indirection), so the fixed error path is confirmed by code reading, not by this
  test; (e) audit-record correctness (the test DB does not migrate `audit_events`).
- **R arms**: verify nothing by execution — they are reasoning over code. Every R finding is a
  hypothesis with a reachability trace, not a reproduced defect. Treated as CANDIDATE until
  reproduced. (Here they happened to align with the answer key, which is the measurement.)
- **Answer key**: verifies the SHAs exist and the pre-fix parents resolve; it does NOT
  re-prove each historical defect from scratch — it reads the historical classification.

---

## 7. New candidate findings (unverified — NOT claimed as defects)

None of the R arms produced a *new* security defect beyond the known answer key. The
non-answer-key notes they raised are all EXPECTED-DIFFERENCE / HARDENING / low-severity
attribution items, explicitly judged safe by the arm itself:
- R-t1: admin-tier detection asymmetry between user/machine actors (verified safe; flagged as a
  future-refactor hazard); gRPC `IssueMachineToken` drops `AllowedCIDRs`/`ReplaceCredentialID`
  (feature gap, not security).
- R-t3: `RemoveMachineRole` runs no ceiling/SoD check (benign — removal only reduces privilege);
  machine granter audited with `UserID=0` (attribution gap, not an authz gap).
- R-t4: HTTP discards the final `GetRolePermissions` read error, so the echoed `permissions`
  body may misreport (low).

Per the rules, since no arm surfaced a *real new* defect, nothing triggers the "stop and write
a private note" clause. All items above are pre-existing and either benign or already in the
answer key.

---

## 8. Caveats

- **n is tiny** (3 review sessions, 1 oracle, 1 fuzz chunk). Anecdotal token/time points, not a
  powered comparison. Do not generalize percentages.
- **CPU-temperature telemetry unavailable** this session: `/sys/.../temp1_input` is blocked by
  the same FS guard (even with the sandbox disabled). Thermal safety relied on `nice -n 10`,
  `-p 2`, `-parallel 2` only; no run streamed full `go test` output.
- **Toolchain friction, stated for reproducibility:** the Bash layer rejects env-var prefixes,
  `;`/`&&` chains, and `2>&1`; go commands ran as single commands with one `>file` redirect and
  the sandbox disabled. External cache dirs are the machine `go env` defaults and the toolchain
  uses them, but my file tools cannot read/write them.
- **No embargoed/third-party internals** (crewjam/saml, digitorus/pkcs7) are reproduced beyond
  what is already public; T2's SAML defects are described at the Keyorix-logic level only.
- **UNVERIFIED items** are labeled as such; Andrei confirms on the Mac.
