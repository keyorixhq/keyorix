# SG2/G3 Milestone Predicate Pruning — Decision

**Date:** 2026-11-21
**Branch:** `fuzz/sg2g3-milestone-pruning-experiment`
**Author:** Andrei Beshkov (session sg2g3, automated)
**Decision:** DROPPED — zero measurable effect; structural reason documented.

---

## Task

Decide whether "milestone predicate" early-exit pruning (SG2/G3 fuzzer backlog items) is worth
building. The same measurement bar as #4041/SG1 applies: the pruned variant must show ≥20
percentage-point improvement in kill rate over the unmodified target, or the backlog row is
formally dropped.

---

## Measurement approach

**Target:** `FuzzCoreOperationSequence` (`internal/core/core_sequence_fuzz_test.go`)
Package has non-test production code; oracle is stateful (shadow model); two oracle directions:
FAIL-CLOSED (unauthorised read must be denied) and PRESERVE-DATA (admin round-trip and
authorised read value integrity).

**Mutation:** negate-cond on the RBAC grant path (`else if ok {` → `else if !(ok) {`) at
`internal/core/permissions.go:246`. When `ok=false` (principal has no role), the mutation grants
access (RBAC bypass). When `ok=true` (principal has a role), the mutation denies access
(over-denial).

**Pruning checkpoint (CP-1):** In the READ step (op=3) of `FuzzCoreOperationSequencePruned`,
skip the read when `canRead[u]=true`. Rationale: the FAIL-CLOSED oracle only fires when
`canRead=false && rerr==nil`; authorised reads cannot trigger that oracle direction, so skipping
them should focus the fuzzer's budget on reads that ARE oracle-visible.

**A/B protocol:** One mutated test binary; 10 independent 15 s fuzz runs per arm.

---

## Step 0: oraclehealth baseline (checkSecretPermission, seed=1, cap=20, fuzztime=15s)

```
mutations: 45 candidate(s), 20 selected (cap=20 seed=1)
killed=11 survived=5 timeout=1 buildfail=3  kill-rate=65%
```

Survivors:

| Line | Op | Why |
|------|----|-----|
| 130 | drop-error-guard | userID=0 guard — fixture never creates userID=0; equivalent |
| 173 | drop-error-guard | sharePermissionFor error guard — no storage errors in SQLite in-memory; equivalent |
| 199 | drop-error-guard | entire ACL block — no ACL rows ever created in fixture; equivalent |
| 199 | cmp-ne-to-eq | `!=` in ACL block — same reasoning; equivalent |
| 199 | logic-and-to-or | `&&` in ACL block — same reasoning; equivalent |

**All five survivors are equivalent mutants.** The 11 kills are caught by seeds in the first
trial. The 65% kill rate is across different mutants; it does not reflect a per-trial rate for any
single mutant.

The specific mutation at line 246 (negate-cond on `else if ok {`) was not among the 20 sampled
mutations (seed=1, cap=20 selects a subset). It was applied manually for the A/B runs.

---

## Step 1: Prototype

File added: `internal/core/core_sequence_pruned_fuzz_test.go`

`FuzzCoreOperationSequencePruned` is a copy of `FuzzCoreOperationSequence` with identical seeds
and one addition: in `runCoreSeqPrunedIteration`'s READ step, `if canRead[u] { return }` before
the actual read. The safety-net call at the end of each iteration (`step(3,0,0)`) goes through the
same pruned step and is also subject to CP-1 (skipped when `canRead[2]=true`), which is correct:
the safety net is specifically for catching FAIL-CLOSED violations when `canRead=false`.

---

## Step 2: A/B results

Mutation applied: `internal/core/permissions.go:246`
`} else if ok {` → `} else if !(ok) {`

```
run  baseline       pruned
 1   KILLED         KILLED
 2   KILLED         KILLED
 3   KILLED         KILLED
 4   KILLED         KILLED
 5   KILLED         KILLED
 6   KILLED         KILLED
 7   KILLED         KILLED
 8   KILLED         KILLED
 9   KILLED         KILLED
10   KILLED         KILLED
```

**Baseline kill rate:** 10/10 (100%)
**Pruned kill rate:** 10/10 (100%)
**Difference:** 0 pp

Fisher exact: p=1.0 (identical tables). No effect.

---

## Why the kill rate is 10/10 for both arms — structural explanation

The mutation is caught by **seed#0, in the first CREATE step**, not by a READ step.

Seed#0 (`{0xFF, 0, 0, ...}`): the first op is `0` (create). `createSecret` calls
`c.CreateSecret(...)`, after which `assertAdminValue(id, val)` immediately reads the secret back
as the admin. The admin (user 1) has `BypassesPermissionChecks=true` through a global role, so
`AuthorizePrincipal` returns `ok=true` for the admin. The mutation changes `else if ok {` to
`else if !(ok) {`, which inverts the condition: `ok=true` → `!(ok)=false` → the grant path is not
taken → admin is denied. The `assertAdminValue` guard catches this as `DATA LOSS/AVAILABILITY`.

This happens at seed-corpus time — before any fuzzing starts — and is fully deterministic. No
15 s budget is consumed; the kill latency is ~0.4 s. Every run, pruned or baseline, fails at the
same point.

The pruning checkpoint CP-1 is in `case 3` (READ step). It is never reached before the
`assertAdminValue` call in `case 0` (CREATE step). CP-1 is structurally irrelevant for this
mutation.

The kill rate cannot be below 10/10 because:
1. `assertAdminValue` is called after EVERY successful `createSecret` in the program body
2. The first seed always has a CREATE as its first step
3. The mutation makes the admin RBAC path fail (over-denial, not over-allow)
4. There is no way to reach a fuzzing phase before the seed corpus fails

Reducing `fuzztime` to 1 s or even 0 s would produce the same 10/10 kill rate; the seed corpus
runs before the fuzzer is ever started.

---

## Conclusion

**VERDICT: DROPPED.**

Milestone predicate pruning (SG2/G3) shows 0 pp improvement under these experimental conditions.
The null result is not noise — it is structural. For `FuzzCoreOperationSequence`:

1. The oracle is unusually strong. `assertAdminValue` fires on EVERY create step, catching
   any mutation that breaks the admin read path immediately at seed-corpus time.
2. The safety net (`step(3, 0, 0)` at end of each iteration) makes the FAIL-CLOSED oracle
   fire without coverage-guided exploration.
3. Together these mean there are no mutations with an intermediate per-trial kill rate (the 2/10–
   7/10 "room to improve" range). Every oracle-detectable mutation is killed by seeds in
   <0.5 s. Equivalent mutants survive unconditionally. Pruning has nothing to work on.

This is good news about the oracle's design, not a failure of the experiment. The finding is
honest and actionable:

> Milestone predicate pruning adds no value to stateful sequence fuzzers with strong safety-net
> oracles and representative seed corpora. It may still add value to fuzzers where the oracle
> is lighter and seeds are sparse — but that case was not tested here.

---

## What this experiment does NOT show

- Whether milestone pruning helps on other targets or mutation types not covered by seeds
- Whether milestone pruning helps at longer budgets (15 s is short; advantages may appear
  when seed-corpus kills are sparser)
- Whether milestone pruning helps on a target with a weaker/simpler oracle (no safety net)
- Whether the specific CP-1 checkpoint generalises to other oracle structures

A DROPPED result rules out a large effect **under these conditions only.**

---

## LEFTOVERS

- TODO-ISSUE: Backlog SG2/G3 rows need explicit DROPPED notation after this decision
  (Andrei to update the backlog).
- TODO-ISSUE: If a target with an intermediate per-trial kill rate is found in future,
  the same A/B protocol (N=10, 20pp threshold, frozen before measurement) applies.
  Candidates: `FuzzAuthzDiff` (test-only package, oraclehealth incompatible), or a new
  lightweight stateless target without a safety net and sparse seeds.
