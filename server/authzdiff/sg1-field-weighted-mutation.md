# SG1: Field-weighted mutation experiment

**Decision: DROP**  
**Run**: 2026-11-20, pve01, branch `fuzz/sg1-field-weighted-mutation`  
**Oracle**: 10 000 simulated random walks per plant per strategy; 5 representative plants

---

## Question

Does **field-weighted** random sampling of the authzdiff case space — oversampling
cases where the custom or machine principal holds a **partial permission set**
(mask ≠ allPerms) — detect the existing planted defects in fewer samples than
**uniform** random sampling?

"Fewer samples" means: in a budget-limited (non-exhaustive) scenario, the
weighted sampler hits the first "unexplained" case after fewer iterations on
average.

---

## What "a field" is in this codebase

A case is `caseKey = {Op, Principal, Target, Arg, variation{Mask, Route, Scope}}`.
The sweep generates cases via `genVariations(R, t)` for pkCustom/pkMachine
(varying `Mask` over all leave-one-out/distractor combinations × routes × scopes)
plus 9 `namedPrincipalKinds` × `defaultVariation`. The "field" that field-weighted
mutation targets is `Mask` for the generated-mask principals.

---

## Signal and mechanism

**Signal**: `weight = 5.0` if `Principal ∈ {pkCustom, pkMachine}` and `Mask ≠ allPerms`
(partial permission set); `weight = 1.0` otherwise.

**Rationale**: a permission-check defect surfaces when a principal LACKS the
required permission but is wrongly allowed. Cases with partial masks for the
generated-mask principals are the most likely to trigger this — specifically the
leave-one-out shape (`mask = requirement \ {p}`).

**Mechanism**: weighted random sampling without replacement over the oracle case
list. This is NOT a modification to the Go fuzz engine; it is a custom sampling
strategy for a hypothetical budget-limited sweep.

---

## Measurement design

For each of 5 representative plants (covering different defect classes):

1. **Oracle collection**: run `TestAuthzDiffSweep` with the plant's overlay once,
   collecting all cases + their `bucket` field (`sg1CollectOracle`).
2. **Clean control**: same without overlay — must produce 0 unexplained cases.
3. **Simulation**: 10 000 random walks under UNIFORM (w=1.0 for all) and WEIGHTED
   (w=5.0 for high-weight cases) strategies; record iteration at first "unexplained" case.

**Decision rule (pre-registered)**: KEEP if improvement ≥ 1.5× for ≥ 3 of 5 plants.
DROP otherwise.

---

## Results

| Plant | N | K (unexpl) | P_base | N_hw | K_hw | P_hw | Ratio | Uni med | Wgt med | Sim improvement |
|---|---|---|---|---|---|---|---|---|---|---|
| name-based-role-check | 2246 | 1398 | 0.622 | 2192 | 1386 | 0.632 | 1.02× | 1 | 1 | **1.00×** |
| grpc-guard-removed | 258 | 239 | 0.926 | 240 | 230 | 0.958 | 1.03× | 1 | 1 | **1.00×** |
| router-gate-removed | 204 | 26 | 0.127 | 195 | 26 | 0.133 | 1.05× | 5 | 5 | **1.00×** |
| env-scope-clause-removed | 524 | 4 | 0.008 | 488 | 4 | 0.008 | 1.07× | 84 | 80 | **1.05×** |
| fix-3990-setrole-ceiling-removed | 2246 | 250 | 0.111 | 2192 | 250 | 0.114 | 1.02× | 6 | 6 | **1.00×** |

**Plants meeting KEEP threshold (improvement ≥ 1.5×): 0 of 5.**

---

## Why the signal is null

The root cause is visible in the N/N_hw column: **97%+ of all cases are already
in the "high-weight" category** (pkCustom/pkMachine with partial mask). For
`name-based-role-check`, N_hw = 2192 of 2246 total cases; for
`fix-3990-setrole-ceiling-removed`, N_hw = 2192 of 2246.

The `genVariations` case generator already produces this composition: for every
op, it generates `genMasks(R) × routes × scopes` cases for the generated-mask
principals (pkCustom, pkMachine), which dominate the case space. The
"field-weight signal" describes 97%+ of the existing case space, leaving only
the 9 named-principal cases (~2.7%) to discriminate against.

Weighting a 97/3 split cannot meaningfully shift the sampling distribution:
whether a walk takes the first step into the 97% bucket or the 3% bucket is
nearly irrelevant when the unexplained cases are proportionally distributed
across both.

**The existing `genVariations` design already implements the "smarter sampling"
idea**: it generates a targeted, permission-varied set of cases for the
generated-mask principals, which is exactly what field-weighting was trying to
prioritise. There is no additional discrimination power left to add via weights.

---

## Relationship to prior experiment #4041 (authz-tuple-novelty)

#4041 (branch `fuzz/authz-tuple-novelty`, NOVELTY.md) tested decision-tuple
novelty feedback for the Go fuzz engine on `FuzzAuthzSeq`. Its conclusion:
"plain coverage already separates allow from deny for each principal, because
the product code takes different edges, so a tuple adds little that the engine
did not already count."

SG1's null result has the same structure: the existing infrastructure already
incorporates the "smarter sampling" approach the experiment was trying to add.
Both experiments confirm that the authzdiff harness is already well-calibrated
for the cases it needs to cover.

**Recommendation**: close #4041 with the same DROP verdict. Two independent
experiments, different mechanisms, same null outcome — the question is answered.

---

## What this does NOT measure

- Go fuzz engine mutation strategy (this is pure random sampling, not fuzzer mutation)
- `FuzzAuthzSeq` or the stateful sequence oracle
- faultops oracle (not reached; authzdiff result alone answers KEEP/DROP)
- Defects outside the op-spec model's case space
- Effect of a DIFFERENT weighting signal (e.g., weighting by specific permission
  combinations derived from the op's requirement mask) — but given that 97%+ of
  cases are already high-weight, any weighting scheme faces the same structural limit

---

## Verdict

**DROP** (improvement 1.00–1.05× across all 5 plants; threshold 1.5×).

The experimental code (`sg1_field_weighted_test.go`) is left committed, opt-in
(`SG1_FW=1`), not wired into CI, and marked DROPPED in its file header so this
experiment is not re-discovered and re-tried without reading this document.
