# SMT model: AAT capability attenuation (I4), parts A-C

An SMT-LIB model of the I4 rules of the attenuating agent tokens draft
(`draft-niyikiza-oauth-attenuating-agent-tokens-02`, ADR-120, design note
[`docs/design-rd-aat.md`](../../design-rd-aat.md) section 4). For each rule it asks the
solver for a widening: a value or invocation that the derived (child) constraint accepts
and the parent rejects, while the structural rule says the child attenuates. `unsat` proves
the rule sound for every parameter value. For each rule, a weakened copy (a mutant, or a
seeded bug) must come back `sat`, so no proof holds just because its hypotheses are too
strong.

R&D artefact (RD-AAT-SMT-RERUN-1): not run by CI and not a runtime dependency. The runtime
uses only the draft's structural checks.

## Source text

The rules are encoded from the draft-02 text as published, read from the author's repository
(`tenuo-ai/tenuo`, `ietf/draft-niyikiza-oauth-attenuating-agent-tokens-02.md` at commit
`aecf7b45fd07`, 2026-10-27, file SHA-256 `b501c01d…1041`). That file contains both
published Section 4.5 rules that ADR-120 decision 6 quotes (`"*"` is excluded from the
omitted-key rule; `any` allows splitting and does not allow union coverage). The sandbox
that built this model cannot reach ietf.org, so it has not been diffed byte for byte against
the datatracker copy.

## Run

```sh
python3 docs/formal/rd-aat-smt/run.py                 # every case on z3, and on cvc5 if present
python3 docs/formal/rd-aat-smt/run.py --solver z3
python3 docs/formal/rd-aat-smt/run.py --witness c-keys/c05_mutant_drop_R4.smt2   # show the model
cat docs/formal/rd-aat-smt/c-keys/prelude.smt2 docs/formal/rd-aat-smt/c-keys/c01_proof_published.smt2 | z3 -in
```

Requirements: `z3` and/or `cvc5` on PATH, and Python 3 (standard library only). The runner
exits 2 with "pending tool install" when neither solver is found. Exit 0 means every case
returned exactly its `; EXPECT:` verdicts. Exit 1 means at least one case did not. A
timeout, `unknown` or any solver `(error ...)` counts as a failure, never as a pass.

Each directory has a `prelude.smt2` (sorts, semantics, named rules). The runner feeds the
prelude plus one case file to the solver. A case file holds only the rule set it assumes
and the query, so a mutant differs from its proof by the one rule it removes.

## What is encoded

| Part | Draft text | Encoding |
|---|---|---|
| A, `a-core/` | 4.5 core table: `exact`, `range` (bounds, inclusivity, missing bounds), `exact` under `range`, `one_of`, `exact` under `one_of`, `not_one_of`, `contains`, `subset`, `wildcard` | values are an uninterpreted sort, equal iff equal JCS serialisation; array members are sets `(Array Val Bool)`; numbers are `Real` |
| B, `b-allany/` | 4.5 `all` (for each parent clause there is a child clause it subsumes) and `any` (for each child clause there is a parent clause that subsumes it; splitting allowed, no one-to-one matching) | clause lists are uninterpreted sorts, so any number of clauses is covered; `m(j,i)` is the recursive check, assumed sound one level down (induction on depth, base case part A) |
| C, `c-keys/` | 3.3 closed world, `optional`, `"*"`, empty map = `{"*": wildcard}`; 4.5 key bullets; steps 4p2-4p4 and 6b | argument names are an uninterpreted sort, so maps naming any number of keys are covered; `"*"` is a map-level flag, not a key |

Part C names the five key rules as in the published text:

| Rule | Published text (4.5 / step 4p) |
|---|---|
| R1 | every key the child names is named by the parent, unless the parent contains `"*"` |
| R2 | a key the parent requires stays required (4p3) |
| R3 | the child may omit a key **other than `"*"`** that the parent names only if the parent marks it optional |
| R4 | ... and only if the child map does not contain `"*"` |
| R5 | the child contains `"*"` only if the parent does |

R4 and R5 read the normalised maps (step 4p2). Per-key value subsumption (4p4) is the
hypothesis `P4`, which parts A and B discharge.

## Results (z3 5.3.2; every case decided in well under a second)

| Part | Proofs (`unsat`) | Mutants / seeded bug (`sat`) | Informational |
|---|---|---|---|
| A core table | 9 | 6 mutants + seeded bug `bug_a_range_equal_bound_inclusive` | `not_one_of` under `one_of` shown unsound (`sat`) |
| B all/any | 2 | 2 mutants + seeded bug `bug_b_any_uses_all_rule` | union coverage is semantically sound (`unsat`), see below |
| C key rules | published rules; pinned rules | R1..R5 each removed (5), P4 removed, no normalisation, seeded bug `bug_c_omit_ok_under_parent_star` | the pinned wording forbids dropping `"*"`; the published wording allows it |

**Part C answer: five load-bearing key rules, unchanged by the carve-out.** With `"*"`
excluded from the omitted-key rule, the published rule set is sound (`c01`), and removing any
one of R1-R5 lets the solver construct a widening (`c02`-`c06`). Witnesses, in words:

- without R1: the child names an argument the parent neither names nor admits under `"*"`;
- without R2: the child makes a parent-required argument optional and the invocation omits it;
- without R3: the parent has `"*"` and requires `k`; the child omits `k` and drops `"*"`; an
  invocation without `k` passes the child;
- without R4: the child omits the parent's optional `k` but keeps `"*"`, so `k` comes back
  under `"*"` with a value the parent's constraint for `k` rejects;
- without R5: the child adds `"*"` and an unnamed argument passes.

Also load-bearing, though not key rules: per-key value subsumption (`c07`) and empty-map
normalisation before the key rules (`c08`: an empty child map passes R4/R5 as written but
accepts every argument at step 6b).

`c09`/`c10` record what the change was: the pinned pre-publication rules are sound but can
never drop the parent's `"*"` (`c10`, first query `unsat`), although 4.5 says dropping `"*"`
narrows. The published rules allow it (second query `sat`), and `c01` proves that relaxation
sound, with a non-vacuity query showing the dropped-`"*"` case is inside the proof.

**Part B answer: the published `any` rule re-proves unchanged.** `b01` proves
`forall j exists i` sound and shows that the hypotheses admit a split (two child clauses under
one parent clause, the J.16.7 shape). `b05` shows that union coverage, which J.16.8 requires
a verifier to reject, is semantically **sound**. J.16.8's DENY is a rule about determinism
and decidability, not soundness. No soundness model can tell a verifier that wrongly permits
J.16.8 from a correct one. Only the vector can.

**Seeded bugs.** Each part has one `bug_*` case, a plausible implementation error that the
checker must flag (`sat`). Planting the same bug into the part's proof (replacing the
published rule) turns that proof red (`got=sat`, runner exit 1). This was done on a copy for
all three parts when the model was built.

## What the model does not cover

- Parts D (chain bounds I2/I3), E (`keyorix_ref_glob`) and F (issuance against RBAC) of the
  design note were not rebuilt here.
- Cross-type pairs other than the table rows above (draft extension types, `exact` under
  `any`, which the draft rejects as conservative).
- JCS canonicalisation and number admissibility (the model assumes equality means equal JCS
  form and that numbers compare as reals), well-formedness, `MAX_CONSTRAINT_DEPTH`, empty
  `all`/`any` arrays (SMT sorts are non-empty; the draft rejects empty arrays as not
  well-formed), and parsing (duplicate members).
- I1, I5, I6 (signatures, `par_hash`, proof of possession), multi-anchor handling (step 3k),
  the `scope` claim (J.9.6). The vectors test these.
- Whether any Go code implements these rules. No AAT verifier exists in the repository.
- Completeness: the model proves that the rules never widen. It does not prove that they
  accept every valid narrowing (the draft says they do not, on purpose).
- cvc5 cross-check: the runner supports it, but it has not been run for this version of the
  model.
