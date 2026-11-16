# configcompat rules (oracle)

Three invariants, each enforced by a function in `oracle.go` that the fuzz target and the
planted red/green tests share. Every rule states what it does **not** verify.

## I1 — fail-closed load & named refusal

`CheckI1Robust` (fuzzed on arbitrary bytes): `config.Load`+`Validate` never panics, the
verdict is deterministic across two loads of the same bytes, and no canary secret **value**
appears in an error string (a canary echoed as a *key* name is masked first — naming the
key is the required behaviour).

`CheckI1Named` (fuzzed on a key name derived from the input): a key HEAD does not recognize
must be **refused**, and the refusal must **name** it (masked refusal signature:
`field X not found in type …` / `unknown key "X"`). An unrecognized key that is accepted
and silently ignored is a fail-open defect.

**Does NOT verify:** that a *value*-validation error (bad duration, bad enum) names a key —
only unknown/removed **keys** are required to be named. It does not run old binaries, so it
cannot prove the old rev actually *accepted* a given file; the "valid at old rev" ground
truth is the shipped example corpus plus the schema's own history.

## I2 — no silently-weakened posture

`TestI2_DefaultPostureMatchesAllowlist` (fixed input): the posture predicates holding on a
defaults-only config must equal `default_posture.tsv` exactly — a new one means a default
silently weakened the baseline; a missing one means the allowlist is stale.

`CheckI2` (fuzzed on accepted configs): a posture predicate that holds must be a documented
default (`default_posture.tsv`) or explained by an explicit opt-in key — its model
`Explicit` list **or** the feature-enabler keys in `postureEnablers` (so a deliberately
plaintext dev listener is the operator's choice, not a flagged default).

**Does NOT verify:** cross-rev default *values* for keys the posture model does not cover; a
weakening that is split across a key combination no single posture predicate models; or that
the enabler map is complete (it is a curated list, stated in `postureEnablers`).

## I3 — deprecated-alias meaning preserved

`CheckI3` / `TestI3_AllAliasPairsEquivalent`: for each pair in the loader's own alias table,
a config written with the **old** key must (a) load (not be hard-refused), (b) record a
deprecation warning that **names** the old key, and (c) have a security fingerprint
(`config.InsecureSettingsRegistry` values + `Model.PostureHolds`) **identical** to the same
config written with the **new** key. A genuinely unknown key must instead be refused by name
(I1).

**Does NOT verify:** value-mapping aliases outside the rename table beyond the dedicated
audit-durability case; aliases that would need a polarity inversion (none exist today); or
that the fingerprint captures a security property neither the registry nor the posture model
models.

## Planted red/green proofs (production code is not edited)

Each oracle is proven non-vacuous by injecting a defective *loader* or *explicit-checker*
behaviourally (`compat_test.go`): a key-name scrubber (I1), a panicking / canary-leaking
loader (I1), a blind explicit-checker (I2), a meaning-changing bogus alias and a
warning-dropping loader (I3). The green side of every proof exercises the **real**
`config.Load`. No shipped file is modified.
