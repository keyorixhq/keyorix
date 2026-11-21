# internal/kdfmeter — INVARIANTS

`kdfmeter` is the production-side seam for counting password-hash / key-derivation
(KDF) invocations. Production credential paths call its `GenerateFromPassword` /
`CompareHashAndPassword` instead of `golang.org/x/crypto/bcrypt` directly, so a
test harness (the resguard `KDFMeter`) can count bcrypt invocations deterministically
— the signal an account-enumeration timing oracle needs. See the package doc for
the full rationale.

Format: `INV-KDFMETER-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-KDFMETER-<slug>.md` (one per file), never
appended here. Every current invariant is a fragment in `INVARIANTS.d/`.
