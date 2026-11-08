# pkg/a invariants

Format: `INV-A-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Parsing

- **INV-A-01** The parser never panics on untrusted input and never accepts a forged
  signature. Why: ADR-001. Guard: `FuzzThing`.
- **INV-A-02** Authorization is checked before any write. Why: ADR-002. Guard: `TestWriteChecksAuthz`.
- **INV-A-03** A planted gap: nothing references this rule, it names no Guard and is not marked.
  Why: fixture.
- **INV-A-04** Tokens expire. Why: ADR-003. Guard: `TestTokenExpiryGone` (this test was removed).
- **INV-A-05** First rule under a reused ID. Why: fixture. Guard: `TestWriteChecksAuthz`.
- **INV-A-05** Second, different rule under the same ID. Why: fixture. Guard: `TestWriteChecksAuthz`.
- **INV-A-06** Encryption keys are wiped after use. Why: ADR-004. Guard: `TestWipeKeys`.
- **INV-A-07** Only a helper in a fuzz test file mentions this. Why: fixture. Guard: UNGUARDED (#1).
- **INV-B-01** Wrong package prefix for this directory. Why: fixture. Guard: `TestWriteChecksAuthz`.
