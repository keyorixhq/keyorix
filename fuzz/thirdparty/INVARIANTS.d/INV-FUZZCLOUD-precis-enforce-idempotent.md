- **INV-FUZZCLOUD-precis-enforce-idempotent** The two PRECIS profiles
  `internal/identity` uses — `NewFreeform(LowerCase(), Norm(NFC))` (folded names)
  and `OpaqueString` (address names) — enforce *idempotently and
  deterministically*: for any input `s`, if `p.String(s)` succeeds with `out`
  then `p.String(out)` succeeds and equals `out`, and `p.String(s)` returns the
  same `(value, error-decision)` on a second call. This is the property
  `NewFoldedName`/`NewAddressName` rely on when they store a folded name and
  later compare it against a freshly-folded candidate (RFC 8264 §7, RFC 8265).
  Does NOT check reject-completeness (which runes the profile should refuse) or
  fold-collision soundness (that two inputs which should fold equal do). Why: a
  direct library-level complement to `FuzzFoldedNameOracles` /
  `FuzzAddressNameOracles` (`internal/identity/fold_oracles_fuzz_test.go`),
  which already check idempotence through Keyorix's wrappers; a non-idempotent fold would silently split identities that must
  compare equal. Guard: `FuzzPrecisProfileIdempotent`
  (`fuzz/thirdparty/precis/precis_idempotent_fuzz_test.go`), red-proofed with a
  planted non-idempotent transform.
