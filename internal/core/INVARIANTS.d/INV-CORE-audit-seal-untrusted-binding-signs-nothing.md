- **INV-CORE-audit-seal-untrusted-binding-signs-nothing** Nothing is signed or authenticated
  against a seal list that cannot be trusted (`auditSealBinding` N < 0, set by
  `loadAuditSeals` when the `audit_seals` row is garbled, forged, replaced by an older list or
  left without its event). `checkpointMACUnder` (`audit_seal.go`) is the one primitive that
  computes a checkpoint or high-water signature: it refuses N < 0, so `signCheckpoint` /
  `signCheckpointUnder` return `ErrAuditSealsUntrusted` and `checkpointSigMatches(Under)`
  return false, even for an empty signature or a MAC over the `v2\x00-1\x00...` form an older
  binary could have written. Every writer goes through it: the checkpoint writers (full and
  incremental) refuse with `ErrAuditCheckpointRefused`, `advanceAuditHighWater` writes neither
  the mark nor the witness, the accept-loss re-seal refuses. `CompleteAuditKeyTransition`
  re-signs the carried seal row first, reloads it, and stops with `ErrAuditSealsUntrusted`
  before re-signing the mark or writing a checkpoint while the seals are untrusted; the
  transition stays open and the next start retries it.
  Why: REVIEW-3757-DEEP-3 finding 1 (AUDIT-SEAL-TAILS-1): completion re-signed the carried mark
  over the N < 0 form, which then verified whenever the binding was untrusted again (reads
  BROKEN, a liveness effect, not laundering). Guard:
  `TestCheckpointSign_UntrustedBindingSignsAndAuthenticatesNothing`,
  `TestAuditSeal_UntrustedSealsBlockKeyTransitionCompletion`,
  `TestAuditSeal_UntrustedSealsSignNoHighWater`, `TestAuditSeal_UntrustedSealsSignNoCheckpoint`
  (`internal/core`, SQLite and PostgreSQL). Not covered: a deleted seal row is "no seals"
  (binding N = 0), not untrusted; the walk, the bound artifacts and the state's seal count
  catch it (INV-CORE-audit-seal-never-valid-tamper-broken).
