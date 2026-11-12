- **INV-CORE-user-update-writes-from-locked-row** Every `UpdateUserIfActiveStateMatches` write
  in `UpdateUser` (all branches, so also `UpdateOwnProfile`) is built from that transaction's
  own `tx.LockUserForUpdate` re-read with only the request's changes applied: username/email
  only when the request changes them (decided and validated against the unlocked `GetUser`),
  display name when set, `is_active` from the request. Nothing from the unlocked read is
  written back. The write stays gated on the unlocked read's `is_active`, so a concurrent
  (de)activation is `ErrUserActiveStateConflict`, not overwritten. `UpdateOwnProfile` passes the
  email on only when it differs from the row its re-auth decision read. Why: the column-scoped
  write (#2785) still wrote username/email from the unlocked read, so a session-only
  display-name edit reverted an admin's concurrent email change (the password-reset anchor),
  and the web page's resent email became an email change that skipped re-auth when the email
  changed between the two reads (#2653/#2654 residue, FIX-USER-ROW-NARROW-1).
  Guard: `cta_review_user_row_narrow_sqlite_test.go` `TestUserRowNarrow_*` (default CI; every
  admin/self-service writer against password change, suspension, MFA enable, email and
  username change, plus the re-auth-read case and the deactivation conflict), their Postgres
  twins `TestCTAReview_UserRowNarrow_*` (pg-gated), and
  `guards/user_profile_column_scoped_guard_test.go:TestUpdateUserWrites_AreBuiltFromALockedRead`.
  **Not covered**: the structural guard counts locked reads against writes; it does not prove
  each write is built from its read (the race tests do).
