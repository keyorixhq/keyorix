- **INV-FUZZOTP-window-pm1** The library primitive behaves as Keyorix's ±1-step loop assumes:
  `totp.ValidateCustom` honours its `Skew` boundary (Skew=1 accepts the previous, current and
  next 30-second step and rejects ±2; Skew=0 rejects neighbours), and a code generated for a
  step is accepted by an in-test `accepts` predicate that mirrors the `delta ∈ {0,-1,+1}` loop.
  Why: `validateTOTPStep` (`KeyorixCore.validateTOTPStep`, `internal/core`) loops over those
  deltas rather than using the library's `Skew`, so it depends on the primitive generating and
  comparing codes per step exactly as pinned here. This invariant does NOT guard the Keyorix
  property itself (the test checks its own mirror predicate and never calls `validateTOTPStep`,
  so it stays green if production widens the window); that property is guarded by
  `INV-CORE-totp-verify-accepts-only-window-codes` (`internal/core/INVARIANTS.d`). Guard:
  `TestKeyorixWindow_PlusMinusOneStep`, `TestSkewWindowBoundary` (`fuzz/thirdparty/otp`).
