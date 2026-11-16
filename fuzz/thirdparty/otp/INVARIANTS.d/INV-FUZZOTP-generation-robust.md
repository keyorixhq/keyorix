- **INV-FUZZOTP-generation-robust** HOTP/TOTP generation never panics or hangs on hostile
  parameters — empty secret, counter at `math.MaxUint64`, `Period=0`, and digit counts out of
  range (0, 1, 20) — and HOTP generation is deterministic for a fixed `(secret, counter,
  digits, algorithm)`. Why: Keyorix always calls with fixed sane options (Period=30, Digits=6),
  but this pins the library's robustness so a future caller or dependency bump cannot turn a
  degenerate option into a crash on an authentication path. Guard: `FuzzHOTPGenerate`,
  `TestPeriodZeroDoesNotPanic`, `TestCounterOverflowDoesNotPanic`,
  `TestDigitsOutOfRangeDoesNotPanic` (`fuzz/thirdparty/otp`).
