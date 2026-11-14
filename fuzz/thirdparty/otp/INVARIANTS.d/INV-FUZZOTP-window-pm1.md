- **INV-FUZZOTP-window-pm1** Keyorix's TOTP acceptance window is exactly ±1 30-second step:
  a code from the previous, current, or next step is accepted, and a code two or more steps
  away is rejected. The library primitive `totp.ValidateCustom` honours its `Skew` boundary
  (Skew=1 accepts ±1 and rejects ±2; Skew=0 rejects neighbours). Why: `validateTOTPStep`
  (`internal/core/mfa.go:822`) loops `delta ∈ {0,-1,+1}` rather than using the library's
  `Skew`, so the window is a Keyorix property pinned here against the primitive it is built
  on; a wider window would enlarge the replay/brute-force surface. Guard:
  `TestKeyorixWindow_PlusMinusOneStep`, `TestSkewWindowBoundary` (`fuzz/thirdparty/otp`).
