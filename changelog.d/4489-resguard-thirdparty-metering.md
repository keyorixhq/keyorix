### Testing
- **Resource metering for four third-party fuzz targets.** The bcrypt, precis,
  ssh and webauthn targets under `fuzz/thirdparty/` now meter every input with
  `resguard` and fail an input whose allocation exceeds the committed budget in
  `testdata/resguard-<lib>.json`. A missing or invalid budget file fails the
  target instead of silently turning the check off, and each
  `TestResguard<Lib>_RedGreen` judges the committed file itself.
