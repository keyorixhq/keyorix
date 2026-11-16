- **INV-FUZZOTP-url-roundtrip-stable** `otp.NewKeyFromURL` is idempotent under
  re-serialisation: for any `otpauth://` URL it accepts, `NewKeyFromURL(k.URL())` yields a key
  with the same `secret`, `type`, `algorithm`, `digits`, and `period`. Why: Keyorix generates
  enrolment URLs via the library and relies on them parsing back to the same parameters
  (percent-encoding of issuer/account, unknown query params, empty labels must not perturb the
  security-relevant fields). A round-trip that silently changed the secret or algorithm would
  desynchronise enrolment from validation. Guard: `FuzzOTPURLRoundTrip` (`fuzz/thirdparty/otp`).
