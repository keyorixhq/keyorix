- **INV-FUZZOTP-base32-leniency-bounded** pquerna/otp's base32 secret acceptance is pinned
  against its current normalisation: it is a superset of a canonical RFC 4648 decoder, and any
  extra acceptance is reproduced by the documented transforms `{surrounding whitespace,
  missing padding, lowercase}` (it `TrimSpace`s, pads to a multiple of 8, and `ToUpper`s before
  decoding), and no canonically-valid secret is rejected. The "explained" check re-implements
  that normalisation over the same lenient stdlib decoder, so it detects a CHANGE in pquerna's
  normalisation; it does NOT prove acceptance stays within those three transforms (an internal
  `\r`/`\n`, which the stdlib decoder skips, also counts as explained). Why: Keyorix stores
  only the library-generated canonical secret, but a dependency bump that widened base32
  acceptance (e.g. started accepting arbitrary non-alphabet bytes) would weaken the secret's
  entropy guarantees; this pins the current behaviour. See `EXPECTED-DIFFERENCE.md`. Guard:
  `FuzzOTPBase32Secret` (`fuzz/thirdparty/otp`) plus the committed `EXPECTED-DIFFERENCE.md`.
