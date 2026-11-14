- **INV-FUZZOTP-base32-leniency-bounded** pquerna/otp's base32 secret acceptance is a strict
  superset of a canonical RFC 4648 decoder, differing only by the documented leniencies
  `{surrounding whitespace, missing padding, lowercase}` (it `TrimSpace`s, pads to a multiple
  of 8, and `ToUpper`s before decoding). No secret is accepted that cannot be explained by
  those three transforms, and no canonically-valid secret is rejected. Why: Keyorix stores
  only the library-generated canonical secret, but a dependency bump that widened base32
  acceptance (e.g. started accepting arbitrary non-alphabet bytes) would weaken the secret's
  entropy guarantees; this bounds the leniency. See `EXPECTED-DIFFERENCE.md`. Guard:
  `FuzzOTPBase32Secret` (`fuzz/thirdparty/otp`) plus the committed `EXPECTED-DIFFERENCE.md`.
