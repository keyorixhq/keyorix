- **INV-FUZZJWT-bounded-alloc** Parsing an attacker-supplied token allocates memory bounded
  by a linear function of the input length (64 KiB + 512·len), and returns inside the
  `fuzzutil.Guard` wall-clock budget — no super-linear amplification from many segments or a
  giant header. Why: golang-jwt's header handling had a memory-exhaustion CVE class
  (CVE-2025-30204, fixed upstream in v5.2.2+; this repo vendors v5.3.1). This invariant pins
  the fix so a future dependency bump that regressed it would be caught, not shipped. Guard:
  `FuzzJWTBoundedWork` (`fuzz/thirdparty/jwt`).
