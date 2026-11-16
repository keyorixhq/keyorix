- **INV-FUZZJWT-bounded-alloc** `jwt.Parser.ParseUnverified` on an attacker-supplied many-periods
  token (`"."×100000`, `"A."×50000`) allocates a small constant (at most 4 KiB; v5.3.1 measures
  a few hundred bytes), independent of input length. Separately, parsing any token allocates at
  most 64 KiB + 512·len and returns inside the `fuzzutil.Guard` wall-clock budget. Why:
  golang-jwt's header handling had a memory-exhaustion CVE (CVE-2025-30204, fixed upstream in
  v5.2.2+; this repo vendors v5.3.1): `strings.Split` on `.` costs about 16 B per input byte.
  The fuzz ceiling is about 32x looser than that, so it catches order-of-magnitude blow-ups
  only and does NOT pin the CVE; the deterministic test does, and carries an in-test red proof
  (the pre-fix `strings.Split` shape, measured the same way, exceeds the 4 KiB ceiling).
  Guard: `TestBoundedWork_ManyPeriods_CVE202530204` (`fuzz/thirdparty/jwt`) for the CVE class;
  `FuzzJWTBoundedWork` for the coarse linear bound and the time budget.
