- **INV-LIBCONF-pkcs7-decrypt-bounded-work** The two digitorus/pkcs7
  decryption entry points (`(*PKCS7).DecryptUsingPSK` and `(*PKCS7).Decrypt`)
  must never panic and never hang on ANY input that parses successfully via
  `pkcs7.Parse`.  `DecryptUsingPSK` additionally verifies that combined
  Parse+DecryptUsingPSK allocation stays within `64 MiB + 4 KiB·N` of the
  N-byte envelope input — the same envelope as the BER memory-exhaustion
  GHSA-3xqc-rpq8-wgp9 (which lived in `Parse`'s BER path); this guard verifies
  the allocation class has not been introduced into the decryption path.  The
  `Decrypt` harness uses a fixed RSA-2048 recipient certificate (not fuzzed)
  and fuzzes only the envelope bytes; ML-KEM/post-quantum decapsulation is
  covered separately by `FuzzPKCS7DecryptMLKEM768` (LS3,
  `INV-LIBCONF-pkcs7-mlkem-decrypt-bounded-work`).  Why: `DecryptUsingPSK` and
  `Decrypt` are both "A*" symbols (LS1 inventory: allocate from input in private
  helpers, the same class as the disclosed DoS); no previous fuzz coverage
  existed for either function.  Guard: `FuzzPKCS7DecryptUsingPSK`,
  `FuzzPKCS7Decrypt` (`internal/libconformance`).
