- **INV-ADMIN-recovery-key-age-ciphertext-is-tamper-evident** The recovery-key encryption
  output (`server/admin/recovery_key_encrypt.go`, `age.Encrypt` to an X25519 / hybrid
  ML-KEM+X25519 / ssh-ed25519 recipient) is a `filippo.io/age` ciphertext, whose binary
  format authenticates every byte (a header HMAC over the recipient stanzas plus a STREAM
  ChaCha20Poly1305 payload). No single-bit mutation of a valid age ciphertext may decrypt to
  *different* plaintext: a flip either makes the header unparseable or makes an HMAC/AEAD tag
  mismatch, so decryption fails. The only tolerated non-rejection is a flip that still yields
  the identical plaintext (a non-significant base64 bit). Why: a recovery key delivered to an
  operator must be exactly the key that was wrapped — a tamper-evident envelope is what lets
  the operator trust `age -d` output without a second channel. The repo had no conformance or
  mutation coverage of this library/call-path before WV1.
  Guard: `internal/libconformance` lib-contract targets `TestAge_KnownAnswerVector`
  (the upstream `filippo.io/age` test vector decrypts to its known plaintext),
  `TestAge_WrongIdentityRejected` and `FuzzAgeCiphertextMutation` (fail-closed: a freshly
  encrypted ciphertext round-trips, and a single-bit flip never decrypts to different
  plaintext, including across the >64 KiB STREAM chunk boundary; red/green-proved by
  simulating an unauthenticated stream-cipher decrypt).
  **Not covered**: recipient *parsing* (`parseRecoveryKeyRecipient`: the age1/age1pq1/
  ssh-ed25519 selection, ssh-rsa refusal) is `server/admin`'s own logic and is not fuzzed
  here; confidentiality against the wrong recipient beyond the single wrong-identity KAT;
  the armored (ASCII) age variant's whitespace handling; and keyorix never *decrypts* the
  output itself, so there is no keyorix decrypt caller to drive — the guard exercises the
  library contract keyorix's encrypt path relies on (`internal/libconformance/doc.go`).
