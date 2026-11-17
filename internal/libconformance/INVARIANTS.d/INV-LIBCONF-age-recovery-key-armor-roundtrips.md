- **INV-LIBCONF-age-recovery-key-armor-roundtrips** The armored age output that
  `admin recovery-key --recipient` writes (age.Encrypt into armor.NewWriter, to an X25519
  or hybrid ML-KEM recipient) decrypts back to exactly the recovery key; armor.NewReader
  accepts a single spelling per payload (up to ignorable whitespace and CRLF); recipient
  strings print back in lower case and mixed case is rejected. Why: the armored text is
  the only copy of the recovery key that leaves the server, decrypted later with the age
  CLI. Guard:
  `internal/libconformance/age_armor_fuzz_test.go:FuzzAgeArmorRecoveryKey`.
<!-- section: Recovery key (age) -->
