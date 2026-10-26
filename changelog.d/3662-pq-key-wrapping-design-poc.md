### Documentation
- **Design note for hybrid post-quantum key wrapping.** `docs/design/pq-key-wrapping.md` inventories which at-rest key hops are exposed to a quantum attacker (the Azure Key Vault RSA-OAEP KEK wrap and classical recipients for recovery-key delivery) and proposes a hybrid X25519 + ML-KEM envelope inside a KEK-authenticated keyset with optional escrow/DR recipient slots. Draft awaiting approval; nothing changes at runtime.

### Internal
- **`internal/pqwrap` proof of concept.** Hybrid KEM-DEM wrap (X25519 + ML-KEM-768/1024, HKDF-SHA-256 combiner, AES-256-GCM) with known-answer vectors, tamper and FIPS 140-only tests and a `FuzzParseEnvelope` fuzz target. Not wired into any server, CLI or storage path.
