# Hybrid post-quantum key wrapping (X25519 + ML-KEM)

Status: **draft for decision; Q1, Q3, Q7 and Q8 decided 2026-10-23 (§15)**. Design only, with an unwired proof of concept. Nothing here is
accepted until Andrei approves it, and no production key path changes before then.
Session RD-PQWRAP-1, 2026-10-23, against origin/main `da6fbb33d`.

Proof of concept: `internal/pqwrap` (imported by nothing). Its tests are the evidence for every
"the PoC shows" sentence below. Measured performance is in the session report and the PR
description, not here, because measurements go stale.

Inputs read: [ADR-077](../adr-077-symmetric-cipher-choice.md) (cipher and the algorithm tag),
[ADR-038](../adr-038-pluggable-key-providers.md) and [ADR-041](../adr-041-kms-key-provider.md)
(key providers), [ADR-010](../adr-010-kek-rotation-reencryption-sweep.md) (rotation sweep),
[ADR-029](../adr-029-audit-log-tamper-evidence.md) (audit checkpoints),
[design-b3-backup-v2](../design-b3-backup-v2.md) (backups),
[design-b2-recover-admin](../design-b2-recover-admin.md) (recovery key), the open PRs #3617
(`docs/design/recovery-options.md`, RECOVERY-OPTIONS-1) and #3648 (AUDIT-ROTATE-TRANSITION-1,
key transition records), and the code under `internal/encryption`, `internal/crypto` and
`server/admin`.

## 1. Summary

- **The symmetric core of the key hierarchy is already quantum-resistant.** The DEK is wrapped with
  AES-256-GCM under a 32-byte KEK, and the KEK comes from PBKDF2, a symmetric cloud KMS key, a TPM
  seal or Shamir shares. A quantum computer gives Grover's square-root speed-up against these, not
  Shor's break. Wrapping the DEK with a KEM adds no confidentiality on this path; it only matters
  where a **public-key** algorithm protects key material.
- **Two classical public-key hops exist at rest today** (§3): the Azure Key Vault provider wraps
  the KEK with RSA-OAEP-256, and that blob sits on disk and in every backup; and the recovery key
  can be delivered age-encrypted to an X25519 or ssh-ed25519 recipient. A harvested copy of
  either opens to a future quantum attacker.
- **Proposal:** one hybrid KEM-DEM envelope (X25519 + ML-KEM, concatenation combiner,
  HKDF-SHA-256, AES-256-GCM) becomes the only public-key wrap Keyorix writes. It is used inside a
  self-describing **keyset** file that replaces today's bare 60-byte `dek.key`: a KEK slot (the
  existing symmetric wrap, now with a header and context binding) plus optional hybrid recipient
  slots for offline escrow and disaster-recovery keys (option R, §7). Fixed suites, no runtime
  algorithm switch, a legacy reader kept for good.
- **Keyorix has no FIPS mode today, and cannot run under `GODEBUG=fips140=only`**: the existing
  AES-GCM code passes its own nonce, which that mode refuses (§9, reproduced). The PoC envelope
  does run under `fips140=only`.
- Nine decisions for Andrei are in §15.

## 2. Goals and non-goals

Goals:

1. No key material at rest that a "harvest now, decrypt later" adversary can open with a quantum
   computer, under the stated assumptions (§3).
2. Every public-key wrap Keyorix writes is hybrid: it stays secure while **either** X25519 **or**
   ML-KEM holds.
3. A self-describing, versioned envelope; the reader never guesses and never negotiates.
4. Existing installs keep working: legacy key files stay readable, migration is explicit, resumable
   and audited, and a downgrade fails closed.
5. Runs under Go's FIPS 140-3 module, including `fips140=only`.

Non-goals:

- Transport (TLS): R1's job. Go 1.24+ negotiates X25519MLKEM768 by default; whether every Keyorix
  hop does is R1's question.
- Signatures (audit checkpoints with ML-DSA): R8. R8 reuses this note's envelope conventions
  (magic, version, closed suite registry).
- Re-encrypting secret rows. The DEK value does not change in any migration here, so no row is
  touched. DEK rotation stays ADR-010's sweep.
- Replacing AES-256. A 256-bit key keeps about 128 bits against Grover, which NIST and BSI treat as
  adequate.

## 3. What is quantum-exposed at rest today

Assumptions: a future cryptographically relevant quantum computer (CRQC) runs Shor's algorithm
against RSA and elliptic curves and Grover's algorithm against symmetric keys; the attacker
recorded ciphertexts and public keys earlier; public keys are not secret.

| Artefact | Protected by (code) | Quantum exposure |
|---|---|---|
| `dek.key` (wrapped DEK) | AES-256-GCM under the KEK, `nonce‖ct‖tag`, 60 bytes, no header, no AAD (`internal/encryption/keymanager_lifecycle.go` `wrapKey`) | Grover only. Not a quantum gap. (The missing context binding is a classical weakness this note fixes in passing.) |
| KEK, password provider | PBKDF2-HMAC-SHA256, 600k iterations, 32-byte salt | Grover on passphrase entropy only |
| KEK, file / env / exec providers | raw 32 bytes from the operator's channel | As safe as that channel |
| KEK, AWS KMS / GCP KMS | KMS `Encrypt`/`Decrypt` with a symmetric key in the provider's HSM | None on our side, if the configured key is symmetric (the default for both) |
| **KEK, Azure Key Vault** | **`WrapKey` with RSA-OAEP-256** (`internal/crypto/azurekms/azurekms.go`, `wrapAlgorithm`); the wrapped blob is on disk and copied into every backup | **Shor.** Blob plus the vault key's public modulus gives the KEK, which gives everything |
| KEK, TPM | sealed under the TCG ECC-P256 SRK template (`internal/crypto/tpm_provider.go`); the sealed blob's confidentiality is symmetric, from the SRK's seed inside the TPM | No Shor path to the stored blob. Its symmetric protection is the TPM's (typically AES-128): NIST category 1 against Grover |
| KEK, Shamir | information-theoretic shares | The channel each share travels over |
| Backup archives (v2) | carry the key files verbatim, plus a KEK-derived HMAC manifest | Inherit the KEK provider's exposure (Azure: yes) |
| **Recovery key delivery** | `admin recovery-key rotate --recipient` age-encrypts to an `age1…` X25519 or ssh-ed25519 recipient (`server/admin/recovery_key_encrypt.go`) | **Shor.** A harvested age file gives the recovery key |
| Audit checkpoint, evidence and backup-manifest keys | HKDF-SHA256 from the KEK, used as HMAC keys | None |

Two things follow. First, the honest claim today is "the at-rest key hierarchy is symmetric except
for two public-key hops", not "Keyorix is not quantum-safe". Second, any future feature that
wraps to a public key (offline escrow, disaster-recovery sites, cross-cluster key transfer, HSM
export) would add a new exposure if it used a classical algorithm. That is what this design
prevents.

## 4. The construction

KEM-DEM: a hybrid KEM produces a one-time wrap key; an AEAD seals the short key under it.

```
ss_M, ct_M = ML-KEM.Encaps(ek_M)                      FIPS 203
eph        = fresh X25519 scalar; ct_X = X25519(eph, G); ss_X = X25519(eph, pk_X)
th         = SHA-256("keyorix/pqwrap/v1/transcript" ‖ 0x00 ‖ header ‖ ct_X ‖ ct_M ‖ pk_X ‖ ek_M)
PRK        = HKDF-Extract(salt = "keyorix/pqwrap/v1/extract", IKM = ss_M ‖ ss_X)
wk         = HKDF-Expand(PRK, info = suiteLabel ‖ 0x00 ‖ th, L = 32)
sealed     = AES-256-GCM(wk).Seal(random 96-bit nonce, key, AAD = header ‖ context)
```

KDF: HKDF with SHA-256 (RFC 5869), an instance of the SP 800-56C Rev. 2 two-step
(extract-then-expand) key derivation. Exact context strings, in `internal/pqwrap/pqwrap.go`:

| Use | String |
|---|---|
| HKDF-Extract salt | `keyorix/pqwrap/v1/extract` |
| Transcript prefix | `keyorix/pqwrap/v1/transcript` then `0x00` |
| Expand info, suite 0x0001 | `keyorix/pqwrap/v1/X25519-MLKEM768/HKDF-SHA256/AES-256-GCM` then `0x00`, then `th` |
| Expand info, suite 0x0002 | `keyorix/pqwrap/v1/X25519-MLKEM1024/HKDF-SHA256/AES-256-GCM` then `0x00`, then `th` |
| Key id | first 16 bytes of SHA-256(`keyorix/pqwrap/v1/keyid` ‖ `0x00` ‖ public key encoding) |
| Seed from KEK (option K only, §7) | HKDF-SHA256(KEK, salt `keyorix/pqwrap/v1/extract`, info `keyorix/pqwrap/v1/key-seed` ‖ `0x00` ‖ suiteLabel ‖ `0x00` ‖ epoch, 96 bytes) |

Every field in the transcript has a length fixed by the suite, and the suite is in the header,
which comes first. Plain concatenation is therefore unambiguous; no length prefixes are needed.

### Why this combiner

Requirements: secure if either component is secure (the point of a hybrid); no reliance on a
special property of one component; built from FIPS-approved pieces; one design for both
parameter sets.

- **Both shared secrets in the KDF input, both ciphertexts and both public keys in the
  transcript.** This is the concatenation ("GHP") combiner of Giacon, Heuer and Poettering
  ("KEM Combiners", PKC 2018) with a PRF-based KDF. It is IND-CCA when either component KEM is
  IND-CCA and the KDF is a PRF/dual-PRF. Binding the ciphertexts stops mix-and-match: the X25519
  share or the ML-KEM ciphertext of one envelope cannot be spliced into another. Binding the public
  keys makes the wrap key specific to the recipient.
- **ML-KEM's secret first.** SP 800-56C Rev. 2 allows a hybrid shared secret `Z' = Z ‖ T`, where `Z`
  comes from an approved scheme and `T` is an auxiliary secret. ML-KEM (FIPS 203) is approved;
  X25519 key agreement is not (it is not in SP 800-56A). SP 800-227 (2025) gives the same guidance
  for combining an approved KEM with another one. The order keeps the construction inside that
  rule, so a FIPS deployment can claim ML-KEM's strength.
- **Same order as TLS.** `X25519MLKEM768` in TLS 1.3 (draft-ietf-tls-ecdhe-mlkem) also
  concatenates the ML-KEM secret first, then X25519.
- **Why not X-Wing / HPKE `MLKEM768-X25519`** (draft-connolly-cfrg-xwing-kem,
  draft-ietf-hpke-pq; in the Go 1.27 standard library as `crypto/hpke`): a good, standard choice
  with one implementation to trust. It leaves the ML-KEM ciphertext out of the combiner on purpose,
  relying on ML-KEM's ciphertext-binding (C2PRI) property. It exists only for ML-KEM-768; the 1024
  hybrid in that draft pairs with P-384, not X25519. Our format is internal (no interoperability
  requirement), so the generic combiner costs nothing that matters (one SHA-256 over about 2.4 KB)
  and does not depend on a property of one parameter set. Decision Q2 asks whether to switch
  anyway.
- **Why not XOR of secrets or nested encryption.** XOR loses IND-CCA when one component is broken
  and malleable. Nesting (wrap under X25519, then under ML-KEM) doubles the format and gives no
  stronger guarantee than the concatenation combiner.
- **DEM: AES-256-GCM with a random nonce** (`cipher.NewGCMWithRandomNonce`), as in ADR-077. The wrap
  key is used once, so even a fixed nonce would be safe. The random-nonce constructor is chosen
  because it is the only GCM form Go allows under `fips140=only` (§9); it costs 12 bytes.

The PoC's known-answer vectors (`internal/pqwrap/testdata/vectors.json`) pin every intermediate:
both shared secrets, the transcript hash, the wrap key and the envelope. A separate implementation
written from this section (cloudflare/circl ML-KEM, x/crypto curve25519 and hkdf) reproduces all
four vectors byte for byte; see the PR description.

## 5. Envelope format

```
offset size        field
0      4           magic "KXPW"
4      1           version = 1
5      2           suite (big-endian)
7      1           purpose
8      16          recipient key id
24     32          X25519 ephemeral public key (ct_X)
56     1088|1568   ML-KEM ciphertext (ct_M), length fixed by suite
..     2           sealed length n (big-endian)
..     n           sealed = nonce(12) ‖ ciphertext ‖ tag(16); 29 ≤ n ≤ 28 + 64
```

The header (the first 24 bytes) is bound twice: in the transcript and as AEAD additional data.
Context (supplied by the reader, not stored) names where the envelope lives, for example
`keyorix:dek:<install id>:<epoch>`. Copying an envelope to another place then fails to open, as
ADR-077's AAD already does for secret rows.

Parsing is strict: wrong magic, an unknown version, suite or purpose, a component length that does
not match the suite, a sealed length out of bounds, or trailing bytes are all refused before any
cryptography runs. One envelope has exactly one encoding. The fuzz target checks this: a parsed
envelope re-encodes to the exact input. Every cryptographic failure in `Unwrap` returns the same
error.

Suites (closed registry, compiled in):

| Id | KEM | KDF | DEM | Envelope for a 32-byte key |
|---|---|---|---|---|
| `0x0001` | X25519 + ML-KEM-768 | HKDF-SHA-256 | AES-256-GCM | 1206 bytes |
| `0x0002` | X25519 + ML-KEM-1024 | HKDF-SHA-256 | AES-256-GCM | 1686 bytes |

Purposes: `0x01` DEK, `0x02` backup key. The reader states which purpose it expects.

### No runtime algorithm switch

This follows the existing decision that agility lives in the format, not in configuration
(ADR-077: the algorithm tag in `EncryptionMetadata` is checked on decrypt, and `AADVersion` names
the AAD scheme; no setting chooses the cipher). There is no separate algorithm-agility ADR in
`docs/`; the brief's `docs/adr/` directory does not exist, and this paragraph is the nearest
written form of that decision. Here it means:

- The writer's suite is a compile-time policy per purpose and data class: 0x0001 for the DEK, 0x0002
  for escrow and backup recipients. It is not a config key, flag or header the operator or a peer
  can set.
- The reader accepts exactly the suites in the registry. A new algorithm is a new suite id, or a new
  version, in a reviewed change with its own vectors. It is never a negotiation.
- Each suite pairs ML-KEM with a classical component. No classical-only suite exists, so a
  downgrade to classical cannot be expressed in the format.
- Version-1 vectors are frozen. Changing the construction means `Version = 2`, never an edit of the
  version-1 vectors (stated in `vectors_test.go`).

## 6. What a KEM-DEM envelope does not give: origin authentication

Anyone holding the public key can make a valid envelope around a key of their choice. The PoC pins
this property in `TestWrap_AnyPublicKeyHolderCanWrap_NoOriginAuthentication`, so the design cannot
silently forget it. For the DEK it matters: an attacker who can write the key directory could
replace the wrapped DEK with one they know. The server would then encrypt new secrets under that
key. Today's symmetric wrap does not have this problem, because forging it needs the KEK.

Therefore:

- An envelope the server reads on boot (the DEK) is accepted only inside a container authenticated
  under a KEK-derived key (the keyset MAC, §7). A KEK-less writer cannot produce one.
- An envelope opened offline by an escrow holder (no KEK available) is checked against the keyset's
  DEK key-check value, and the DEK it yields must decrypt real data before a restore commits. A
  substituted DEK then fails closed rather than being used.

## 7. Where the envelope is used: three options

### Option R (recommended): keyset with recipient slots

`dek.key` becomes a keyset file:

```
"KXKS" | version u8 | dek_kcv [16] | slot count u8 | slots | mac [32]
slot   = type u8 | length u16 | body
  type 1, KEK slot:     kek_id [16] ‖ AES-256-GCM(KEK, DEK), AAD = keyset header ‖ slot index
  type 2, hybrid slot:  pqwrap envelope, purpose DEK, context = keyset header
dek_kcv = HKDF-SHA256(DEK, info "keyorix/pqwrap/v1/dek-kcv")[:16]
mac     = HMAC-SHA256(HKDF-SHA256(KEK, info "keyorix/pqwrap/v1/keyset-mac"), all preceding bytes)
```

- Boot reads the KEK slot, the same symmetric unwrap as today but with a header and context
  binding, then checks the MAC and the KCV. Missing, extra or altered slots fail the MAC and stop
  the boot, as a wrong passphrase does now.
- A hybrid slot wraps the same DEK to an offline recipient: an escrow key generated by the operator
  on an offline machine (only its public key reaches the server), or a disaster-recovery site's key.
  Escrow and backup recipients use suite 0x0002 (ML-KEM-1024).
- Backups carry the keyset verbatim, as they carry `dek.key` now. A backup can then be restored with
  the escrow key when the KEK is gone: a forgotten passphrase, a deleted KMS key, a lost Azure
  tenant. That is a new capability, and it is PQ-safe. Today losing the KEK means losing the data.
- `admin backup --recipient <pq public key>` can add a backup-only slot to the archive's copy of
  the keyset, for an off-site key that the live server never holds.

Gain: every public-key path is hybrid, the symmetric path keeps its strength, and there is a real
recovery feature. Cost: a new key-file format, an offline escrow ceremony (optional, off by
default) and about 1.7 KB per slot.

### Option K: "KEM everything", wrap key pair derived from the KEK

The install's hybrid key pair is derived from the KEK (`DeriveSeed`, §4); `dek.key` is one
envelope to that key pair, plus a KEK-derived MAC (§6). KMS, TPM and Shamir providers stay
unchanged: they still supply 32 bytes.

This satisfies "new writes use hybrid envelopes" literally, but it **adds no quantum resistance**:
whoever gets the KEK derives the private key, and the KEK path was already symmetric. It would make
a claim ("the DEK is protected by ML-KEM") that sounds stronger than it is. That is a risk for
evidence that goes to ENISA and investors (§14). Its only real use is letting a process that holds
just the public key write envelopes (for example a backup agent), and option R covers that with
recipient slots.

### Option H: hybrid only for the public-key flows

`dek.key` stays as it is (or gains only a header). The envelope is used for the recovery-key
delivery, escrow/DR recipients and any future key transfer, and the Azure gap is closed on the
KMS side (§8). Smallest change, but it leaves the 60-byte headerless, context-free `dek.key`, and
the escrow slot has to live in some other file.

**Recommendation: R.** It contains H, adds a feature operators ask for (recovery without the KEK),
and keeps the claims accurate. **Decided (Q1, Andrei, 2026-10-23): option R.**

## 8. Interplay with key providers and KMS

- The `KeyProvider` interface does not change: it still returns 32 bytes, and every provider keeps
  working under every option.
- **Azure Key Vault (RSA-OAEP-256).** The only classical public-key hop in the KEK path. The
  envelope cannot fix it from our side: any second wrap needs a secret that also lives somewhere.
  Options for Q4:
  1. Support an Azure **Managed HSM symmetric (oct-HSM) key** and wrap with AES (KW or GCM) there.
     Symmetric, no Shor exposure.
  2. Report it in the compliance posture now ("KEK wrapped with RSA: not quantum-resistant") and
     tell operators in the docs to combine Azure with a hybrid escrow slot. That protects
     recoverability, not confidentiality.
  3. Wait for Azure to offer ML-KEM wrapping and add it then as another provider mode.

  Recommended: 2 now (no break for existing installs), 1 as a follow-up.
- AWS KMS and GCP KMS: symmetric keys by default, so no action. If an operator configures an
  asymmetric key (RSA decrypt), refuse it or flag it in the posture. Today the providers call
  symmetric `Encrypt`; asymmetric keys are not used, but nothing checks that. Follow-up: a startup
  check on the key spec.
- TPM: no change. The sealed blob's protection is symmetric inside the TPM.
- `migrate-provider` / `rotate-kek` (ADR-041, #3607, #3648) rewrite `dek.key`. Under option R they
  rewrite the keyset: re-wrap the KEK slot, recompute the MAC under the new KEK and keep the hybrid
  slots byte for byte (the DEK and the escrow keys did not change). The order is the same as
  #3607's two-phase key-file commit: key files first, database records second.

## 9. FIPS mode

What Go provides (Go 1.24+, repo on 1.27.2): the Go Cryptographic Module (FIPS 140-3), selected at
build time with `GOFIPS140` and at run time with `GODEBUG=fips140=on|only`. ML-KEM-768/1024
(`crypto/mlkem`), HKDF, SHA-256/SHA-3 and AES-GCM are in the module. Check the module's current
CMVP status at decision time; this note does not claim a certificate.

Observed on this machine with a small probe and the repo's own tests (behaviour only, no timings):

| Under `GODEBUG=fips140=only` | Result |
|---|---|
| `crypto/mlkem` 768 and 1024: key from seed, encapsulate, decapsulate | works |
| `crypto/ecdh` X25519 | **refused**: "use of X25519 is not allowed in FIPS 140-only mode" |
| `crypto/ecdh` P-384 | works |
| `crypto/hkdf` SHA-256 | works |
| `cipher.NewGCM` + `Seal` with a caller-chosen nonce | **refused**: "use of GCM with arbitrary IVs is not allowed … use NewGCMWithRandomNonce" |
| `cipher.NewGCMWithRandomNonce` | works |
| `crypto/hpke` MLKEM768-X25519 | works: the standard library lifts enforcement around X25519 inside the hybrid ("Hybrid of ML-KEM, which is Approved") |
| Keyorix `internal/encryption` (`TestWrapKey_ThenUnwrapKey_RoundTrip`, `TestService_EncryptLargeSecret_RoundTrip`) | **fails** with the GCM error above |
| Keyorix KEK providers (`internal/crypto` password and Shamir tests, PBKDF2) | pass |

**What Keyorix does today:** it has no FIPS mode: no setting, no startup check, nothing in the
posture. An operator can set `GODEBUG=fips140=on` (approved implementations, non-approved still
allowed). `fips140=only` breaks at the first encryption, because `wrapKey` and the
`EncryptionService` pass their own random nonce to `cipher.NewGCM`. Fixing that (moving to
`NewGCMWithRandomNonce`, whose layout `nonce‖ct‖tag` is the same as today's) is a prerequisite for
any FIPS claim, and independent of PQ. **Decided (Q7, Andrei, 2026-10-23):** a separate backlog item,
not part of R4.

**The PoC:** it uses `NewGCMWithRandomNonce`. Each X25519 operation runs inside
`fips140.WithoutEnforcement`, scoped to that one call, with the same justification the standard
library's HPKE hybrid uses. `TestFIPS140OnlyMode` re-runs the round trip in a child process under
`GODEBUG=fips140=only`. A mutation run (exemption removed) makes it fail with the X25519 refusal,
so the test does catch the problem it names. In a validated deployment the security strength
claimed is ML-KEM's; X25519 adds defence in depth that the validation does not count. For a
customer whose lab will not accept even an auxiliary non-approved component, a P-384 suite
(`0x0003`, approved ECDH) is the fallback. **Decided (Q3, Andrei, 2026-10-23):** X25519 for both
suites now; a P-384 suite is added only when a FIPS customer needs it.

## 10. Recovery key and recovery options (#3617)

- Today's recovery key (design-b2) is an **authenticator**, not a decryption key: a 256-bit secret
  whose SHA-256 verifier is stored, consumed by `recover-admin` and, under #3617's proposals, by
  host commands such as `admin reset-mfa`. It wraps nothing.
- **Delivery is the quantum gap** (§3): the `--recipient` output is age X25519 or ssh-ed25519.
  `filippo.io/age` v1.3.2, already in `go.mod`, supports hybrid `mlkem768x25519` recipients
  (`age.ParseHybridRecipient`). Accepting them, and warning on a classical recipient, is a small
  change that does not depend on this ADR. Decision Q5.
- **Do not turn the recovery key into the escrow key.** Option R's escrow recipient is a separate key
  pair with a separate ceremony. If one secret both authenticated admin recovery and decrypted every
  DEK, stealing it would give both powers at once, and #3617 §1's "host root plus the recovery key
  adds no new power" argument would no longer hold. Decision Q6.
- #3617 §3 recommends a pre-commit decrypt check for DEK rotation. The rewrap job below uses the same
  check (unwrap the new envelope and compare before committing).

## 11. Audit key transitions (#3648)

- The audit checkpoint, evidence and backup-manifest keys are derived from the **KEK** by HKDF, not
  wrapped. A format-only rewrap (same KEK, same DEK) changes none of them and must not write a key
  transition record. Test to ask for: after a rewrap the checkpoint key id, the evidence key id and
  the manifest key id are unchanged, and `verify-audit` gives the same verdict as before.
- Under option R the keyset MAC key is one more KEK-derived key (`keyorix/pqwrap/v1/keyset-mac`).
  It changes exactly when the checkpoint key changes, inside the same rotate-kek / migrate-provider
  run that #3648 already brackets with a cross-signed transition record. No new transition record
  type is needed. The keyset's KEK slot `kek_id` should use the same key-id convention as the
  transition record's `old_kid`/`new_kid`, so an auditor can match the two.
- Under option K the hybrid key pair rotates with the KEK. #3648's transition payload would then
  need the old and new wrap-key ids. This is one more reason to prefer R.

## 12. Rewrap migration job

What gets rewrapped is the **key files**, not the secret rows. On one install that is one keyset
(`dek.key`) per key directory (each HA replica has its own copy), plus any backup archives the
operator chooses to convert. The job's size is O(number of key artefacts), not O(number of secrets).

Design:

- **Inventory.** Every wrapped-key artefact is listed from the key-file registry
  (`internal/keyfiles`), which rotate-kek and backup already use, plus operator-named archives.
  Each artefact has a detected format: `legacy-60` (exactly 60 bytes, no magic), `keyset-v1`, or
  unknown. Unknown is refused, never guessed.
- **Per-envelope, idempotent.** For each artefact: detect; if it is already in the target form,
  skip and report "already current". Otherwise unwrap with the current KEK, build the new keyset
  (same DEK), write `<file>.pending`, **unwrap `.pending` in memory and compare to the DEK**, then
  `durableRename` and fsync the directory (the existing helpers). A crash at any point leaves either
  the old file or the new file, both readable.
- **Resumable.** The file on disk is the state: a re-run re-detects formats and continues. A
  progress record (artefact, old format, new format, old and new SHA-256 of the file) is only for
  reporting, never for deciding what to do.
- **Online.** A live server holds `dek.lock` exclusively (#2602), so only the server process can
  rewrap its own key directory: an admin endpoint or a startup step, guarded by the same
  snapshot-compare `RewrapDEK` already uses (#195), so it never overwrites a concurrent rotation.
  The DEK does not change, so the cross-replica DEK epoch (`dek_epoch.go`) does not move and other
  replicas keep running. Replicas can be migrated one at a time, and mixed formats are fine because
  every new binary reads both. When the server is stopped, the same code runs as an offline
  `admin encryption rewrap` command under the exclusive lock.
- **Progress and feedback.** The command says what it found ("3 key files, 2 legacy, 1 current"),
  prints one line per artefact on stderr, ends with a summary, and supports `--json` and `--dry-run`.
- **Audit.** One `encryption.key_envelope_rewrapped` event per artefact (path id, old and new
  format, suite, recipient key ids, file hashes; never key material) and one summary event. Offline
  runs use the existing startup-audit path to record the event on the next boot.
- **Backups.** `admin backup rewrap --input old.kxb --output new.kxb` converts an archive offline:
  same content, new keyset and optional recipient slots, manifest re-signed under the same KEK. The
  original is never modified in place.

## 13. Legacy-readable guarantee, rollback and downgrade

- **Read both forever.** Every binary after this change reads `legacy-60` and `keyset-v1`. The legacy
  reader is about 20 lines. Keeping it costs nothing and avoids a hard migration deadline, the same
  reasoning as design-b3's decision to keep a v1-archive reader. A frozen legacy fixture in
  `testdata` must keep unwrapping, as a guard.
- **Write only the new form** once the feature ships, except through an explicit offline
  `admin encryption rewrap --to legacy` for a downgrade.
- **An older binary on a new keyset fails closed.** Its `unwrapKey` treats the keyset as a GCM
  blob, the tag check fails, and it refuses to start with "wrong passphrase or corrupted key file".
  No data is touched, but the message is misleading. UPGRADING must say: before a downgrade, run
  `rewrap --to legacy` with the new binary (hybrid slots are dropped and the command says so).
- **No old-DEK copies.** Rewrap never keeps a `.legacy` copy of the key file next to the new one.
  After a later DEK rotation that copy would be stale, and an older binary that picked it up would
  unwrap the wrong DEK.
- **Reverting a rewrap** is just another rewrap (to legacy, or with different slots). No state
  outside the file needs undoing.

## 14. Performance budget

Hybrid wraps happen at boot, at rotation, at rewrap and at backup or restore, never per request.
Budget (targets, not measurements):

- Unwrap at boot: well under 5 ms per envelope on the smallest supported host.
- Wrap during rotation or rewrap: under 5 ms per envelope.
- Size: at most 2 KB per envelope, at most 8 KB per keyset with three slots.
- Zero hybrid operations on the request path; secret encryption stays AES-256-GCM under the DEK.

The PoC's benchmarks (`BenchmarkWrap`, `BenchmarkUnwrap`, `BenchmarkPrivateKeyFromSeed`) measure
against this budget. The measured numbers are in the session report, not here.

## 15. Decisions for Andrei

| # | Question | Recommendation |
|---|---|---|
| Q1 | Where the envelope is used: R (keyset with recipient slots), K (KEM everything) or H (public-key flows only) | **Decided 2026-10-23:** R |
| Q2 | Combiner: keep the generic concatenation KDF (as built) or switch to stdlib `crypto/hpke` MLKEM768-X25519 (X-Wing) | Keep it for the at-rest format; use age's hybrid recipients (HPKE) for operator-facing deliveries |
| Q3 | Classical partner for ML-KEM-1024: X25519 (as built) or P-384 (approved ECDH) | **Decided 2026-10-23:** X25519; add a P-384 suite only when a FIPS customer needs it |
| Q4 | Azure Key Vault RSA-OAEP KEK wrap | Posture warning now; Managed HSM symmetric key as follow-up; no breaking change |
| Q5 | Accept hybrid age recipients for recovery-key delivery and warn on classical ones | Yes, as its own small PR now |
| Q6 | Escrow recipient separate from the recovery-key authenticator | Yes, separate, optional, off by default |
| Q7 | Keyorix FIPS mode: move GCM to `NewGCMWithRandomNonce`, add a startup check and a posture line | **Decided 2026-10-23:** yes, a separate backlog item, before any FIPS claim |
| Q8 | Reword R4's acceptance from "new writes use hybrid envelopes" to "every public-key wrap at rest is hybrid; key files self-describing; legacy readable; rewrap migrates key files; backups rewrap offline" | **Decided 2026-10-23:** reworded as proposed |
| Q9 | Legacy-60 reader lifetime | Keep indefinitely |

## 16. New vs state of the art

State of the art, as of writing (verify with a dated search before any external claim):

- Hybrid key exchange in transport is deployed: X25519MLKEM768 is the default in Go 1.24+, the major
  browsers and large CDNs. Standards are settling: FIPS 203 (2024), SP 800-227 (2025), IETF drafts
  for TLS (draft-ietf-tls-ecdhe-mlkem), HPKE (draft-ietf-hpke-pq), X-Wing
  (draft-connolly-cfrg-xwing-kem), generic hybrid KEMs (draft-irtf-cfrg-hybrid-kems) and composite
  ML-KEM for CMS/X.509 (draft-ietf-lamps-pq-composite-kem).
- File encryption has hybrid recipients (age v1.3, `mlkem768x25519`). Cloud KMS vendors have started
  offering post-quantum signatures and KEMs, mostly at preview stage.
- European guidance (BSI TR-02102-1, ANSSI's position papers, the NIS Cooperation Group's June 2025
  coordinated PQC roadmap) recommends hybrid constructions and asks operators to inventory
  quantum-vulnerable key material first, with high-risk systems migrated by 2030.

What this design adds:

1. **An exposure inventory of a secrets manager's own at-rest key hierarchy** (§3). It shows that
   the symmetric core is already resistant and names the two classical public-key hops. Generic
   advice says "migrate everything"; this says where the risk actually is.
2. **A hybrid envelope that runs under FIPS 140-3 strict mode** (`fips140=only`), with ML-KEM as
   the approved component and the combiner ordered for SP 800-56C/SP 800-227. This is
   machine-checked by a test, not only asserted.
3. **No runtime agility**: a closed suite registry where no classical-only suite can be expressed,
   so downgrade is a format impossibility rather than a configuration rule.
4. **Keyset recipient slots** that give PQ-safe offline recovery of the DEK and of backups without
   the KEK, with KEK-authenticated slot integrity and a KCV for KEK-less checks. This addresses the
   origin-authentication gap that a bare KEM-DEM leaves (§6).
5. **Evidence by mechanism**: known-answer vectors cross-checked by an independent implementation,
   a fuzz target with a canonical-encoding oracle, tamper and suite-confusion tests, and a test
   that pins the no-origin-authentication property.

## 17. Technical risks

| Risk | Mitigation |
|---|---|
| Own combiner: a construction mistake | Generic GHP combiner, standard primitives only, every intermediate pinned by vectors, independent re-implementation matches; external cryptographic review before GA (or Q2: switch to stdlib X-Wing) |
| KEM-DEM has no sender authentication; DEK substitution by a key-directory writer | Keyset MAC under a KEK-derived key; KCV for offline checks; property pinned by a test (§6) |
| FIPS labs may not accept the `WithoutEnforcement` exemption for X25519 | Same pattern as Go's own HPKE; ML-KEM carries the claimed strength; P-384 suite as fallback (Q3) |
| IETF drafts change | The format is internal and pinned by `Version`; no interoperability dependency on a draft |
| Over-claiming "quantum-safe at rest" in evidence | §3 states the exact claim; option K rejected partly for this reason; the wording of R4's acceptance (Q8) |
| Azure installs stay exposed until Q4 is acted on | Posture warning makes the exposure visible; escrow slot protects recoverability |
| Downgrade error message is misleading on older binaries | UPGRADING note plus `rewrap --to legacy`; fails closed either way |
| Side channels in ML-KEM implementations (the KyberSlash class) | Go's implementation is constant-time and Wycheproof-tested in the standard library; we add no ML-KEM code |
| Offline escrow key handling is an operational burden | Optional, off by default, ML-KEM-1024, documented ceremony |
| Key files and backups grow | About 1.2–1.7 KB per envelope; negligible |
| ML-KEM decapsulation failure | Probability about 2⁻¹⁶⁴ (768) / 2⁻¹⁷⁴ (1024), and failure means a refused unwrap, never a wrong key |

## 18. What the proof of concept covers, and what it does not

Covers: wrap/unwrap for both suites and both purposes; deterministic keys from a seed; public-key
encoding and key ids; the KEK-derived seed (option K's mechanism); strict parsing; known-answer
vectors; every-bit-flip, truncation, trailing-byte, wrong-context, wrong-purpose, wrong-key,
suite-confusion and header-rewrite failures; `fips140=only`; a parser fuzz target
(`scripts/fuzzing/targets.d/internal-pqwrap__FuzzParseEnvelope.conf`); benchmarks.

Does not cover (left for after the decision): the keyset container (§7), the rewrap job (§12),
any change to `internal/encryption`, the KEK providers, backups or the recovery key, an
`INVARIANTS.md` for the package (added when it is wired in), and container or VM runs (pending
e2e VM; nothing here needs one).

## References

- NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (2024).
- NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms (2025).
- NIST SP 800-56C Rev. 2, Recommendation for Key-Derivation Methods in Key-Establishment Schemes (2020).
- RFC 5869 (HKDF), RFC 7748 (X25519), RFC 9180 (HPKE).
- draft-ietf-tls-ecdhe-mlkem; draft-ietf-hpke-pq; draft-connolly-cfrg-xwing-kem;
  draft-irtf-cfrg-hybrid-kems; draft-ietf-lamps-pq-composite-kem. Versions to be pinned when this
  note is accepted.
- F. Giacon, F. Heuer, B. Poettering, "KEM Combiners", PKC 2018.
- N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila, "Hybrid Key Encapsulation
  Mechanisms and Authenticated Key Exchange", PQCrypto 2019.
- BSI TR-02102-1; ANSSI PQC position papers; NIS Cooperation Group, coordinated implementation
  roadmap for the transition to post-quantum cryptography (June 2025).
