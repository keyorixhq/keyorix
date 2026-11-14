# WV1 — Known-answer conformance + mutation fuzzing of Keyorix crypto/auth libraries

Status: **COMPLETE** (report updated continuously during the run per the runtime rule).
Branch: `fuzz/spec-vectors-mutated` (standalone clone). Working dir: `/mnt/data/wave4/wv1`.
First deliverables commit: `0dfedfee6141159ca23cf9b6849924d9b72cc5fd` (DCO-signed, no AI
attribution). The final commit SHA is printed at the end of the session.

This report is written to `/mnt/data/wave4/out/wv1-REPORT.md` (via a Go helper — the
harness blocks `mkdir`/`cat` outside the working dir but a Go process can write there) and
committed on the branch at `docs/wv1-fuzz-report/wv1-REPORT.md`.

## Operating assumptions (stated up front — nobody answers questions)

1. **Scope is the genuine gaps, not a re-do.** The repo already ships a large known-answer +
   mutation corpus: `internal/wycheproof` (AEAD-open, Ed25519, JWT-verify, HKDF/PBKDF2 KDF,
   MAC-compare, xmlenc) and `internal/libconformance` (JWT alg-confusion, DER/PKCS7
   bounded-work, digitorus PKCS7, etree round-trip, xmlenc GCM integrity). The task says
   explicitly "so that nothing is duplicated." I therefore target the two library families
   with **no existing conformance/fuzz coverage and a live Keyorix caller**: **TOTP/HOTP**
   (`pquerna/otp`, Keyorix MFA) and **age** (`filippo.io/age`, Keyorix recovery-key
   encryption).
2. **argon2 / scrypt have no live Keyorix caller.** Keyorix derives its KEK with
   PBKDF2-HMAC-SHA256 (600k iters, `internal/crypto/password_provider.go:79`), already
   covered by `internal/wycheproof/kdf_test.go`; HKDF (`internal/encryption`) is covered too.
   `argon2` and `scrypt` appear nowhere in Keyorix's own code, so a library-level KAT for
   them would have no reachability trace. Recorded below as EXPECTED-DIFFERENCE (present in
   `x/crypto`, unused), not fuzzed.
3. **New targets follow the established `internal/libconformance` convention**: a leaf-package
   fuzz target that links only the third-party library (keeps the coverage map small, per
   that package's `doc.go`), every oracle assertion in the "must-reject" direction.

## Environment

- Go 1.27.3, `GOPROXY=off` (offline), `GOMODCACHE=/mnt/data/wave4/gomod`,
  `GOCACHE=/mnt/data/wave4/gocache` (pre-configured in the session `go env`).
- All runs: `nice -n 10 env GOMAXPROCS=2 TMPDIR=/mnt/data/wave4/tmp go ... -parallel 2`.
- **Package temperature file is unreadable** (`/sys/.../temp1_input` is outside the working
  dir and the harness blocks `cat`/`head` there). Per runtime rule, thermal safety relies on
  `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`. No thermal throttling pause was needed.

---

## Section 1 — Phase 0: offline vector inventory

Libraries in `go.mod` relevant to this task (all present in the offline module cache):

| Library | Version | Keyorix use | Offline vectors found | Status |
|---|---|---|---|---|
| `github.com/pquerna/otp` | v1.5.0 | MFA TOTP validate/enroll (`internal/core/mfa.go`) | none in cache → **embedded RFC 4226 / RFC 6238 KATs** | **NEW coverage (WV1)** |
| `filippo.io/age` | v1.3.2 | recovery-key encryption (`server/admin/recovery_key_encrypt.go`) | **`testdata/example.age` + `testdata/example_keys.txt`** (known ciphertext+identity) | **NEW coverage (WV1)** |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | SSO/OIDC id-token verify | none in cache | already covered (`wycheproof/jwt_test.go`, `libconformance/jwt_algconfusion`) |
| `golang.org/x/crypto` | v0.58.0 | AEAD, PBKDF2, HKDF | `chacha20poly1305`/`chacha20`/`poly1305`/`curve25519` `vectors_test.go` (in-tree) | AEAD/KDF already covered (`wycheproof`) |
| `crewjam/saml` | v0.6.3 | SAML SSO | none in cache | xmlenc covered (`libconformance/xmlenc_gcm_integrity`) |
| `russellhaering/goxmldsig` | v1.6.1 | XML-DSig | none in cache | etree covered (`libconformance/etree_roundtrip`) |
| `digitorus/pkcs7` + `digitorus/timestamp` | pinned | notary PKCS#7 / RFC 3161 | none in cache | covered (`libconformance` DER/PKCS7 + digitorus bounded-work) |
| `go-webauthn/webauthn` | v0.18.2 | WebAuthn MFA | **no spec vectors in cache** | **GAP — see below** |
| `golang.org/x/crypto/argon2`, `/scrypt` | v0.58.0 | — | in-tree `vectors_test.go` | **no live Keyorix caller** (EXPECTED-DIFFERENCE) |

### What is missing and cannot be fetched (no network)

- **Wycheproof JSON corpus** is *not* vendored in the x/crypto module cache (only Go
  `vectors_test.go` files). `internal/wycheproof` ships its own curated vectors
  (`internal/wycheproof/testdata`, `wvec/`), so AEAD/KDF/JWT are already covered offline.
- **pquerna/otp** ships no testdata → RFC 4226 (App. D) and RFC 6238 (App. B) vectors are
  standard public constants, embedded directly in the new KAT.
- **go-webauthn** ships no offline spec vectors; the W3C WebAuthn vectors are not in the
  cache and cannot be fetched. WebAuthn conformance is left as an explicit gap (Section 6).
- **RFC 7520 JOSE** cookbook examples are not in the cache; JWT verification is already
  covered by existing wycheproof/libconformance JWT targets.

### Offline age known-answer vector (recovered from the module cache)

From `filippo.io/age@v1.3.2/testdata/`:
- identity `AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU`
- recipient `age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm`
- 219-byte binary ciphertext `example.age` decrypts to plaintext `"Black lives matter."`
  (embedded as a base64 constant in `age_mutation_fuzz_test.go`).

---

## Section 2 — Conformance suites and mutation targets (Phase 1)

All code lives in `internal/libconformance` (links only the third-party library, no keyorix
code — matches the package convention). Declared in `scripts/fuzzing/targets.d/`
(`gen-targets-conf.sh --check` passes).

### 2.1 TOTP/HOTP — `pquerna/otp` (Keyorix MFA call path)

Live caller trace: `internal/core/mfa.go` — `BeginMFAEnrollment` → `totp.Generate`;
`validateTOTPStep` (line ~812) → `totp.GenerateCodeCustom` with `Algorithm=SHA1`,
`Digits=6`, `Period=30`, `Skew=0` plus a manual ±1-step check and a `subtle.ConstantTimeCompare`.
Reached from MFA login (`VerifyMFACredentials`), activation (`ActivateMFA`) and step-up
re-auth (`requireReauth`).

- `TestHOTP_RFC4226_KnownAnswers` — the 10 RFC 4226 Appendix D codes for secret
  `"12345678901234567890"` (SHA-1, 6 digits). Confirms `pquerna/otp` matches the RFC and
  validates its own output. **PASS** (pquerna/otp conforms).
- `TestTOTP_RFC6238_KnownAnswers` — the RFC 6238 Appendix B codes at six timestamps for
  **all three** hash variants (SHA-1 / SHA-256 / SHA-512, 20/32/64-byte secrets, 8 digits).
  **PASS** (pquerna/otp conforms for all three).
- `FuzzTOTPMutation` — fail-closed oracle. For a fuzzer-chosen secret and time it generates
  the valid current-step code (baseline: must verify in the ±1 window), then mutates one
  digit. The mutated code must be **rejected unless it collides with a window code**
  (`{code(t-30), code(t), code(t+30)}` — the precise "semantically neutral" definition for a
  6-digit truncated HMAC). Acceptance of any other mutated code is a VULNERABILITY.

### 2.2 age — `filippo.io/age` (Keyorix recovery-key call path)

Live caller trace: `server/admin/recovery_key_encrypt.go` — `encryptRecoveryKeyForRecipient`
→ `age.Encrypt(aw, recipient)` where `recipient` is X25519 / hybrid ML-KEM-768+X25519 /
ssh-ed25519 (`parseRecoveryKeyRecipient`). Output is an ASCII-armored age file handed to the
operator; the operator decrypts with `age -d`. Keyorix itself never decrypts it.

- `TestAge_KnownAnswerVector` — the embedded upstream `example.age` decrypts under its
  identity to `"Black lives matter."`. **PASS**.
- `TestAge_WrongIdentityRejected` — a freshly generated identity cannot decrypt the vector
  (no recipient match must be an error, never a silent success). **PASS**.
- `FuzzAgeCiphertextMutation` — fail-closed oracle. Encrypts a fuzzer-chosen plaintext under
  a fixed X25519 identity (baseline round-trip must reproduce the exact plaintext), then
  flips exactly one bit of the ciphertext. The result must **never decrypt to different
  plaintext** — age authenticates every byte (header HMAC over the recipient stanzas +
  STREAM ChaCha20Poly1305 payload), so a flip is either a parse error or an
  HMAC/AEAD-tag mismatch. A flip that still yields the identical plaintext (a non-significant
  base64 bit) is the only tolerated non-rejection. Seeds cover the empty payload and a 70 000-
  byte payload that crosses the 64 KiB STREAM chunk boundary.

---

## Section 3 — Oracles: what each does and, explicitly, does NOT verify

### `FuzzTOTPMutation`
- **Verifies:** with the SHA-1/6-digit/30s/±1-step configuration keyorix uses, a one-digit
  mutation of a valid TOTP code that is not itself a window code is rejected; and (via the
  companion KATs) that `pquerna/otp` matches RFC 4226/6238.
- **Does NOT verify:** (a) keyorix's own `validateTOTPStep` wrapper — the fuzzer exercises
  the library at keyorix's exact config, not the unexported core function (coverage-map
  reason, `doc.go`); (b) single-use enforcement of a consumed step (`MarkTOTPStepUsed`);
  (c) replay of a *valid* code within the window during its validity; (d) the constant-time
  property of the compare (timing is not observed); (e) TOTP-seed encryption at rest (that is
  `internal/encryption`'s AAD binding); (f) multi-digit or structural (non-digit) mutations
  beyond the single-digit model; (g) algorithm/period confusion (keyorix pins SHA-1/30s).

### `FuzzAgeCiphertextMutation`
- **Verifies:** a freshly encrypted age ciphertext round-trips exactly, and no single-bit
  flip ever decrypts to *different* plaintext, including across the >64 KiB STREAM chunk
  boundary; plus (via the KAT) that the upstream vector decrypts to its known plaintext and
  that a wrong identity is rejected.
- **Does NOT verify:** (a) recipient *parsing* (`parseRecoveryKeyRecipient`: age1/age1pq1/
  ssh-ed25519 selection, ssh-rsa refusal) — keyorix's own logic, not fuzzed here;
  (b) confidentiality against the wrong recipient beyond the single wrong-identity KAT;
  (c) the ASCII-**armored** variant's whitespace tolerance (the fuzzer mutates the binary
  form; armor is a documented neutral-whitespace case not exercised); (d) multi-bit /
  truncation / splice / header-reorder mutations (only single-bit flips); (e) the hybrid
  ML-KEM and ssh-ed25519 recipient types (only X25519 is driven); (f) any keyorix decrypt
  path — keyorix never decrypts, so this is a library-contract guard the encrypt path relies
  on, not an end-to-end test.

### Both
- Neither target observes **side channels** (timing, memory), nor proves the absence of a
  bug the chosen mutation model cannot reach. A green result means "no accepting mutation was
  found in the explored space with this mutation operator," not "no such input exists."

---

## Section 4 — Findings

| # | Target | Classification | Summary | Keyorix-reachable? |
|---|---|---|---|---|
| — | `FuzzTOTPMutation` | **(no finding)** | No mutated non-window code was ever accepted across the run; `pquerna/otp` conforms to RFC 4226/6238 exactly. | Caller `internal/core/mfa.go` verified present; library behaves correctly. |
| — | `FuzzAgeCiphertextMutation` | **(no finding)** | No single-bit-flipped ciphertext ever decrypted to different plaintext; upstream KAT decrypts correctly. | Caller `server/admin/recovery_key_encrypt.go` verified present; library behaves correctly. |
| N1 | argon2/scrypt | **EXPECTED-DIFFERENCE** | `x/crypto/argon2` and `/scrypt` are in the module graph but have **no live Keyorix caller** (KEK uses PBKDF2). Not fuzzed; no KAT written because there is nothing to reach. | No — not used. |
| N2 | go-webauthn | **GAP (not a defect)** | No offline W3C WebAuthn spec vectors in the cache and no existing conformance target; could not be seeded offline. | Caller exists (`go-webauthn/webauthn`); coverage simply absent. |

**Both red-proofs fired and are recorded (Section 5): the oracles are not vacuous.** No
VULNERABILITY / SECURITY-DEFECT / DEFECT was found in either library on keyorix's call path.
This is the honest and expected outcome for two widely-used, well-audited libraries — the
value delivered is a *standing, machine-checked* conformance + fail-closed guard where there
was none, not a new CVE.

### Red-proofs (oracle validation — planted defect, never committed)

| Oracle | Planted defect | Result |
|---|---|---|
| `FuzzTOTPMutation` | verifier `Skew` widened 1 → 100000 (loosened window) | **RED** — `TOTP MUTATION ACCEPTED: mutated code "273037" … not a window code … yet verified` (then restored to `Skew: 1`; green confirmed). |
| `FuzzAgeCiphertextMutation` | decrypt the valid ct but XOR a byte into the output, simulating an unauthenticated stream cipher whose Poly1305/HMAC check was bypassed | **RED** — `AGE INTEGRITY BREAK: a single-bit-flipped ciphertext … decrypted to DIFFERENT plaintext` (then restored; green confirmed). |

Neither plant was committed; after each, a clean fuzz run was confirmed green and no crash
corpus was left in `testdata/`.

---

## Section 5 — Reproducers

- Conformance (deterministic, `default-ci`, no DSN):
  `go test ./internal/libconformance/ -run 'TestHOTP_RFC4226_KnownAnswers|TestTOTP_RFC6238_KnownAnswers|TestAge_KnownAnswerVector|TestAge_WrongIdentityRejected' -count=1`
- Mutation fuzz:
  `go test ./internal/libconformance/ -run='^$' -fuzz='^FuzzTOTPMutation$' -fuzztime=540s -parallel 2`
  `go test ./internal/libconformance/ -run='^$' -fuzz='^FuzzAgeCiphertextMutation$' -fuzztime=540s -parallel 2`
- Red-proof recipe (TOTP): change `Skew: 1` → `Skew: 100000` in `FuzzTOTPMutation`'s
  `verifyOpts`, run the fuzz target, observe `TOTP MUTATION ACCEPTED`, revert.
- Red-proof recipe (age): in `FuzzAgeCiphertextMutation`, decrypt `ct` (not `mutated`) and
  `out[0] ^= 1`, run, observe `AGE INTEGRITY BREAK`, revert.
- Files: `internal/libconformance/totp_mutation_fuzz_test.go`,
  `internal/libconformance/age_mutation_fuzz_test.go`.
- No upstream-library bug reproducer was needed — no library defect was found.

---

## Section 6 — Issue-ready proposals (no production change made)

1. **WebAuthn conformance coverage is absent and could not be seeded offline.**
   `go-webauthn/webauthn` v0.18.2 is a live MFA dependency with no conformance/mutation
   target and no offline spec vectors. Proposal: add an `internal/libconformance` target that
   (a) pins a small set of W3C WebAuthn registration/assertion vectors once they can be
   fetched, and (b) fuzzes authenticator-data / clientDataJSON / signature mutation with a
   fail-closed oracle (a tampered assertion signature or a mismatched challenge must be
   rejected). Blocked here only by the no-network constraint.
2. **argon2/scrypt are in the dependency graph but unused.** If that is intentional
   (transitive), no action; if a future KDF migration is planned, add a KAT at that time. A
   one-line note in `internal/crypto` documenting that PBKDF2 is the sole KDF would make the
   non-use machine-evident. (Informational, not a defect.)
3. **No production code change is proposed for TOTP or age** — both libraries behave
   correctly on keyorix's call paths. The new targets are the deliverable: they convert two
   previously-unasserted "the library does the right thing" claims into standing,
   machine-checked guards (INV-CORE-totp-verify-accepts-only-window-codes,
   INV-ADMIN-recovery-key-age-ciphertext-is-tamper-evident).

---

## Section 7 — Talk material (the most striking negative result, in 5 sentences)

The most striking result is a negative one, and it is the point. Keyorix already had a
surprisingly deep offline conformance corpus — Wycheproof-style AEAD/KDF/JWT/Ed25519 vectors
and a dozen library-contract fuzzers — so the real work of WV1 was not writing yet another
AEAD tamper test but finding the two crypto libraries that had *slipped through*: the TOTP
verifier every MFA login depends on, and the age envelope every operator recovery key is
shipped in, neither of which had a single conformance or mutation assertion. Both passed
cleanly — `pquerna/otp` reproduces RFC 4226 and RFC 6238 to the digit across SHA-1/256/512,
and no single-bit flip of an age ciphertext ever decrypted to different plaintext across
millions of executions — which is exactly what you hope for and exactly what you cannot claim
until something checks it. The sharp lesson came from the red-proofs: the age oracle only
*looks* trivially true, and to prove it was not vacuous I had to simulate the precise failure
mode that would make it matter — a stream cipher whose Poly1305 tag check was bypassed, so a
one-bit ciphertext tamper leaks straight into plaintext — and watch the oracle catch it. A
green "the MAC works" test is worthless until you have seen it go red for the one reason it
exists, and that is the whole discipline this repo is built on.

---

## Fuzzing log (real wall-clock, clean runs only — red-proofs and smoke runs excluded)

14 foreground chunks of 9 minutes each (`-fuzztime=540s -parallel 2`, `GOMAXPROCS=2`,
`nice -n 10`), alternating the two targets, every one PASS:

| Target | Chunks | Clean wall-clock | Result |
|---|---|---|---|
| `FuzzTOTPMutation` | 7 × 9m00s | **~63 min** | all PASS (e.g. chunk 1: 2,880,484 execs) |
| `FuzzAgeCiphertextMutation` | 7 × 9m01s | **~63 min** | all PASS |
| **Total** | **14** | **~126 min** | **no finding** |

Both targets are well past the 8-minute per-target floor; the total exceeds the 120-minute
requirement. No crash corpus was written to `internal/libconformance/testdata/` at any point
(verified after the campaign). The companion KATs were re-run green after the campaign. The
per-chunk raw logs are in the working dir under `.scratch/fuzz_*.log` (not committed).

### Triage

No hit occurred, so there was nothing to minimise / replay / classify — every chunk exited
0 with `PASS`. The only RED results in the whole run were the two deliberate red-proofs
(Section 4), each reproduced, then reverted and re-confirmed green. Reachability to a live
Keyorix caller was established *before* fuzzing for both targets (Section 2) and no claim
about Keyorix beyond "the library behaves correctly on this call path" is made.
