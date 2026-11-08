# Wycheproof conformance rules (pre-registered)

These rules were written before the suites were first run. A change to them
after the fact goes in a separate commit with the reason.

Vectors: C2SP/wycheproof, `testvectors_v1/`, pinned to commit
`d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`. The exact files and their SHA-256
are in `wvec/SHA256SUMS`; `scripts/wycheproof/fetch.sh` downloads and verifies
them into `internal/wycheproof/testdata/vectors/` (git-ignored). A file whose
hash does not match is a hard error. Tests skip when the vectors are absent,
unless `WYCHEPROOF_REQUIRE=1` (then absence is a failure).

## 1. Result semantics

| Wycheproof result | Rule |
|---|---|
| `valid` (in the wrapper's declared scope) | must be accepted, and the output must equal the vector's expected output |
| `valid` (outside the declared scope, e.g. a 128-bit key for a 256-bit-only wrapper) | must be rejected (fail closed), never accepted with a different output. Rejecting is by design and counted as "out of scope" |
| `invalid` | must be rejected; never accepted; never a panic |
| `acceptable` | either outcome is allowed, but the outcome must be deterministic (two evaluations agree) and must equal the pin recorded in `testdata/acceptable_pins.json`. A vector without a pin fails the test until its outcome is reviewed and pinned |
| any call that panics | failure, for every result class |

Declared scope per wrapper:

* `internal/encryption/aead` (AES-256-GCM): key 256 bit, nonce 96 bit, tag 128 bit. Vectors with another key, IV or tag size are out of scope. Flags `SmallIv`, `LongIv`, `ZeroLengthIv` and any non-128-bit tag are tolerated by design as "rejected".
* `pkg/trust` (Ed25519): any message, 32-byte key, 64-byte signature.
* JWT verification path (`rules.ParseJWK` + `golang-jwt/jwt/v5` methods ES256, ES384, RS256, PS256). PS256 uses SHA-256, MGF1-SHA-256, salt length 32. Keyorix's `WithValidMethods` (`internal/oidcverify/oidc.go`, `internal/core/sso.go`) allows nine methods; RS384, RS512, ES512, PS384 and PS512 are NOT covered by these suites.
* crewjam/saml `xmlenc` (AES128GCM): key 128 bit, nonce 96 bit, tag 128 bit, empty AAD.
* HKDF-SHA256 and PBKDF2-HMAC-SHA256: library level, with the same call shape Keyorix uses (`hkdf.Key`/`hkdf.New`, `pbkdf2.Key`, `encryption.GenerateKEK` for 32-byte output). PBKDF2 vectors above 100,000 iterations are skipped to keep the run short and are counted as skipped.

Flags tolerated by design (documented here, each still has a fixed expected outcome):

* AES-GCM `SmallIv`, `LongIv` (valid in Wycheproof, rejected by the wrapper): expected outcome reject.
* ECDSA `SignatureMalleability`-type behaviour (r, n-s is also a valid signature): ES256/ES384 as used by JWT do not enforce low-S. The mutation is recorded, not asserted.
* RSA PKCS#1 v1.5 `MissingNull`: pinned like any `acceptable` vector.
* Ed25519 `SmallOrderPublicKey`, `MixedOrderPublicKey`: `acceptable`, pinned.
* HKDF `EmptySalt`: an empty salt and a hash-length block of zero bytes are the same input by RFC 5869; the mutation suite does not treat that pair as a distinct input.

## 2. Mutations

Applied to every in-scope `valid` vector. Every mutation produces an input that
differs from the original. Unless stated, a mutated input must be rejected
(signatures, AEAD) or must change the output (KDFs).

AEAD (AES-GCM wrappers): flip each bit of the tag, nonce and key; flip every bit of the first 16 bytes of ciphertext and of AAD and one bit per byte after that (up to 256 bytes); shorten the tag by 1 to 16 bytes; drop leading ciphertext; empty data; append 1, 16 and 1024 bytes; nonce lengths 0, 1, 11, 13, 16, 24; tag and nonce swaps (tag replaced by the zero-padded nonce, nonce replaced by the tag prefix, tag and ciphertext exchanged); add AAD when there is none, drop or extend AAD when there is some.

Ed25519: flip each of the 512 signature bits and 256 public key bits; flip message bits (first 32 bytes) and truncate or extend the message; truncate the signature to 63, 32, 1, 0 bytes; extend it to 65, 96, 128 bytes; replace S with S+L and S+2L (malleable form); swap R and S; use a signature of another vector; wrong key id and wrong purpose through the registry.

ECDSA P-256/P-384 (raw r||s) and RSA (PKCS#1 v1.5, PSS): flip signature bits (all bits, except P-384 where all bits of the first and last 8 bytes and one bit per byte in between), truncate, extend, zero and all-0xFF signature, r=0, s=0, r=n, s=n, r and s swapped, signature plus modulus, DER-encoded form of a P1363 signature, message bit flips and truncation. The `(r, n-s)` form is recorded only.

xmlenc (AES128GCM CipherValue): flip each bit of nonce, ciphertext and tag; truncate to every length from 0 to 28 bytes; extend. A panic on any input is a failure.

HKDF/PBKDF2: flip bits of IKM/password, salt, info (up to 64 each); change output length (prefix property must hold); change the iteration count by one; every change must alter the output.

## 3. Planted defects (the suites must catch every one; controls must stay silent)

1. AEAD wrapper that skips the tag check.
2. AEAD wrapper that accepts a truncated tag (compares only the bytes present).
3. AEAD wrapper that ignores the nonce-length rule (takes the first 12 bytes of any nonce).
4. Ed25519 wrapper that accepts high-S (reduces S modulo L before verifying), and one that ignores trailing bytes after the 64-byte signature.
5. RSA PKCS#1 v1.5 wrapper that accepts s+N.
6. A MAC comparison written with `==` (caught by the source check below).

Controls: the same wrappers built directly on the standard library primitives
with no defect. They must report zero failures.

## 4. MAC comparison source check

`maccompare_test.go` parses the non-test Go files of Keyorix's cryptographic
packages and reports any `==`/`!=` where an operand is named like a MAC
(`mac`, `hmac`, `sig`, `signature`, `tag` as the final word) and the
other operand is not a literal, `nil` or a `len` call; and any `bytes.Equal`,
`strings.EqualFold` or `reflect.DeepEqual` on such names. An operand is also
recognised through a slice expression and through `string(x)`, `[]byte(x)`,
`hex.EncodeToString(x)` or a base64 `EncodeToString(x)`. It does not see a MAC
copied into a differently named variable, other encoders, or a comparison in a
helper that receives the MAC under another name. MACs must be compared
with `hmac.Equal` or `subtle.ConstantTimeCompare`. Findings are triaged by hand
(a false positive gets an entry with a reason in the allow list). The check is
a repo-wide guard and follows `docs/guard-rollout-contract.md` (report-only on
PRs while `docs/guard-rollout.d/TestMACComparisonsAreConstantTime.tsv` exists);
a listed package with no non-test Go file fails it.

## 5. Divergence handling

Every failure is minimised, replayed at least three times, and classified as
one of: Keyorix wrapper bug, third-party library, vector-interpretation
artifact, by-design flag.

## 6. Native fuzz targets

`FuzzWycheproofAEADOpen`, `FuzzWycheproofEd25519Verify`,
`FuzzWycheproofJWTVerify` are differential: the Keyorix wrapper or the library
under test must agree (accept/reject and output) with the standard library
primitive used directly. They are seeded from the vectors when present. They
are always seeded with generated valid inputs as well (an AES-GCM ciphertext
sealed with crypto/cipher, an Ed25519 signature from a fixed seed key), and the
JWT target falls back to a fixed P-256 and RSA-2048 public key with one valid
signature each, so without the vectors every target still checks its accept
and reject branches. The JWT target fails at setup if it has no usable key.

## 7. Amendments after the first run

* Section 4: `digest` was dropped from the names. The first run flagged only
  comparisons of unkeyed hash digests of public data (audit seal and anchor
  digests), which are not authenticators. Keyed MACs, signatures and tags stay
  covered. Two `tag` hits are storage format markers and are in the allow list
  with that reason.
* Section 2: a mutated input that the standard library, called directly, also
  accepts is counted as "valid per reference" and is not a failure (for example
  the one-bit neighbour of an ECDSA edge-case vector is itself a valid
  signature).
* Section 1: a vector may be listed as a known library behaviour for one
  exact test id; it must still reproduce, and the reason is kept privately.
* Sections 1, 4 and 6 (review of #4038): section 1 names the five allowed JWT
  methods the suites do not cover; section 4 describes the operand forms the
  check recognises and the ones it does not, and its rollout status; section 6
  describes the fallback seeds, which did not exist before (the JWT target
  checked nothing without the vectors).
