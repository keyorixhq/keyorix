# pkcs7 API inventory — Stage 1 (LS1)

**Package:** `github.com/digitorus/pkcs7`  
**Version:** `v0.0.0-20261104125046-a476de3098e4`  
**Generated:** 2026-11-20 by `scripts/fuzzing/apigen/main.go`  
**Source:** `docs/fuzz/library-surface/api-inventory.json`

---

## Summary counts

| Metric | Count |
|--------|------:|
| Total exported symbols | 27 |
| Symbols covered by existing fuzz targets | 1 |
| Symbols uncovered | 26 |
| Existing fuzz harnesses | 3 (all cover `Parse`) |

### Parameter classes (across all symbols)

| Class | Count | Meaning |
|-------|------:|---------|
| `structured` | 18 | Typed objects: `*x509.Certificate`, `x509.VerifyOptions`, `*x509.CertPool`, etc. |
| `untrusted-bytes` | 7 | `[]byte` or `string` — raw caller-controlled bytes |
| `handle` | 5 | Opaque handles: `crypto.PrivateKey`, `crypto.Signer`, `interface{}` |
| `config` | 1 | Config type: `time.Time` |

---

## Coverage gap

**1 of 27 symbols covered** by existing fuzz targets; 26 uncovered.

The three existing harnesses all exercise `Parse` only:

| Fuzz target | File | Oracle |
|-------------|------|--------|
| `FuzzDigitorusPKCS7BoundedWork` | `internal/libconformance/digitorus_boundedwork_fuzz_test.go` | Bounded time+memory |
| `FuzzDERPKCS7BoundedWork` | `internal/libconformance/der_pkcs7_boundedwork_fuzz_test.go` | Grammar-driven DER, bounded-work |
| `FuzzPKCS7TimeTravelOracle` | `internal/libconformance/timetravel_pkcs7_fuzz_test.go` | Time-travel differential vs older version |

---

## govulncheck pre-screen

`govulncheck` is not available offline (golang.org/x/vuln not in module cache).  
Manual check against known advisories:

- **GHSA-3xqc-rpq8-wgp9** (BER-length memory amplification in `Parse`) —
  **fixed** in pinned version; closure documented in `docs/security-closures.d/digitorus-pkcs7-ber-dos-001.tsv`.
- **CBC padding** (PR #25, 2026-11-04) — **fixed** in pinned version.
- No other known open advisories for the pinned version.

**Result:** govulncheck pre-screen passes for `v0.0.0-20261104125046-a476de3098e4`.

---

## Top 20 symbols by risk score

Risk score (0–100) combines: Keyorix-caller tier, decrypt/verify/sign-path heuristic,
untrusted-bytes parameter presence, AST allocation heuristic, and branch-count
proxy for cyclomatic complexity. See `scripts/fuzzing/apigen/main.go scoreSymbol()`.

**Scoring note on VerifyWithOpts:** `(*PKCS7).VerifyWithOpts` (score 52) is a
tier-1 Keyorix caller — `internal/notary/notary.go` calls it directly with a
TSA-response-derived `*PKCS7`. Its score ties with `Encrypt` (tier-3) because
`VerifyWithOpts` takes `x509.VerifyOptions` (config class) rather than raw bytes,
so the untrusted-bytes bonus doesn't apply. For Stage 2 scheduling, VerifyWithOpts
should be **treated as Tier 1A** (direct Keyorix call path) regardless of its
numerical score.

| Rank | Score | Sym | BW | Covered | Recv | Key reason |
|-----:|------:|-----|:--:|:-------:|------|-----------|
| 1 | 80 | `Parse` | A | ✓ (3 targets) | — | tier-1 caller + untrusted-bytes + is-parser |
| 2 | 65 | `DecryptUsingPSK` | m | | `*PKCS7` | tier-2-adjacent + untrusted-bytes key + decrypt-path |
| 3 | 52 | `Encrypt` | — | | — | untrusted-bytes content + allocates-from-input + complexity |
| 3 | 52 | `VerifyWithOpts` | — | | `*PKCS7` | **tier-1 Keyorix caller** + verify-path |
| 5 | 49 | `Decrypt` | — | | `*PKCS7` | tier-2-adjacent + decrypt-path |
| 6 | 42 | `Verify` | — | | `*PKCS7` | tier-2-adjacent + verify-path |
| 6 | 42 | `VerifyWithChain` | — | | `*PKCS7` | tier-2-adjacent + verify-path |
| 6 | 42 | `VerifyWithChainAtTime` | — | | `*PKCS7` | tier-2-adjacent + verify-path |
| 9 | 38 | `EncryptUsingPSK` | — | | — | untrusted-bytes content+key |
| 9 | 38 | `NewSignedData` | A | | — | untrusted-bytes data + is-parser |
| 11 | 35 | `UnmarshalSignedAttribute` | — | | `*PKCS7` | tier-2-adjacent |
| 12 | 34 | `AddSignerChain` | — | | `*SignedData` | append-based alloc in body |
| 13 | 33 | `GetOnlySigner` | — | | `*PKCS7` | tier-2-adjacent |
| 14 | 30 | `DegenerateCertificate` | A | | — | untrusted-bytes input |
| 14 | 30 | `SignWithoutAttr` | — | | `*SignedData` | append-based alloc in body |
| 16 | 20 | `AddCertificate` | — | | `*SignedData` | append-based alloc |
| 16 | 20 | `AddSigner` | — | | `*SignedData` | structured cert input |
| 18 | 18 | `GetDigestOIDForSignatureAlgorithm` | — | | — | utility |
| 18 | 18 | `GetSignedData` | — | | `*SignedData` | getter only |
| 18 | 18 | `SetEncryptionAlgorithm` | — | | `*SignedData` | config setter |

---

## Full symbol table

Sorted by risk score. P = can_panic; A = allocates_from_input (direct body); A* = known alloc in private helper (not caught by AST heuristic).

| Score | Sym | Kind | Recv | BW | P | A | Params (classified) |
|------:|-----|------|------|----|---|---|---------------------|
| 80 | `Parse` | func | — | A | | A* | `data []byte` [untrusted-bytes] |
| 65 | `DecryptUsingPSK` | method | `*PKCS7` | m | | A* | `key []byte` [untrusted-bytes] |
| 52 | `Encrypt` | func | — | — | | A | `content []byte` [untrusted-bytes], `recipients []*x509.Certificate` [structured] |
| 52 | `VerifyWithOpts` | method | `*PKCS7` | — | | | `opts x509.VerifyOptions` [config] |
| 49 | `Decrypt` | method | `*PKCS7` | — | | A* | `cert *x509.Certificate` [structured], `pkey crypto.PrivateKey` [handle] |
| 42 | `Verify` | method | `*PKCS7` | — | | | *(no params)* |
| 42 | `VerifyWithChain` | method | `*PKCS7` | — | | | `truststore *x509.CertPool` [structured] |
| 42 | `VerifyWithChainAtTime` | method | `*PKCS7` | — | | | `truststore *x509.CertPool` [structured], `currentTime time.Time` [config] |
| 38 | `EncryptUsingPSK` | func | — | — | | | `content []byte` [untrusted-bytes], `key []byte` [untrusted-bytes] |
| 38 | `NewSignedData` | func | — | A | | | `data []byte` [untrusted-bytes] |
| 35 | `UnmarshalSignedAttribute` | method | `*PKCS7` | — | | | `attributeType asn1.ObjectIdentifier` [structured], `out interface{}` [handle] |
| 34 | `AddSignerChain` | method | `*SignedData` | — | | A | `ee *x509.Certificate` [structured], `keyOrSigner interface{}` [handle], `parents []*x509.Certificate` [structured], `config SignerInfoConfig` [config] |
| 33 | `GetOnlySigner` | method | `*PKCS7` | — | | | *(no params)* |
| 30 | `DegenerateCertificate` | func | — | A | | | `cert []byte` [untrusted-bytes] |
| 30 | `SignWithoutAttr` | method | `*SignedData` | — | | A | `ee *x509.Certificate` [structured], `keyOrSigner interface{}` [handle], `config SignerInfoConfig` [config] |
| 20 | `AddCertificate` | method | `*SignedData` | — | | A | `cert *x509.Certificate` [structured] |
| 20 | `AddSigner` | method | `*SignedData` | — | | | `ee *x509.Certificate` [structured], `keyOrSigner interface{}` [handle], `config SignerInfoConfig` [config] |
| 18 | `GetDigestOIDForSignatureAlgorithm` | func | — | — | | | `digestAlg x509.SignatureAlgorithm` [structured] |
| 18 | `GetSignedData` | method | `*SignedData` | — | | | *(no params)* |
| 18 | `SetEncryptionAlgorithm` | method | `*SignedData` | — | | | `d asn1.ObjectIdentifier` [structured] |
| 10 | `Detach` | method | `*SignedData` | — | | | *(no params)* |
| 10 | `Error` | method | `*MessageDigestMismatchError` | — | | | *(no params)* |
| 10 | `Finish` | method | `*SignedData` | — | | | *(no params)* |
| 10 | `RemoveAuthenticatedAttributes` | method | `*SignedData` | — | | | *(no params)* |
| 10 | `RemoveUnauthenticatedAttributes` | method | `*SignedData` | — | | | *(no params)* |
| 10 | `SetContentType` | method | `*SignedData` | — | | | `contentType asn1.ObjectIdentifier` [structured] |
| 10 | `SetDigestAlgorithm` | method | `*SignedData` | — | | | `d asn1.ObjectIdentifier` [structured] |

**A* note:** `Parse` and `(*PKCS7).Decrypt`/`DecryptUsingPSK` allocate from
input-derived sizes inside private helpers (`ber2der`, `eci.decrypt`), not in
their direct AST bodies. The AST heuristic flags only direct-body `make([]byte,
n)` calls; alloc-in-callee is a manual annotation. `Parse`'s BER allocation was
the root cause of GHSA-3xqc-rpq8-wgp9.

---

## bwgen gap analysis

bwgen found 3 package-level function targets + 1 method out of 27 symbols:

| Shape | Symbols found by bwgen | Remaining (need method walker) |
|-------|------------------------|-------------------------------|
| A — `func([]byte) (T, error)` | `Parse`, `DegenerateCertificate`, `NewSignedData` | — |
| m — method with `[]byte` first param | `DecryptUsingPSK` (reported, not emitted) | — |
| None — multi-param or no byte-input | — | 23 symbols |

The 23 symbols outside bwgen's A/B/U shapes require either:
- A constructor-synthesising wrapper (future Stage 2 work), or
- Hand-written harnesses using `go-fuzz-headers` for the structured inputs.

---

## Stage 2 priority targets

Based on the full risk ranking plus Keyorix-caller tier:

**Tier 1A — Must fuzz (Keyorix calls directly on untrusted input):**
1. `(*PKCS7).VerifyWithOpts` — called in `internal/notary` with TSA response bytes

**Tier 1B — High risk, uncovered (decrypt/CBC surface):**
2. `(*PKCS7).DecryptUsingPSK` — takes raw PSK bytes, BER-decoded ciphertext
3. `(*PKCS7).Decrypt` — ML-KEM/RSA decapsulation; structured params but adversarial cert

**Tier 2 — Verify surface (signature bypass potential):**
4. `(*PKCS7).Verify`
5. `(*PKCS7).VerifyWithChain`
6. `(*PKCS7).VerifyWithChainAtTime`

**Tier 3 — Signing surface + utility:**
7. `Encrypt`, `EncryptUsingPSK`
8. `NewSignedData` + `(*SignedData).AddSigner` + `(*SignedData).AddSignerChain` + `Finish`
9. `DegenerateCertificate`

---

## Portability test: `github.com/google/uuid` v1.6.0

The apigen tool was run on a second library to verify portability:

```
go run scripts/fuzzing/apigen/main.go \
  -pkg github.com/google/uuid \
  -srcdir /root/go/pkg/mod/github.com/google/uuid@v1.6.0 \
  -version v1.6.0
```

**Results:**

| Metric | Value |
|--------|------:|
| Total exported symbols | 59 |
| Coverage | 0 / 59 (no existing fuzz targets) |
| untrusted-bytes params | 18 |
| structured params | 11 |
| handle params | 2 |
| Top symbol by risk | `Parse` (string input, is-parser, 49) |

The generator correctly identified `Parse`, `ParseBytes`, and `MustParse` as the
top risk symbols, with `MustParse` classified as panic-by-contract (Must* prefix).
Full output: `.scratch/uuid-inventory.json`.

---

## Generator notes (gaps and limitations)

1. **Workspace contamination**: Running `packages.Load` from the keyorix workspace
   root fails (workspace go.sum includes modules not in the offline cache). Fix: run
   from the library's own source directory via `packages.Config{Dir: srcdir}`. The
   `-srcdir` flag exposes this.

2. **Alloc-in-callee**: The AST heuristic detects `make()/append()` only in the
   exported function's direct body, not in private helpers it calls. `Parse` and
   `Decrypt`/`DecryptUsingPSK` are known to allocate from input in private helpers.
   This is documented as `alloc_in_callee` in the JSON schema (currently false for
   all — requires manual annotation or inter-procedural analysis).

3. **govulncheck**: Not available offline. Manual check substituted.

4. **Score ties**: `(*PKCS7).VerifyWithOpts` (tier-1 Keyorix caller) ties with
   `Encrypt` (tier-3) at score 52 because VerifyWithOpts doesn't take untrusted
   bytes directly. Stage 2 scheduling should use the caller-tier column, not the
   raw score, as the primary sort key.

5. **bwgen output not auto-merged**: Running bwgen with `-out` to generate bounded-work
   fuzz targets was not done in Stage 1 (per survey.md "NEVER auto-merge"). Stage 2
   should run bwgen with `-out` for the 3 matched function shapes, then verify each
   target is green on seeds before promoting.
