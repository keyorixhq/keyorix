# LS5 — pkcs7 remaining 10-symbol decision

**Date**: 2026-11-21  
**Library**: github.com/digitorus/pkcs7 v0.0.0-20261104125046-a476de3098e4  
**Branch**: docs/ls5-library-fuzzing-pkcs7-remaining-decision  
**Prior coverage**: 17/27 exported symbols (LS2–LS4)

---

## Background

LS3 and LS4 LEFTOVERS flagged 10 remaining symbols as "setters/trivial formatters on
`*SignedData`" and deferred the decision to LS5: either build cheap bwgen-style never-panic
targets, or formally DROP them with justification. This document records the decision for
each symbol after reading its implementation in the pinned library source
(`/root/go/pkg/mod/github.com/digitorus/pkcs7@v0.0.0-20261104125046-a476de3098e4/`).

Decision criteria (from CLAUDE.md "Explicitly not building"):
- **BUILD**: a genuine attacker-byte-shaped input exists AND a real oracle (never-panic/
  never-hang, or differential/round-trip property) is possible and worth the fuzz budget.
- **COMPOSE**: no standalone oracle, but meaningful exercise inside an existing composed
  harness with a real oracle.
- **DROP**: internal-state setter or trivial formatter, no attacker-byte input shape, no
  meaningful oracle beyond "doesn't panic on a near-fixed-size enum/typed input".

---

## Decision table

| Symbol | Sig (file:line) | Decision | One-line reason |
|--------|-----------------|----------|-----------------|
| `(*SignedData).AddCertificate` | sign.go:304 | DROP | Input is `*x509.Certificate` (parsed struct), not bytes; append-to-slice, no parser exposure |
| `(*SignedData).SetContentType` | sign.go:310 | DROP | Typed OID setter (`sd.sd.ContentInfo.ContentType = contentType`); no parsing, no failure path |
| `(*SignedData).Detach` | sign.go:316 | DROP | No args; struct-field assignment; resulting detached token covered by existing harnesses |
| `(*SignedData).GetSignedData` | sign.go:321 | DROP | No input; returns unexported `*signedData`; nothing testable externally |
| `(*SignedData).RemoveAuthenticatedAttributes` | sign.go:341 | COMPOSE | Exercises verify.go's `len(AuthenticatedAttributes)==0` branch; real oracle: VerifyWithChain returns error (not panic) |
| `(*SignedData).RemoveUnauthenticatedAttributes` | sign.go:348 | DROP | No unauthenticated attrs in standard sign harness; no-op toggle; unauthenticated attrs are not in signature computation |
| `(*SignedData).SetDigestAlgorithm` | sign.go:127 | DROP | Typed OID setter; unknown OID causes AddSigner error (not panic); no new code path exposed |
| `(*SignedData).SetEncryptionAlgorithm` | sign.go:134 | DROP | Typed OID setter; only used in SignWithoutAttr path; that path is covered by FuzzPKCS7SignWithoutAttr |
| `GetDigestOIDForSignatureAlgorithm` | pkcs7.go:126 | DROP | Pure switch over typed-int enum; no allocation, no external calls; cannot panic for any int input |
| `(*MessageDigestMismatchError).Error` | verify.go:289 | DROP | `fmt.Sprintf` with `%X` on two []byte fields; fmt.Sprintf is panic-safe on any input; no pkcs7-specific code path |

---

## Per-symbol justifications

### 1. AddCertificate (`sign.go:304`)

```go
func (sd *SignedData) AddCertificate(cert *x509.Certificate) {
    sd.certs = append(sd.certs, cert)
}
```

**DROP.** Input is `*x509.Certificate`, a fully-parsed struct from `crypto/x509`. No
attacker-byte input exists at this method boundary — the bytes are parsed by x509 before
reaching here. Appending a typed value to a slice cannot panic. The only observable effect
is that `Finish()` calls `marshalCertificates(sd.certs)` which writes `cert.Raw` to a
buffer; `cert.Raw` is a []byte field on the x509 struct, already validated during parsing.
Building a never-panic harness would test `crypto/x509`'s parsing, not pkcs7's AddCertificate.

### 2. SetContentType (`sign.go:310`)

```go
func (sd *SignedData) SetContentType(contentType asn1.ObjectIdentifier) {
    sd.sd.ContentInfo.ContentType = contentType
}
```

**DROP.** `asn1.ObjectIdentifier` is a typed `[]int` value. The assignment stores the OID
in the contentInfo struct field. No parsing, no allocation, no failure path. Setting to any
OID — including nil, empty, or an OID with large arc values — cannot panic. The resulting
content type appears in the encoded token; a downstream oracle (sign-then-verify) would just
test whether pkcs7 verification accepts non-OIDData content types, which is a pkcs7
conformance question unrelated to panic safety.

### 3. Detach (`sign.go:316`)

```go
func (sd *SignedData) Detach() {
    sd.sd.ContentInfo = contentInfo{ContentType: OIDData}
}
```

**DROP.** No arguments. Replaces contentInfo with an empty struct (OIDData type, no content
bytes). No input, no parsing, no allocation. The resulting token is a standard detached
signature — `Parse` will succeed, `VerifyWithChain` will not find the content and will fail
to compute a digest match. This failure path is expected behavior for detached signatures
and does not represent a panic risk. The existing never-panic oracle in FuzzPKCS7Sign
already covers the Finish() call that follows Detach(); exercising this toggle with a full
sign-then-verify would only demonstrate that the library correctly returns an error (not
panic) for a detached signature, which is already derivable from code inspection.

### 4. GetSignedData (`sign.go:321`)

```go
func (sd *SignedData) GetSignedData() *signedData {
    return &sd.sd
}
```

**DROP.** No input. Returns a pointer to `signedData`, which is an unexported type. The
returned value cannot be used or inspected outside the `pkcs7` package. There is no
testable property of this function accessible from a test in a different package — calling
it and discarding the result exercises exactly one statement (`return &sd.sd`), which cannot
panic and reveals nothing about library correctness.

### 5. RemoveAuthenticatedAttributes (`sign.go:341`)

```go
func (sd *SignedData) RemoveAuthenticatedAttributes() {
    for i := range sd.sd.SignerInfos {
        sd.sd.SignerInfos[i].AuthenticatedAttributes = nil
    }
}
```

**COMPOSE.** When called between `AddSigner` and `Finish()`, it clears the authenticated
attributes from every signerInfo. The resulting token has no authenticated attributes
in its ASN.1 encoding.

The real oracle is in `verifySignature` (verify.go:161):

```go
if len(signer.AuthenticatedAttributes) > 0 {
    // ... validates digest, marshals attrs, sets signedData = marshaledAttrs
}
// else: signedData remains p7.Content (the raw payload)
return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
```

When AuthenticatedAttributes is nil, `signedData = p7.Content`. But the ECDSA signature
was computed over `marshalAttributes(finalAttrs)` (the authenticated attrs) during
`AddSigner` (sign.go:217–224). So `CheckSignature(sigalg, p7.Content, sig_over_attrs)`
will return a signature mismatch error — not panic. The oracle asserts this: when
RemoveAuthenticatedAttributes was called, `VerifyWithChain` MUST return non-nil error.
When it was not called, the existing round-trip oracle holds (VerifyWithChain succeeds).

This exercises the `len(AuthenticatedAttributes) == 0` branch in `verifySignature` and
`verifySignatureAtTime`, confirming the library handles this state by returning an error
rather than panicking or silently accepting an invalid signature.

### 6. RemoveUnauthenticatedAttributes (`sign.go:348`)

```go
func (sd *SignedData) RemoveUnauthenticatedAttributes() {
    for i := range sd.sd.SignerInfos {
        sd.sd.SignerInfos[i].UnauthenticatedAttributes = nil
    }
}
```

**DROP.** The standard `AddSigner` call in the sign harness uses
`pkcs7.SignerInfoConfig{}` (zero value), which means `ExtraUnsignedAttributes` is nil.
So `UnauthenticatedAttributes` starts as nil and calling RemoveUnauthenticatedAttributes
is a no-op toggle. Even if unauthenticated attrs were explicitly added: the signature is
computed over `marshalAttributes(finalAttrs)` = authenticated attrs ONLY (sign.go:218);
unauthenticated attrs are not included. Verification also ignores them: neither
`verifySignature` nor `verifySignatureAtTime` reads `UnauthenticatedAttributes`. The
oracle "token still verifies" after removing unauthenticated attrs is trivially true from
code inspection, not a fuzzing question. Building a harness that explicitly adds
unauthenticated attrs to test their removal would be constructing an artificial scenario
to cover a function whose behavior is structurally defined by the ASN.1 schema.

### 7. SetDigestAlgorithm (`sign.go:127`)

```go
func (sd *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
    sd.digestOid = d
}
```

**DROP.** Typed OID setter. Called before `AddSigner`. Setting an unsupported OID causes
`AddSigner` to return an error from `getHashForOID` (pkcs7.go:108) — not panic. Setting a
supported OID (SHA-256, SHA-384, SHA-512) works normally. `FuzzPKCS7Sign` already exercises
the signing path with the default SHA-1 digestOid; the algorithm path is parametric in the
OID but the structural code path through `AddSigner` is the same regardless of which known
OID is used. No attacker-byte input.

### 8. SetEncryptionAlgorithm (`sign.go:134`)

```go
func (sd *SignedData) SetEncryptionAlgorithm(d asn1.ObjectIdentifier) {
    sd.encryptionOid = d
}
```

**DROP.** Typed OID setter. This field (`sd.encryptionOid`) is passed as
`configuredSignatureOID` only in `getCMSSignerAlgorithm` when called from `SignWithoutAttr`
(sign.go:253). In `AddSigner`/`AddSignerChain`, `configuredSignatureOID` is nil (sign.go:154)
and `encryptionOid` is ignored. Setting this field before `AddSigner` has no effect on the
signing path. `FuzzPKCS7SignWithoutAttr` covers the SignWithoutAttr code path where
`encryptionOid` is used (with the default nil OID, which causes the OID to be derived from
the key). No attacker-byte input.

### 9. GetDigestOIDForSignatureAlgorithm (`pkcs7.go:126`)

```go
func GetDigestOIDForSignatureAlgorithm(digestAlg x509.SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
    switch digestAlg {
    case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
        return OIDDigestAlgorithmSHA1, nil
    // ... ~8 more cases
    }
    return nil, fmt.Errorf("pkcs7: cannot convert hash to oid, unknown hash algorithm")
}
```

**DROP.** Input is `x509.SignatureAlgorithm`, a typed `int` (defined in `crypto/x509`).
The entire implementation is a switch statement returning pre-defined package-level OID
constants or a `fmt.Errorf`. No allocation, no parsing, no external calls. Cannot panic
for any int value — a switch on a typed int either matches a case (returning a constant)
or falls through to `fmt.Errorf` (also safe). The input domain has ~10 known values and
the rest return error. Building a never-panic harness would assert a property trivially
guaranteed by the Go runtime: a switch/return over typed ints cannot panic.

### 10. MessageDigestMismatchError.Error (`verify.go:289`)

```go
func (err *MessageDigestMismatchError) Error() string {
    return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X",
        err.ExpectedDigest, err.ActualDigest)
}
```

**DROP.** `fmt.Sprintf` with `%X` on two `[]byte` fields. The `%X` verb on any `[]byte` —
including nil, empty, and arbitrarily large — is defined behavior in the Go standard library:
nil → `""`, large → hex string, no panic, bounded allocation proportional to the input length.
Building a harness would assert `fmt.Sprintf` semantics (which are covered by Go's own test
suite), not pkcs7-specific behavior. The `ExpectedDigest` and `ActualDigest` fields are set
by the library's own digest computation (`subtle.ConstantTimeCompare` failing in
`verifySignature`), not directly from attacker bytes at the `Error()` call level.

---

## Coverage after LS5

| Stage | Covered | Notes |
|-------|---------|-------|
| LS2 | 7/27 | Parse, 4×Verify, 2×Decrypt |
| LS3 | 14/27 | +DegenerateCertificate, NewSignedData, 2×AddSigner, Finish, 2×Encrypt |
| LS4 | 17/27 | +UnmarshalSignedAttribute, GetOnlySigner, SignWithoutAttr |
| **LS5** | **18/27** | +RemoveAuthenticatedAttributes (COMPOSE) |

9 symbols formally dropped (out of scope): AddCertificate, SetContentType, Detach,
GetSignedData, RemoveUnauthenticatedAttributes, SetDigestAlgorithm,
SetEncryptionAlgorithm, GetDigestOIDForSignatureAlgorithm,
MessageDigestMismatchError.Error.

**Pilot status**: CLOSED at 18/27. The remaining 9/27 are out of scope by DROP decision:
no attacker-byte input shape, no meaningful oracle beyond trivially-derivable language
guarantees. The 9th uncovered symbol (GetDigestOIDForSignatureAlgorithm) and the 10th
(MessageDigestMismatchError.Error) represent pure-enum dispatch and fmt formatting
respectively — neither warrants a fuzz target.
