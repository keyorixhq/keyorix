- **INV-LIBCONF-pkcs7-unmarshal-attr-and-signwithoutattr-bounded-work** Three
  digitorus/pkcs7 methods added in LS4 must never panic and never hang on ANY
  input accepted by their Go API: `(*PKCS7).UnmarshalSignedAttribute` (called
  for each of the three standard signed-attribute OIDs — ContentType,
  MessageDigest, SigningTime — on a parsed, attacker-controlled envelope),
  `(*PKCS7).GetOnlySigner` (certificate lookup on arbitrary parsed token), and
  `(*SignedData).SignWithoutAttr` (signs arbitrary plaintext content without
  appending authenticated attributes to the SignerInfo).
  `UnmarshalSignedAttribute` is the highest-priority of the three: it performs
  an ASN.1 `Unmarshal` on a raw attribute value whose bytes come from the
  attacker-supplied PKCS7 envelope, so a panic or hang in the unmarshal path
  is directly reachable from any caller that passes attacker-controlled
  signed-data to this function.  `GetOnlySigner` and `SignWithoutAttr` carry
  only the never-panic/never-hang oracle; no differential or sign-then-verify
  oracle is applied (tokens produced by `SignWithoutAttr` cannot be verified
  by `Verify`/`VerifyWithChain` because those verifiers require authenticated
  attributes, which `SignWithoutAttr` deliberately omits).  Why: all three
  symbols were unguarded by any fuzz harness prior to LS4; `UnmarshalSignedAttribute`
  allocates from the input inside an `encoding/asn1` unmarshal path that had no
  panic coverage.  Guard: `FuzzPKCS7UnmarshalSignedAttribute`,
  `FuzzPKCS7GetOnlySigner`, `FuzzPKCS7SignWithoutAttr` (`internal/libconformance`).
