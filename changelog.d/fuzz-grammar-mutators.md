### Added
- **Structure-aware (grammar-based) fuzz input generation for the ASN.1 DER and XML
  parsers.** New `internal/fuzzutil/grammar` package: a DER builder (TLV tree + a
  length-consistent-by-default mutation set — indefinite length, non-minimal length,
  length overflow/under-run, wrong tag class, long-form tags, trailing bytes, deep
  nesting), an XML builder (tree + mutation set — namespace-prefix rebinding, duplicate
  IDs, comment/CDATA splitting, DOCTYPE/entity shapes, attribute reorder, whitespace,
  deep nesting, wide siblings), and a decoder that turns a fuzzer's `[]byte` into a tree
  plus mutation choices so `go test -fuzz` mutates structural choices rather than raw
  octets. Three new targets consume it: `FuzzDERStructure` (the standalone
  `encoding/asn1` + `crypto/x509.ParseCertificate`/`ParseCertificateRequest` target the
  repo previously lacked), `FuzzDERPKCS7BoundedWork` (grammar-driven counterpart of
  `FuzzDigitorusPKCS7BoundedWork`), and `FuzzSAMLXMLGrammar` (grammar-driven counterpart
  of `FuzzSAMLXMLTransitive`). Every pre-existing oracle is preserved; each new target's
  doc comment states explicitly what it does not verify.

### Testing
- Pre-registered a grammar-vs-byte-level fuzzing measurement (coverage growth and
  time-to-planted-defect across the DER, PKCS7 and SAML-XML target pairs); see the
  campaign report for the fixed rule and results.
