- **INV-LIBCONF-xml-parser-skeleton-agreement** For any XML document that
  `mattermost/xml-roundtrip-validator` ACCEPTS, beevik/etree and an independent `encoding/xml`
  `Decoder.Token()` walk must build the SAME resolved element skeleton — the ordered sequence
  of `{namespace-uri}local` element names with their nesting depth, and each element's set of
  resolved attribute names — up to the catalogued, machine-checked benign classes (undeclared
  prefix, reserved `xml:` prefix, duplicate attribute name, etree-stricter-than-the-check;
  trailing content after the first root is out of scope). A document the validator accepts
  whose two parser skeletons disagree is a validator-bypass candidate: crewjam/saml verifies a
  signature over the etree tree (goxmldsig) but extracts the identity it trusts with an
  independent `encoding/xml` decode, and keyorix runs this exact validator at
  `internal/saml/provider.go:534` (crewjam runs it again via its vendored `internal/xmlroundtrip`)
  precisely to close that "two layers, one bytes" gap. Why: the XML signature-wrapping class,
  CVE-2020-29509/10/11 (encoding/xml round-trip instability), and the provider.go:534 /
  crewjam `unmarshalElement` split; catalogue and what the oracle does NOT verify in
  `EXPECTED-DIFFERENCES-xml-parser-differential.md`. Guard: `FuzzXMLParserDifferential` with
  its red-proof `TestXMLParserDifferential_RedProof_*` and baseline (`internal/libconformance`,
  `xml_parser_differential_fuzz_test.go` + `_redproof_test.go`).
