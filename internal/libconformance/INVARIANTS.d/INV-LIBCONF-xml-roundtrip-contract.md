- **INV-LIBCONF-xml-roundtrip-contract** For any XML document that
  `mattermost/xml-roundtrip-validator` ACCEPTS, an independent `encoding/xml` round trip —
  decode (RawToken) → re-serialise (`xml.Encoder`) → decode — must leave the document's
  **element skeleton** (the ordered, depth-tagged sequence of element local names) AND its
  **`xml.Unmarshal` view** (element local name + attribute name=value + text, recursively — the
  information crewjam's structs are populated from) unchanged, and the re-serialised bytes must
  still parse. A document the validator accepts whose round trip injects/drops/renests an
  element (the signature-wrapping overflow primitive) or changes the unmarshalled structure is a
  validator-contract-violation candidate. This is the validator's OWN documented promise
  (`go doc`: "Validate makes sure the given XML bytes survive round trips through encoding/xml
  without mutations"; "CheckToken … returns an error if the newly calculated token differs"),
  which keyorix depends on at `internal/saml/provider.go:534` before crewjam's `xml.Unmarshal`.
  Why: the XML signature-wrapping class and CVE-2020-29509/10/11 (encoding/xml round-trip
  instability) — xrv exists specifically to guarantee the re-serialise step is stable, so a
  counterexample is a hole in the guard keyorix trusts. Distinct from and additive to
  [[INV-LIBCONF-xml-parser-skeleton-agreement]], which compares an etree PARSE against an
  encoding/xml PARSE of the same bytes and never re-serialises. Namespace prefix re-spelling
  (encoding/xml cannot round-trip a prefix; the validator normalises it via
  `fixNamespacePrefixes`) and adjacent-CDATA coalescing are catalogued representational
  differences (RT-E1/RT-E2), handled by the namespace-robust element skeleton and the semantic
  unmarshal view; what the oracle does NOT verify is listed in the target's file header. Guard:
  `FuzzXMLRoundtripContract` with its red-proof `TestXMLRoundtripContract_RedProof_*` and
  baseline (`internal/libconformance`, `xml_roundtrip_contract_fuzz_test.go` +
  `_redproof_test.go`).
