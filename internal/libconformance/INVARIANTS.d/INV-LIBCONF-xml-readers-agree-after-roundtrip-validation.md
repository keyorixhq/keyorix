- **INV-LIBCONF-xml-readers-agree-after-roundtrip-validation** On bytes that
  mattermost/xml-roundtrip-validator accepts and strict encoding/xml accepts,
  encoding/xml and beevik/etree build the same namespace-resolved element tree
  (element names, effective attributes, character data); every disagreement between
  the validator's and strict encoding/xml's verdicts falls in a named class; the
  verdict does not depend on reader chunking; Validate allocates a bounded amount per
  input byte. The known exceptions, namespace-ill-formed documents that rebind the
  reserved xml prefix or undeclare a prefix (xmlns:p=""), are modelled exactly and
  pinned. Why: the validator exists to stop documents two XML
  readers see differently, and keyorix's SAML path has both readers. Guard:
  `internal/libconformance/xrv_differential_fuzz_test.go:FuzzXMLRoundtripValidatorDifferential`,
  `internal/libconformance/xrv_findings_test.go:TestXRVFindingXMLPrefixRebind`,
  `internal/libconformance/xrv_findings_test.go:TestXRVFindingPrefixUndeclare`,
  `internal/saml/xml_prefix_rebind_reach_test.go:TestXMLPrefixRebindPassesBothRoundTripValidators`.
<!-- section: XML -->
