### Testing
- **Cross-library parser-differential fuzz targets (DF1).** Four new differential
  fuzzers that feed ONE input to two independent readings and fail on a disagreement
  that is not a documented library difference, each with an EXPECTED-DIFFERENCE allowlist
  (reason per entry) and a dead-entry guard test: `FuzzXMLEtreeVsEncodingXML`
  (beevik/etree vs encoding/xml, namespace-resolved structural view — the SAML
  signature-wrapping substrate), `FuzzOpenAPIVsJSONSchema` (getkin/kin-openapi vs
  santhosh-tekuri/jsonschema/v6 verdict agreement), `FuzzYAMLVsJSON` (gopkg.in/yaml.v3 vs
  encoding/json on JSON-that-is-also-YAML — duplicate-key and float64-precision splits),
  and `FuzzIdentityFoldVsPrecis` (Keyorix's custom identity fold vs the RFC 8265
  `precis.UsernameCaseMapped` an external IdP would use — the fullwidth-`ＡＤＭＩＮ`/`admin`
  shadow-admin shape). Each oracle documents what it does NOT verify. See
  `internal/libconformance/INVARIANTS.d/` and the DF1 report.
