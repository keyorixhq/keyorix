- **INV-LIBCONF-yaml-json-agree** For any input encoding/json (default float64
  decode) accepts, gopkg.in/yaml.v3 must decode the same bytes to the same value (numbers
  compared by mathematical value), except for two documented splits on the allowlist with
  reasons: a duplicate JSON object key (RFC 8259 last-wins vs YAML 1.2 reject) and a JSON
  number too large for an IEEE-754 double (float64 rounding vs yaml int). A value or
  acceptance disagreement outside those classes is a decision-vs-action split where one
  config/policy reader is JSON-based and another YAML-based. Why: DF1. Guard:
  `FuzzYAMLVsJSON` + `TestYAMLJSONCompare_RedGreen` + `TestYAMLDiffAllowlistNoDead`
  (`internal/libconformance`).
