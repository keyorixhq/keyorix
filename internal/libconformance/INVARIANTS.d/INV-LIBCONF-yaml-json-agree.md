- **INV-LIBCONF-yaml-json-agree** For any input encoding/json (default float64
  decode) accepts, gopkg.in/yaml.v3 must decode the same bytes to the same value (numbers
  compared by mathematical value), except for the documented splits on the allowlist with
  reasons (see `yamlDiffAllow`): a duplicate JSON object key (RFC 8259 last-wins vs YAML
  1.2 reject), a JSON number changed only by float64 rounding (vs yaml int), YAML line
  separators in strings, invalid UTF-8, and a hard YAML reject of tab/control bytes. A value or
  acceptance disagreement outside those classes is a decision-vs-action split where one
  config/policy reader is JSON-based and another YAML-based. Why: DF1. Guard:
  `FuzzYAMLVsJSON` + `TestYAMLJSONCompare_RedGreen` + `TestYAMLDiffAllowlistNoDead`
  (`internal/libconformance`).
