- **INV-THIRDPARTY-yaml-decode-bounded** `gopkg.in/yaml.v3` decoding, as
  `internal/config` and `cli/internal/credstore` run it on operator-provided
  config/credential files, is bounded: arbitrary bytes decode without panic and
  within a generous time bound, and a *successful* decode re-marshals to a
  bounded size — an anchor/alias "billion laughs" the decoder EXPANDED would
  blow the size bound, whereas yaml.v3 rejects it (confirmed: the alias-bomb
  seed is rejected, not expanded). Does NOT check round-trip fidelity (YAML is
  non-canonical), the Keyorix schema layer, or peak allocation. Why: reachgen
  ranked yaml.v3 decode as the top uncovered config-provenance parser. Guard:
  `FuzzYAMLDecodeBoundedWork`
  (`fuzz/thirdparty/yaml/yaml_boundedwork_fuzz_test.go`), red-proofed by
  inflating the decoded value past the size bound.
