- **INV-FUZZCLOUD-yaml-decode-bounded** `go.yaml.in/yaml/v4` decoding (the module every live caller imports), as
  `internal/config` and `cli/internal/credstore` run it on operator-provided
  config/credential files, is bounded: arbitrary bytes decode without panic and
  within a generous time bound, and a *successful* decode re-marshals to a
  bounded size — an anchor/alias "billion laughs" the decoder EXPANDED would
  blow the size bound, whereas yaml v4 rejects it (confirmed: the alias-bomb
  seed is rejected, not expanded). Does NOT check round-trip fidelity (YAML is
  non-canonical), the Keyorix schema layer, or peak allocation. Why: every live
  config/credstore caller decodes with v4, while the existing library-level
  YAML target (`internal/libconformance/complexity_yaml_fuzz_test.go`) covers
  the v3 module, which has no production importer. Guard:
  `FuzzYAMLDecodeBoundedWork`
  (`fuzz/thirdparty/yaml/yaml_boundedwork_fuzz_test.go`), red-proofed by
  inflating the decoded value past the size bound.
