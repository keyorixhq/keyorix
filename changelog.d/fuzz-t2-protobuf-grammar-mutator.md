### Internal
- **Protobuf grammar mutator.** Added `internal/fuzzutil/grammar/protobuf.go`
  (`ProtoMsg`/`ProtoField`/`ProtoFieldMut`/`DecodeProto`) — a structure-aware
  protobuf wire-format generator following the same DER/XML pattern already in this
  package. The fuzzer's bytes decode into a message tree plus four mutation choices
  (non-minimal varint, wrong wire type, overlong varint, length-prefix delta); the
  tree serialises to well-formed-by-construction protobuf; the engine then mutates
  structural choices instead of raw bytes, reaching packed fields, deep nesting,
  groups, and wire-type mismatches that raw byte mutation rarely produces. Consuming
  oracle added in `internal/libconformance/complexity_protobuf_grammar_fuzz_test.go`.
