- **INV-LIBCONF-protobuf-grammar-structural-complexity** The `google.golang.org/protobuf`
  runtime's wire decoder must allocate O(grammar-input-length) for ANY structure-aware
  input from `grammar.DecodeProto`: packed repeated fields, deep nested messages, groups,
  non-minimal varints, and wide flat messages. This extends the sibling raw-bytes oracle
  (`FuzzProtobufDecodeComplexity`) to the structural shapes raw byte mutation rarely
  reaches — packed fields (a flat allocation path the recursion limit alone does not
  bound), deep chains (the recursion limit path), and groups (deprecated but legal). Why:
  `FuzzProtobufDecodeComplexity`'s doc comment explicitly notes "most fields land in the
  UNKNOWN-field set" because raw bytes rarely produce schema-matching wire; the grammar
  target gives the engine single-choice access to the structural amplification shapes.
  Guard: `FuzzProtobufGrammarComplexity`
  (`internal/libconformance/complexity_protobuf_grammar_fuzz_test.go`).
