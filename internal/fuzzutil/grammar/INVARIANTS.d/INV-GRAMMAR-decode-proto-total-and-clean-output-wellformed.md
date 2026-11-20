- **INV-GRAMMAR-decode-proto-total-and-clean-output-wellformed** `DecodeProto` is total and
  bounded for ANY input (including empty and truncated): it never panics, and the tree it
  builds is capped by the same `maxRecurseDepth`/`maxChildren`/`maxNodes`/`maxContentLen`/
  `maxChainDepth`/`maxSiblings` constants (see `decode.go`) so the builder itself cannot
  OOM or hang before the target's parser even runs. Separately, output built with the ZERO
  mutation set must be well-formed protobuf wire format by construction: a zero-mutation
  `ProtoMsg` round-trips through `google.golang.org/protobuf/encoding/protowire` and each
  decoded field has the expected number, type, and value — otherwise a fuzz target that fed
  "clean" grammar output could never reach the parser it means to exercise, and a green run
  would prove nothing. Mutation flags (`ProtoFieldMut`) are the ONLY thing allowed to
  produce parser-rejected bytes, and each one must actually perturb the encoding (an inert
  mutation gives the engine a dead choice). Why: same soundness requirement as
  INV-GRAMMAR-decode-total-and-clean-output-wellformed — a generator that crashes or emits
  malformed "clean" bytes is itself the bug, not the target. Guard:
  `TestDecodeProtoTotal`, `TestProtoZeroMutationRoundTrips`, `TestProtoDeepChain`,
  `TestProtoMutationsChangeBytes`, `TestProtoNonMinimalVarintIsAccepted`,
  `TestProtoOverlongVarintIsRejected`, `TestProtoWrongWireTypeChangesTag`,
  `TestProtoLenDeltaChangesLength`, `TestProtoNestedMsgZeroMutation`,
  `TestProtoGroupZeroMutation`, `TestProtoPackedFieldZeroMutation`
  (`internal/fuzzutil/grammar/protobuf_test.go`).
