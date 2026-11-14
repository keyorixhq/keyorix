package libconformance

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// FuzzProtobufDecodeComplexity is a cost-per-byte oracle over the
// google.golang.org/protobuf runtime's wire decoder, the code every gRPC
// service method runs on untrusted bytes before the handler sees anything:
// server/grpc/server.go:186 sets MaxRecvMsgSize (EffectiveMaxRequestBodyBytes,
// default 10 MiB) and the runtime unmarshals the request message from the
// network. Unknown fields (retained), nested groups/messages (recursive
// descent), and packed repeated fields are the classic amplification shapes.
//
// We decode into structpb.Struct — a recursively nestable well-known type
// (Struct → Value → Struct). Raw fuzz bytes rarely match its schema, so most
// fields land in the UNKNOWN-field set: exactly the attacker-reachable path
// where the decoder must scan and retain data it has no field for. Using a
// known type instead of a keyorix pb message keeps the fuzz binary's coverage
// map small (see doc.go) while still driving the real protobuf runtime decoder.
//
// Property: decoding N wire bytes must allocate O(N). The runtime enforces a
// recursion limit (default 100) against unbounded nesting; this oracle is the
// cross-check that *allocation* also stays linear, which the recursion limit
// alone does not guarantee (a flat message of many unknown fields, or a large
// packed field, allocates without nesting).
//
// What this oracle does NOT verify:
//   - Nothing about the decoded message's meaning or any gRPC authz/validation
//     (those are server/grpc and server/faultops fuzzers). Cost only.
//   - It decodes into one concrete type; a different message with map or
//     extension fields could have a different (still-expected-linear) profile.
//   - Allocated bytes, not CPU; CPU-only blow-up is caught only by MaxWall.
func FuzzProtobufDecodeComplexity(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})                   // field 1, len 0
	f.Add([]byte{0x08, 0x96, 0x01})             // field 1 varint
	f.Add([]byte{0x12, 0x02, 0x08, 0x01})       // nested message
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}) // overlong varint-ish

	budget := complexity.Budget{
		MaxAllocBytesPerByte: 64,
		FloorBytes:           2 << 20,
		AbsMaxAllocBytes:     256 << 20, // worst case at the 10 MiB gRPC limit
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		n := len(data)
		c := complexity.Measure(func() {
			m := &structpb.Struct{}
			_ = proto.Unmarshal(data, m) // result/err discarded; cost is the property
		})
		budget.Check(t.Fatalf, "proto.Unmarshal(Struct)", n, c)
	})
}
