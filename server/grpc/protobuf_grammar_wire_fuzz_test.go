package grpc_test

// FuzzGRPCProtobufGrammarWireInvariants — fuzzer inventory item #7: wire-level
// mutations on top of the existing descriptor-driven grammar model.
//
// WHAT THIS ADDS vs FuzzGRPCProtoreflectInvariants (item #6):
//
//  1. Wire mutation layer. The grammar builder (buildMessage, same file as
//     item #6) produces a valid, well-typed proto message; this target also
//     applies one of seven wire-level mutations to the marshaled bytes BEFORE
//     sending, exercising paths the descriptor-driven builder explicitly avoids:
//
//       - wireMutWrongType: replaces the first field tag's wire type with an
//         incompatible one (e.g., uint32 field gets wire type 2 / bytes).
//       - wireMutTruncate: cuts the message mid-varint, ensuring the server's
//         proto.Unmarshal sees a genuinely truncated input.
//       - wireMutLargeLen: replaces a length-delimited field's length prefix
//         with 2^31-1, triggering ErrInvalidLength in the decoder.
//       - wireMutDupField: duplicates the first field (exercises "last value
//         wins" proto3 semantics and conflicting-oneof semantics at wire level).
//       - wireMutInvalidUTF8: appends a string field with \xFF\xFE bytes,
//         exercising the "proto3 strings must be valid UTF-8" check the grammar
//         builder explicitly strips (strings.ToValidUTF8).
//       - wireMutConflictOneof: appends two members of the same oneof, so the
//         server sees both set in the wire frame.
//       - wireMutRawJunk: appends randomly-structured bytes with high bits set
//         (looks like a runaway varint continuation to the decoder).
//
//  2. Oracle (c): malformed-encoding → client-error. For mutations that make
//     the bytes syntactically unparseable (WrongType, Truncate, LargeLen,
//     RawJunk), the server is expected to reject the request with a client-error
//     code. If the server returns codes.Internal or codes.Unknown, this is logged
//     as a HARDENING finding (not t.Fatalf -- HARDENING is not a security defect;
//     the right fix is mapping the decode error to codes.InvalidArgument). The
//     total HARDENING count is reported at Cleanup.
//
//  3. Oracle (d): idempotency for the zero-grant identity. The same raw bytes
//     are sent twice; the gRPC error code must be identical on both calls
//     (excluding DeadlineExceeded and ResourceExhausted — both are gRPC
//     infrastructure codes that appear non-deterministically under parallel load).
//     A code change indicates either an unauthorized best-effort write (caught
//     by oracle 3 jointly), or an existence-leak: the first call caused the
//     resource to exist/not-exist in a way that changes what the second call
//     reports back.
//
// WHAT THIS DOES NOT VERIFY (stated explicitly):
//   - Semantic correctness of authorized calls (that is item #6's job).
//   - Streaming RPCs (same gap as item #6; Cleanup logs the unreached set).
//   - That the error message itself is free of stack traces or raw DB errors
//     for malformed wire input (item #6's classifyStatusLeak covers that for
//     all calls; oracle (c) here only checks the status CODE).
//   - Heap growth or allocation amplification (left as LEFTOVER in PBG1 report).
//   - Existence leakage via comparing error codes for a known-existing vs a
//     random resource ID: oracle (d) approximates this for zero-grant via
//     two identical calls; the full "substitute a real ID vs a random ID"
//     check is noted as LEFTOVER.
//   - CREATE-class RPC idempotency: oracle (d) is applied only to the zero-grant
//     identity (which should NEVER get OK on a mutating call), so AlreadyExists
//     on a second call is not a valid input here.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/core"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

// --- rawProtoCodec: send pre-built bytes through the gRPC frame layer --------

// rawProtoCodec is an encoding.Codec that returns pre-built raw bytes from
// Marshal, bypassing proto.Marshal on the CLIENT side. The server receives those
// bytes and unmarshals them with its own registered proto codec, so malformed
// bytes cause a real server-side proto.Unmarshal failure (and therefore a real
// server-side error response). Used exclusively for wire-level mutation testing
// in this file; not registered globally (grpc.ForceCodec is per-call).
type rawProtoCodec struct {
	raw []byte
}

func (rawProtoCodec) Name() string { return "proto" } // content-type application/grpc+proto

// Marshal returns raw pre-built bytes, ignoring v. The placeholder argument
// passed to conn.Invoke is irrelevant when this codec is active.
func (c rawProtoCodec) Marshal(_ any) ([]byte, error) { return c.raw, nil }

// Unmarshal decodes a response (server-side responses are always well-formed
// proto produced by the server's own handlers).
func (rawProtoCodec) Unmarshal(data []byte, v any) error {
	if m, ok := v.(proto.Message); ok {
		return proto.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, m)
	}
	return nil
}

// invokeRaw calls method m with pre-built raw proto bytes as the request
// payload (sent via rawProtoCodec), using the given authorization token.
// The response is discarded; only the gRPC error is returned.
func invokeRaw(ctx context.Context, conn *grpc.ClientConn, m grpcMethod, rawBytes []byte, tok string) error {
	codec := rawProtoCodec{raw: rawBytes}
	resp := dynamicpb.NewMessage(m.output)
	placeholder := dynamicpb.NewMessage(m.input)
	if tok != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+tok))
	}
	return conn.Invoke(ctx, m.fullMethod(), placeholder, resp, grpc.ForceCodec(codec))
}

// --- Wire mutation kinds and helpers -----------------------------------------

// wireMutKind identifies one of the wire-level mutation strategies.
type wireMutKind uint8

const (
	wireMutNone          wireMutKind = iota // no mutation: send the valid marshaled bytes
	wireMutWrongType                        // first tag's wire type is replaced with an incompatible one
	wireMutTruncate                         // message truncated mid-varint
	wireMutLargeLen                         // a length-delimited field gets a huge length prefix
	wireMutDupField                         // first field is duplicated at the end
	wireMutInvalidUTF8                      // a string field gets \xFF\xFE bytes appended
	wireMutConflictOneof                    // two oneof members appended to the message
	wireMutRawJunk                          // random high-bit bytes appended
	wireMutNumKinds      wireMutKind = iota
)

// expectedDecodeError reports whether this mutation reliably makes the wire
// bytes syntactically unparseable by proto.Unmarshal. Used by oracle (c) to
// classify a server codes.Internal response as HARDENING rather than a bug.
func (k wireMutKind) expectedDecodeError() bool {
	switch k {
	case wireMutWrongType, wireMutTruncate, wireMutLargeLen, wireMutRawJunk:
		return true
	}
	return false
}

// applyWireMut applies mutation k to validBytes and returns the mutated
// bytes. validBytes must be a valid proto encoding; some mutations produce
// syntactically invalid output, some produce syntactically valid but
// semantically odd output (e.g., duplicate fields, conflicting oneof).
func applyWireMut(k wireMutKind, validBytes []byte, c *fuzzCursor, desc protoreflect.MessageDescriptor) []byte {
	switch k {
	case wireMutWrongType:
		return wmBadType(validBytes, c)
	case wireMutTruncate:
		return wmTruncate(validBytes, c)
	case wireMutLargeLen:
		return wmBigLen(validBytes)
	case wireMutDupField:
		return wmDupField(validBytes)
	case wireMutInvalidUTF8:
		return wmInvalidUTF8(validBytes, desc)
	case wireMutConflictOneof:
		return wmConflictOneof(validBytes, desc)
	case wireMutRawJunk:
		return wmRawJunk(validBytes, c)
	}
	return validBytes
}

// wmBadType replaces the wire type of the first parseable field tag with an
// incompatible one from {Varint, Fixed64, Bytes, Fixed32}, rotating away from
// the current type. If no parseable tag is found (empty or corrupt message),
// injects a fixed64 tag+value at the start.
func wmBadType(b []byte, c *fuzzCursor) []byte {
	if len(b) == 0 {
		var out []byte
		out = protowire.AppendTag(out, 1, protowire.Fixed64Type)
		out = protowire.AppendFixed64(out, 0)
		return out
	}
	num, origType, tagLen := protowire.ConsumeTag(b)
	if tagLen <= 0 {
		return wmTruncate(b, c)
	}
	validTypes := [4]protowire.Type{
		protowire.VarintType, protowire.Fixed64Type, protowire.BytesType, protowire.Fixed32Type,
	}
	newType := validTypes[(int(origType)+1+int(c.byte()))%4]
	for newType == origType {
		newType = validTypes[(int(newType)+1)%4]
	}
	newTagBytes := protowire.AppendTag(nil, num, newType)
	out := make([]byte, 0, len(b)+len(newTagBytes))
	out = append(out, newTagBytes...)
	out = append(out, b[tagLen:]...)
	return out
}

// wmTruncate returns a prefix of b that cuts the message either
// mid-varint (most disruptive) or at a byte boundary chosen by c.
func wmTruncate(b []byte, c *fuzzCursor) []byte {
	if len(b) == 0 {
		return b
	}
	cutAt := 1 + int(c.byte())%max(1, len(b))
	for i := 0; i < cutAt && i < len(b); i++ {
		if b[i]&0x80 != 0 {
			return b[:i] // cut mid-varint
		}
	}
	return b[:cutAt]
}

// wmBigLen finds the first length-delimited field and replaces its length
// prefix with 2^31-1, triggering proto.ErrInvalidLength in the decoder.
func wmBigLen(b []byte) []byte {
	const hugeLen = uint64(1<<31 - 1)
	rem := b
	offset := 0
	for len(rem) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(rem)
		if tagLen <= 0 {
			break
		}
		if typ == protowire.BytesType {
			out := make([]byte, 0, offset+tagLen+10)
			out = append(out, b[:offset]...)
			out = protowire.AppendTag(out, num, protowire.BytesType)
			out = protowire.AppendVarint(out, hugeLen)
			// Drop the remaining bytes: decoder will seek past EOF.
			return out
		}
		fieldValLen := protowire.ConsumeFieldValue(num, typ, rem[tagLen:])
		if fieldValLen <= 0 {
			break
		}
		total := tagLen + fieldValLen
		offset += total
		rem = rem[total:]
	}
	// No bytes field found; prepend a fake huge-length field at the start.
	out := protowire.AppendTag(nil, 1, protowire.BytesType)
	out = protowire.AppendVarint(out, hugeLen)
	out = append(out, b...)
	return out
}

// wmDupField duplicates the first complete field (tag + value), appending the
// duplicate at the end. For proto3 singular fields, the last value wins.
// For oneof members, two members of the same oneof appear in the wire frame.
func wmDupField(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	num, typ, tagLen := protowire.ConsumeTag(b)
	if tagLen <= 0 {
		return b
	}
	valLen := protowire.ConsumeFieldValue(num, typ, b[tagLen:])
	if valLen <= 0 {
		return b
	}
	fieldBytes := b[:tagLen+valLen]
	out := make([]byte, len(b)+len(fieldBytes))
	copy(out, b)
	copy(out[len(b):], fieldBytes)
	return out
}

// wmInvalidUTF8 appends a copy of the first string field declared in desc with
// \xFF\xFE bytes as the content. In proto3, the last occurrence of a singular
// field wins, so this effectively replaces the field's value with invalid UTF-8.
// If desc has no string fields, the original bytes are returned unchanged.
func wmInvalidUTF8(b []byte, desc protoreflect.MessageDescriptor) []byte {
	fields := desc.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.StringKind {
			continue
		}
		// 0xFF is never valid in UTF-8; 0xFE is also not. Inject both so strict-
		// mode parsers that might accept lone 0xFE are also exercised.
		invalidUTF8 := []byte{0xFF, 0xFE, 0x41, 0x42} // \xFF\xFE followed by "AB"
		out := make([]byte, len(b), len(b)+20)
		copy(out, b)
		out = protowire.AppendTag(out, fd.Number(), protowire.BytesType)
		out = protowire.AppendBytes(out, invalidUTF8)
		return out
	}
	return b // no string fields in this message type
}

// wmConflictOneof appends two members of the first real oneof it can find in
// desc -- one varint zero for the first member, one varint zero for the second.
// In proto3 wire format, this is legal (last wins); some handlers explicitly
// detect and reject two set oneof members. If desc has no real oneof with at
// least two members, returns the original bytes.
func wmConflictOneof(b []byte, desc protoreflect.MessageDescriptor) []byte {
	fields := desc.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		oo := fd.ContainingOneof()
		if oo == nil || oo.IsSynthetic() || oo.Fields().Len() < 2 {
			continue
		}
		second := oo.Fields().Get(1)
		out := make([]byte, len(b), len(b)+30)
		copy(out, b)
		out = protowire.AppendTag(out, fd.Number(), protowire.VarintType)
		out = protowire.AppendVarint(out, 0)
		out = protowire.AppendTag(out, second.Number(), protowire.VarintType)
		out = protowire.AppendVarint(out, 0)
		return out
	}
	return b // no real oneof with 2+ members
}

// wmRawJunk appends 4–15 bytes all with the high bit set, looking like a
// runaway varint continuation to the proto decoder.
func wmRawJunk(b []byte, c *fuzzCursor) []byte {
	n := 4 + int(c.byte())%12
	junk := make([]byte, n)
	for i := range junk {
		junk[i] = c.byte() | 0x80
	}
	out := make([]byte, len(b)+n)
	copy(out, b)
	copy(out[len(b):], junk)
	return out
}

// --- The fuzz target ---------------------------------------------------------

func FuzzGRPCProtobufGrammarWireInvariants(f *testing.F) {
	w := buildPRWorld(f)

	// hardeningCount tracks the number of HARDENING-1 findings: malformed bytes
	// → server codes.Internal instead of codes.InvalidArgument.
	var hardeningCount atomic.Int64

	f.Cleanup(func() {
		w.close()
		if n := hardeningCount.Load(); n > 0 {
			f.Logf("HARDENING-1: %d inputs caused codes.Internal for malformed wire bytes (expected codes.InvalidArgument) -- see PBG1 report HARDENING-1", n)
		}
	})

	// One seed per discovered method in pure-grammar mode (k=0, no wire mutation),
	// ensuring every RPC is exercised at least once in a plain `go test` run.
	for i := range len(w.methods) {
		f.Add([]byte{byte(i), 0})
	}
	// Seeds exercising wire mutation kinds: one entry per mutation kind on method 0.
	for k := range wireMutNumKinds {
		f.Add([]byte{0, byte(k)})
	}

	f.Fuzz(func(t *testing.T, program []byte) {
		w.resetPrincipalGrants(t, context.Background())

		cur := newFuzzCursor(program)
		m := w.methods[int(cur.byte())%len(w.methods)]

		// Grammar build starts at this cursor position.
		bodyOffset := cur.pos

		// Pick wire mutation kind.
		k := wireMutKind(cur.byte() % uint8(wireMutNumKinds))

		// Build a valid proto message from the remaining cursor bytes, then marshal.
		buildFresh := func() *dynamicpb.Message {
			fresh := &fuzzCursor{data: program, pos: bodyOffset}
			return buildMessage(m.input, fresh, 0)
		}
		validBytes, err := proto.Marshal(buildFresh())
		if err != nil {
			// proto.Marshal can only fail if the message contains non-serializable
			// fields (not expected from dynamicpb). Skip rather than fail so a stale
			// corpus entry that hits this doesn't abort the run.
			t.Skipf("proto.Marshal failed: %v", err)
		}

		// Apply wire mutation using a fresh cursor slice after the grammar body.
		mutCur := &fuzzCursor{data: program, pos: cur.pos}
		rawBytes := applyWireMut(k, validBytes, mutCur, m.input)

		// --- shared helpers ------------------------------------------------

		pbDrain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}

		// runAsRaw invokes the RPC with the given token, running the full set of
		// per-call oracles that apply regardless of which identity is calling.
		// Returns (code, before-snapshot, after-snapshot).
		runAsRaw := func(label, tok string) (codes.Code, dbSnapshot, dbSnapshot) {
			pbDrain()
			before := snapshotDB(t, w.db)
			cctx, cancel := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel()
			callErr := invokeRaw(cctx, w.conn, m, rawBytes, tok)
			pbDrain()
			after := snapshotDB(t, w.db)

			// Oracle (a): no leak-shaped Internal / no Unknown.
			if bad, reason := classifyStatusLeak(callErr); bad {
				t.Fatalf("LEAK op=%s principal=%s mutKind=%d: %s", m.key(), label, k, reason)
			}

			// Oracle (c): malformed encoding must yield a client-error code,
			// not codes.Internal or codes.Unknown. Classify as HARDENING (not fatal).
			if k.expectedDecodeError() {
				code := status.Code(callErr)
				if code == codes.Internal || code == codes.Unknown {
					hardeningCount.Add(1)
					t.Logf("HARDENING-1 op=%s principal=%s mutKind=%d: malformed wire bytes returned codes.%v -- expected codes.InvalidArgument/OutOfRange",
						m.key(), label, k, code)
				}
			}

			return status.Code(callErr), before, after
		}

		// --- zero-grant identity -------------------------------------------

		zCode, zBefore, zAfter := runAsRaw("zero-grant", w.zeroGrantTok)

		if zCode == codes.OK {
			if diffs := zBefore.unexplainedWrites(zAfter, "zero-grant"); len(diffs) > 0 {
				t.Fatalf("AUTHZ BYPASS (write) op=%s mutKind=%d: zero-grant got OK and DB changed: %s",
					m.key(), k, formatTableDeltas(diffs))
			}
		}
		if zCode != codes.OK {
			if diffs := zBefore.unexplainedWrites(zAfter, "zero-grant"); len(diffs) > 0 {
				t.Fatalf("ERROR-IMPLIES-NO-COMMIT op=%s principal=zero-grant mutKind=%d: non-OK (%v) but DB changed: %s",
					m.key(), k, zCode, formatTableDeltas(diffs))
			}
		}

		// Oracle (d): idempotency for zero-grant. The same raw bytes sent twice
		// must return the same gRPC error code (excluding DeadlineExceeded and
		// ResourceExhausted). Both are gRPC-infrastructure codes that can appear
		// non-deterministically under parallel fuzz load: DeadlineExceeded from
		// per-call timeout races, ResourceExhausted from gRPC frame limits on
		// large duplicated messages (wmDupField) when the in-process bufconn
		// connection is being re-established between parallel workers.
		{
			pbDrain()
			cctx2, cancel2 := context.WithTimeout(context.Background(), perCallTimeout)
			defer cancel2()
			callErr2 := invokeRaw(cctx2, w.conn, m, rawBytes, w.zeroGrantTok)
			pbDrain()
			zCode2 := status.Code(callErr2)
			infraCode := func(c codes.Code) bool {
				return c == codes.DeadlineExceeded || c == codes.ResourceExhausted
			}
			if !infraCode(zCode) && !infraCode(zCode2) && zCode != zCode2 {
				t.Fatalf("IDEMPOTENCY op=%s mutKind=%d: zero-grant first=%v second=%v -- same bytes, same DB state, different error code",
					m.key(), k, zCode, zCode2)
			}
		}

		// --- read-only identity --------------------------------------------

		rCode, rBefore, rAfter := runAsRaw("read-only", w.readOnlyTok)

		if rCode == codes.OK {
			if diffs := rBefore.unexplainedWrites(rAfter, "read-only"); len(diffs) > 0 {
				t.Fatalf("AUTHZ BYPASS (write) op=%s mutKind=%d: read-only got OK and DB changed: %s",
					m.key(), k, formatTableDeltas(diffs))
			}
		}
		if rCode != codes.OK {
			if diffs := rBefore.unexplainedWrites(rAfter, "read-only"); len(diffs) > 0 {
				t.Fatalf("ERROR-IMPLIES-NO-COMMIT op=%s principal=read-only mutKind=%d: non-OK (%v) but DB changed: %s",
					m.key(), k, rCode, formatTableDeltas(diffs))
			}
		}

		// --- admin identity ------------------------------------------------

		adCode, adBefore, adAfter := runAsRaw("admin", w.adminTok)
		// No authz assertion for admin (expected to succeed broadly).
		if adCode != codes.OK {
			if diffs := adBefore.unexplainedWrites(adAfter, "admin"); len(diffs) > 0 {
				t.Fatalf("ERROR-IMPLIES-NO-COMMIT op=%s principal=admin mutKind=%d: non-OK (%v) but DB changed: %s",
					m.key(), k, adCode, formatTableDeltas(diffs))
			}
		}
	})
}

// FuzzGRPCByteLevelRaw — byte-level baseline for the grammar vs byte-level
// measurement section of the PBG1 report. Sends raw fuzz bytes directly as
// the proto payload with NO grammar structure, using the same world and
// oracle (a)(c) as FuzzGRPCProtobufGrammarWireInvariants. Used ONLY for
// measurement; not intended as a long-running production fuzzer (grammar
// coverage is strictly better for handler-level logic).
//
// WHAT THIS DOES NOT VERIFY: everything that requires a well-formed proto
// message -- oracle (b) authz bypass, oracle (d) idempotency -- because
// malformed random bytes almost never produce a request that reaches a
// handler's business logic.
func FuzzGRPCByteLevelRaw(f *testing.F) {
	w := buildPRWorld(f)
	var hardeningCount atomic.Int64

	f.Cleanup(func() {
		w.close()
		if n := hardeningCount.Load(); n > 0 {
			f.Logf("byte-level HARDENING-1: %d inputs returned codes.Internal for raw bytes", n)
		}
	})

	// Seeds: one per method with an empty payload (empty proto = all zero fields).
	for i := range len(w.methods) {
		f.Add([]byte{byte(i)}, []byte(nil))
	}
	// A seed that resembles a minimal valid varint field (field 1, varint, value 1).
	f.Add([]byte{0}, []byte{0x08, 0x01})

	f.Fuzz(func(t *testing.T, methodSel []byte, rawBytes []byte) {
		if len(methodSel) == 0 {
			return
		}
		m := w.methods[int(methodSel[0])%len(w.methods)]

		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}
		drain()

		cctx, cancel := context.WithTimeout(context.Background(), perCallTimeout)
		defer cancel()
		callErr := invokeRaw(cctx, w.conn, m, rawBytes, w.zeroGrantTok)
		drain()

		// Oracle (a).
		if bad, reason := classifyStatusLeak(callErr); bad {
			t.Fatalf("LEAK op=%s byte-level: %s", m.key(), reason)
		}
		// Oracle (c): any raw bytes are "expected to fail decode" since the
		// byte-level fuzzer has no grammar structure.
		code := status.Code(callErr)
		if code == codes.Internal || code == codes.Unknown {
			hardeningCount.Add(1)
			t.Logf("HARDENING-1 op=%s byte-level: codes.%v for %d-byte input", m.key(), code, len(rawBytes))
		}

		_ = fmt.Sprintf // keep fmt imported
	})
}
