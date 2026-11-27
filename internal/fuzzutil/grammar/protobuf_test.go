package grammar

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// TestDecodeProtoTotal: DecodeProto+Encode never panics and never errors for
// arbitrary bytes, including short/empty inputs.
func TestDecodeProtoTotal(t *testing.T) {
	for _, in := range [][]byte{
		nil, {}, {0}, {1}, {1, 0, 0}, {2, 0, 0},
		{0x00, 0x05, 0x08, 0x96, 0x01},
		bytes.Repeat([]byte{0xff}, 64),
		bytes.Repeat([]byte{0x01, 0x80, 0x05}, 40),
		bytes.Repeat([]byte{0x03, 0x41, 0x02}, 50),
	} {
		msg := DecodeProto(in)
		_ = msg.Encode() // must not panic
	}
}

// TestProtoZeroMutationRoundTrips: a hand-built ProtoMsg with no mutations
// encodes to bytes that protowire accepts and that re-decode to the expected
// field values — the "clean output is well-formed" property.
func TestProtoZeroMutationRoundTrips(t *testing.T) {
	// Message with field 1 (varint 42), field 2 (bytes "hello"), field 3 (fixed32 7).
	msg := &ProtoMsg{
		Fields: []*ProtoField{
			{Num: 1, Kind: ProtoVarint, Varint: 42},
			{Num: 2, Kind: ProtoLenDel, Payload: []byte("hello")},
			{Num: 3, Kind: ProtoI32, I32: 7},
		},
	}
	wire := msg.Encode()

	// Scan the wire bytes with protowire and verify field-by-field.
	type fieldGot struct {
		num protowire.Number
		typ protowire.Type
		val any // uint64 for varint/fixed32/fixed64, []byte for LenDel
	}
	var got []fieldGot
	b := wire
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatalf("protowire.ConsumeTag returned error on zero-mutation wire: n=%d bytes=%x", n, wire)
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				t.Fatalf("protowire.ConsumeVarint error")
			}
			b = b[n2:]
			got = append(got, fieldGot{num, typ, v})
		case protowire.BytesType:
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				t.Fatalf("protowire.ConsumeBytes error")
			}
			b = b[n2:]
			got = append(got, fieldGot{num, typ, v})
		case protowire.Fixed32Type:
			v, n2 := protowire.ConsumeFixed32(b)
			if n2 < 0 {
				t.Fatalf("protowire.ConsumeFixed32 error")
			}
			b = b[n2:]
			got = append(got, fieldGot{num, typ, uint64(v)})
		default:
			t.Fatalf("unexpected wire type %v at field %v in zero-mutation encoding", typ, num)
		}
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 fields, got %d: %+v", len(got), got)
	}
	if got[0].num != 1 || got[0].typ != protowire.VarintType || got[0].val.(uint64) != 42 {
		t.Fatalf("field 1 wrong: %+v", got[0])
	}
	if got[1].num != 2 || got[1].typ != protowire.BytesType || !bytes.Equal(got[1].val.([]byte), []byte("hello")) {
		t.Fatalf("field 2 wrong: %+v", got[1])
	}
	if got[2].num != 3 || got[2].typ != protowire.Fixed32Type || got[2].val.(uint64) != 7 {
		t.Fatalf("field 3 wrong: %+v", got[2])
	}
}

// TestProtoDeepChain: the deep-chain opcode reaches real structural depth from a
// tiny input — the lever byte-level mutation cannot pull in one choice.
func TestProtoDeepChain(t *testing.T) {
	// mode byte 0x01 selects deep chain; next two bytes set the depth.
	in := []byte{0x01, 0x10, 0x00}
	msg := DecodeProto(in)
	if got := msg.Depth(); got < 1000 {
		t.Fatalf("proto deep chain only reached depth %d from a 3-byte input", got)
	}
	_ = msg.Encode() // large but must not panic
}

// TestProtoMutationsChangeBytes: each mutation flag actually perturbs the
// encoding — a mutation that produces the same bytes as the zero case would give
// the fuzzer a dead choice.
func TestProtoMutationsChangeBytes(t *testing.T) {
	base := &ProtoField{Num: 1, Kind: ProtoVarint, Varint: 1}
	ref := base.encode()

	cases := map[string]ProtoFieldMut{
		"nonminimalvarint": {NonMinimalVarint: 2},
		"wrongwiretype":    {WrongWireType: true},
		"overlongvarint":   {OverlongVarint: true},
	}
	for name, m := range cases {
		f := *base
		f.Mut = m
		got := f.encode()
		if bytes.Equal(got, ref) {
			t.Fatalf("mutation %q did not change the encoding (ref=%x)", name, ref)
		}
	}

	// LenDelta applies only to LenDel fields.
	baseLD := &ProtoField{Num: 2, Kind: ProtoLenDel, Payload: []byte("abc")}
	refLD := baseLD.encode()
	fLD := *baseLD
	fLD.Mut = ProtoFieldMut{LenDelta: 3}
	if bytes.Equal(fLD.encode(), refLD) {
		t.Fatal("mutation LenDelta did not change the LenDel encoding")
	}
}

// TestProtoNonMinimalVarintIsAccepted: a non-minimal varint encoding produces
// bytes that the google.golang.org/protobuf runtime parses correctly (the spec
// says parsers MUST accept non-minimal varints).
func TestProtoNonMinimalVarintIsAccepted(t *testing.T) {
	f := &ProtoField{Num: 1, Kind: ProtoVarint, Varint: 42, Mut: ProtoFieldMut{NonMinimalVarint: 3}}
	wire := f.encode()

	// The tag should now be non-minimal (more than 1 byte for a small field number).
	if len(wire) <= 2 {
		t.Fatalf("expected non-minimal tag to expand encoding, got %x (%d bytes)", wire, len(wire))
	}

	// protowire should still decode it successfully.
	_, _, n := protowire.ConsumeTag(wire)
	if n < 0 {
		t.Fatalf("protowire rejected non-minimal tag: n=%d wire=%x", n, wire)
	}
	v, n2 := protowire.ConsumeVarint(wire[n:])
	if n2 < 0 {
		t.Fatalf("protowire rejected non-minimal varint value: n=%d wire=%x", n2, wire)
	}
	if v != 42 {
		t.Fatalf("non-minimal varint decoded to %d, want 42", v)
	}
}

// TestProtoOverlongVarintIsRejected: an overlong varint (11+ bytes) makes
// protowire.ConsumeTag return a negative n — the runtime rejects it.
func TestProtoOverlongVarintIsRejected(t *testing.T) {
	f := &ProtoField{Num: 1, Kind: ProtoVarint, Varint: 1, Mut: ProtoFieldMut{OverlongVarint: true}}
	wire := f.encode()

	if len(wire) < 11 {
		t.Fatalf("overlong encoding expected ≥11 bytes, got %d: %x", len(wire), wire)
	}

	_, _, n := protowire.ConsumeTag(wire)
	if n >= 0 {
		t.Fatalf("protowire accepted an overlong tag varint (n=%d, wire=%x) — expected rejection", n, wire)
	}
}

// TestProtoWrongWireTypeChangesTag: WrongWireType changes the wire-type bits in
// the tag without changing the field number.
func TestProtoWrongWireTypeChangesTag(t *testing.T) {
	base := &ProtoField{Num: 5, Kind: ProtoVarint, Varint: 100}
	refNum, refTyp, n := protowire.ConsumeTag(base.encode())
	if n < 0 {
		t.Fatalf("ConsumeTag on clean field failed")
	}

	mutated := &ProtoField{Num: 5, Kind: ProtoVarint, Varint: 100, Mut: ProtoFieldMut{WrongWireType: true}}
	mutNum, mutTyp, n2 := protowire.ConsumeTag(mutated.encode())
	if n2 < 0 {
		t.Fatalf("ConsumeTag on WrongWireType field failed (tag itself must still parse)")
	}
	if mutNum != refNum {
		t.Fatalf("WrongWireType changed the field number: ref=%d got=%d", refNum, mutNum)
	}
	if mutTyp == refTyp {
		t.Fatalf("WrongWireType did not change the wire type (both %v)", refTyp)
	}
}

// TestProtoLenDeltaChangesLength: LenDelta>0 makes the declared length larger
// than the actual payload (the declared-vs-actual mismatch mutation).
func TestProtoLenDeltaChangesLength(t *testing.T) {
	payload := []byte("abcdef")
	clean := &ProtoField{Num: 1, Kind: ProtoLenDel, Payload: payload}
	over := &ProtoField{Num: 1, Kind: ProtoLenDel, Payload: payload, Mut: ProtoFieldMut{LenDelta: 10}}

	cleanWire := clean.encode()
	overWire := over.encode()
	if bytes.Equal(cleanWire, overWire) {
		t.Fatal("LenDelta=10 did not change the encoding")
	}

	// Parse the declared length from the clean and mutated encodings and compare.
	_, _, nt := protowire.ConsumeTag(cleanWire)
	cleanLen, _ := protowire.ConsumeVarint(cleanWire[nt:])

	_, _, nt2 := protowire.ConsumeTag(overWire)
	overLen, _ := protowire.ConsumeVarint(overWire[nt2:])

	if overLen != cleanLen+10 {
		t.Fatalf("LenDelta=10: expected declared length %d, got %d", cleanLen+10, overLen)
	}
}

// TestProtoNestedMsgZeroMutation: a ProtoMsg with a nested message encodes to
// valid wire format that protowire accepts at both levels.
func TestProtoNestedMsgZeroMutation(t *testing.T) {
	inner := &ProtoMsg{Fields: []*ProtoField{
		{Num: 1, Kind: ProtoVarint, Varint: 7},
	}}
	outer := &ProtoMsg{Fields: []*ProtoField{
		{Num: 1, Kind: ProtoLenDel, Nested: inner},
	}}
	wire := outer.Encode()

	// Outer: field 1, LenDel.
	_, typ, n := protowire.ConsumeTag(wire)
	if n < 0 || typ != protowire.BytesType {
		t.Fatalf("outer tag invalid: n=%d typ=%v", n, typ)
	}
	innerBytes, n2 := protowire.ConsumeBytes(wire[n:])
	if n2 < 0 {
		t.Fatalf("outer LenDel consume failed: n=%d", n2)
	}
	// Inner: field 1, varint 7.
	_, iTyp, ni := protowire.ConsumeTag(innerBytes)
	if ni < 0 || iTyp != protowire.VarintType {
		t.Fatalf("inner tag invalid: n=%d typ=%v", ni, iTyp)
	}
	v, nv := protowire.ConsumeVarint(innerBytes[ni:])
	if nv < 0 || v != 7 {
		t.Fatalf("inner varint: n=%d v=%d (want 7)", nv, v)
	}
}

// TestProtoGroupZeroMutation: a group field encodes a matching start/end group tag
// pair that protowire accepts.
func TestProtoGroupZeroMutation(t *testing.T) {
	group := &ProtoMsg{Fields: []*ProtoField{
		{Num: 2, Kind: ProtoVarint, Varint: 3},
	}}
	f := &ProtoField{Num: 1, Kind: ProtoGroup, Group: group}
	wire := f.encode()

	// First tag: field 1, wire type 3 (SGROUP).
	num, typ, n := protowire.ConsumeTag(wire)
	if n < 0 || num != 1 || typ != protowire.StartGroupType {
		t.Fatalf("SGROUP tag wrong: num=%v typ=%v n=%d wire=%x", num, typ, n, wire)
	}
	// protowire.ConsumeGroup consumes from AFTER the start tag to end-of-group.
	groupBytes, ng := protowire.ConsumeGroup(1, wire[n:])
	if ng < 0 {
		t.Fatalf("ConsumeGroup failed: ng=%d wire=%x", ng, wire)
	}
	// Inside the group: field 2, varint 3.
	_, iTyp, ni := protowire.ConsumeTag(groupBytes)
	if ni < 0 || iTyp != protowire.VarintType {
		t.Fatalf("group inner tag: n=%d typ=%v", ni, iTyp)
	}
	v, nv := protowire.ConsumeVarint(groupBytes[ni:])
	if nv < 0 || v != 3 {
		t.Fatalf("group inner varint: n=%d v=%d (want 3)", nv, v)
	}
}

// TestProtoPackedFieldZeroMutation: a packed repeated field encodes as a LenDel
// whose payload is a concatenation of varint encodings, as protowire confirms.
func TestProtoPackedFieldZeroMutation(t *testing.T) {
	values := []uint64{1, 2, 128, 300}
	f := &ProtoField{Num: 1, Kind: ProtoLenDel, Packed: values}
	wire := f.encode()

	_, typ, n := protowire.ConsumeTag(wire)
	if n < 0 || typ != protowire.BytesType {
		t.Fatalf("packed tag: n=%d typ=%v", n, typ)
	}
	payload, np := protowire.ConsumeBytes(wire[n:])
	if np < 0 {
		t.Fatalf("packed payload consume: n=%d", np)
	}
	// Re-decode the packed varints from the payload.
	var decoded []uint64
	for len(payload) > 0 {
		v, nv := protowire.ConsumeVarint(payload)
		if nv < 0 {
			t.Fatalf("packed varint decode failed at offset %d", len(payload))
		}
		decoded = append(decoded, v)
		payload = payload[nv:]
	}
	if len(decoded) != len(values) {
		t.Fatalf("packed: got %d values, want %d", len(decoded), len(values))
	}
	for i, want := range values {
		if decoded[i] != want {
			t.Fatalf("packed[%d]: got %d, want %d", i, decoded[i], want)
		}
	}
}
