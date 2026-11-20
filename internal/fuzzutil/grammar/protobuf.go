package grammar

import "encoding/binary"

// ProtoWireKind is the protobuf wire type for a field. Only the five types used
// in practice are named; wire types 3 and 4 (group start/end, deprecated) are
// handled together by ProtoGroup.
type ProtoWireKind uint8

const (
	ProtoVarint ProtoWireKind = 0 // wire type 0: varint (int32/int64/bool/enum)
	ProtoI64    ProtoWireKind = 1 // wire type 1: 64-bit (fixed64/double)
	ProtoLenDel ProtoWireKind = 2 // wire type 2: length-delimited (bytes/string/message/packed)
	ProtoGroup  ProtoWireKind = 3 // wire types 3+4: group start/end (deprecated but legal)
	ProtoI32    ProtoWireKind = 5 // wire type 5: 32-bit (fixed32/float)
)

// ProtoFieldMut is the per-field mutation set. The zero value produces the
// canonical protobuf wire-format encoding; each field, when set, breaks exactly
// one spec invariant so a decoder's handling of that specific malformation is
// exercised. A fuzz target states in its own doc comment which mutations it
// expects a correct decoder to reject vs. tolerate.
type ProtoFieldMut struct {
	// NonMinimalVarint, when >0, encodes the tag and (for Kind==ProtoVarint) the
	// value using this many extra zero-value continuation bytes beyond the minimal
	// varint encoding — e.g. the value 1 normally occupies one byte (0x01) but with
	// NonMinimalVarint=1 is written as two bytes (0x81 0x00). The proto3 spec says
	// parsers MUST accept non-minimal varints; some older implementations may not.
	NonMinimalVarint uint8

	// WrongWireType, when set, replaces the wire-type bits in the tag with
	// (actualWireType+1)%6 — the field number is correct but the declared wire type
	// is wrong. A correct decoder SHOULD return an error when the declared wire type
	// disagrees with the field's known schema; for unknown fields the decoder
	// retains the bytes verbatim and may or may not detect the mismatch.
	WrongWireType bool

	// OverlongVarint, when set, pads the tag varint (and, for Kind==ProtoVarint,
	// the value varint) to 11 bytes — one more than the 10-byte maximum for a 64-bit
	// varint. The google.golang.org/protobuf runtime rejects overlong varints; a
	// correct decoder MUST reject them per the binary format spec.
	OverlongVarint bool

	// LenDelta, when non-zero, is added to the length prefix of a Kind==ProtoLenDel
	// field (overflow if >0, truncation if <0). The payload bytes are unchanged, so
	// the declared length disagrees with the actual payload length — causing the
	// decoder to either over-read (consuming bytes from the next field as content)
	// or under-read (leaving tail bytes of the payload to be parsed as the next tag).
	// A correct decoder MUST return an error or produce garbage that subsequent
	// tag parsing detects.
	LenDelta int
}

// ProtoMsg is a protobuf message: an ordered sequence of fields plus optional
// trailing bytes appended after all fields (the "trailing data" malformation, which
// a strict decoder must reject but a lenient one may silently ignore).
type ProtoMsg struct {
	Fields   []*ProtoField
	Trailing []byte
}

// ProtoField is one (tag, value) wire-format pair.
//
// Kind selects the wire type used in the tag and determines which value field is live:
//   - Kind==ProtoVarint:  Varint
//   - Kind==ProtoI64:     I64
//   - Kind==ProtoLenDel:  Nested (if non-nil), else Packed (if non-nil), else Payload
//   - Kind==ProtoGroup:   Group
//   - Kind==ProtoI32:     I32
type ProtoField struct {
	Num  uint32        // field number (1 to 2^29–1; the generator uses 1..127)
	Kind ProtoWireKind // wire type selector

	Varint  uint64    // live when Kind==ProtoVarint
	I64     uint64    // live when Kind==ProtoI64 (little-endian 8-byte fixed)
	Payload []byte    // live when Kind==ProtoLenDel (raw bytes)
	Nested  *ProtoMsg // when Kind==ProtoLenDel and non-nil, Nested.Encode() is the payload
	Packed  []uint64  // when Kind==ProtoLenDel and non-nil, packed varint repeated field
	I32     uint32    // live when Kind==ProtoI32 (little-endian 4-byte fixed)
	Group   *ProtoMsg // live when Kind==ProtoGroup (fields between SGROUP/EGROUP tags)

	Mut ProtoFieldMut
}

// Encode serialises the message to protobuf wire-format bytes.
func (m *ProtoMsg) Encode() []byte {
	if m == nil {
		return nil
	}
	var out []byte
	for _, f := range m.Fields {
		out = append(out, f.encode()...)
	}
	return append(out, protoTrailing(m)...)
}

func protoTrailing(m *ProtoMsg) []byte {
	if m == nil {
		return nil
	}
	return m.Trailing
}

func (f *ProtoField) encode() []byte {
	if f == nil {
		return nil
	}

	num := f.Num
	if num == 0 {
		num = 1 // field number 0 is not valid; clamp to 1
	}

	wt := f.wireType()
	tag := uint64(num)<<3 | uint64(wt)

	var out []byte

	// Encode the tag varint, applying mutations.
	switch {
	case f.Mut.OverlongVarint:
		out = appendProtoVarintOverlong(out, tag)
	case f.Mut.NonMinimalVarint > 0:
		out = appendProtoVarintPadded(out, tag, f.Mut.NonMinimalVarint)
	default:
		out = appendProtoVarint(out, tag)
	}

	// Encode the value.
	switch f.Kind {
	case ProtoVarint:
		switch {
		case f.Mut.OverlongVarint:
			out = appendProtoVarintOverlong(out, f.Varint)
		case f.Mut.NonMinimalVarint > 0:
			out = appendProtoVarintPadded(out, f.Varint, f.Mut.NonMinimalVarint)
		default:
			out = appendProtoVarint(out, f.Varint)
		}
	case ProtoI64:
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], f.I64)
		out = append(out, b[:]...)
	case ProtoLenDel:
		payload := f.lendel()
		declared := len(payload) + f.Mut.LenDelta
		if declared < 0 {
			declared = 0
		}
		out = appendProtoVarint(out, uint64(declared))
		out = append(out, payload...)
	case ProtoGroup:
		// The start-group tag (wire type 3) was already written above.
		// Encode the group's inner fields, then the matching end-group tag.
		if f.Group != nil {
			for _, child := range f.Group.Fields {
				out = append(out, child.encode()...)
			}
		}
		endTag := uint64(num)<<3 | 4 // wire type 4 = EGROUP
		out = appendProtoVarint(out, endTag)
	case ProtoI32:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], f.I32)
		out = append(out, b[:]...)
	}

	return out
}

// wireType returns the wire-type bits to write in the tag, applying WrongWireType.
func (f *ProtoField) wireType() uint8 {
	wt := uint8(f.Kind)
	if f.Kind == ProtoGroup {
		wt = 3 // SGROUP; EGROUP (4) is emitted implicitly after the group content
	}
	if f.Mut.WrongWireType {
		wt = (wt + 1) % 6
		if wt == 4 {
			wt = 5 // skip wire type 4 (EGROUP only valid after a matching SGROUP)
		}
	}
	return wt
}

// lendel returns the bytes payload for a Kind==ProtoLenDel field.
// Priority: Nested > Packed > Payload.
func (f *ProtoField) lendel() []byte {
	if f.Nested != nil {
		return f.Nested.Encode()
	}
	if f.Packed != nil {
		var b []byte
		for _, v := range f.Packed {
			b = appendProtoVarint(b, v)
		}
		return b
	}
	return f.Payload
}

// Depth returns the maximum message nesting depth (a leaf message is depth 1).
// Groups and nested messages both count as nesting levels.
func (m *ProtoMsg) Depth() int {
	if m == nil {
		return 0
	}
	maxD := 0
	for _, f := range m.Fields {
		if f == nil {
			continue
		}
		var d int
		switch f.Kind {
		case ProtoLenDel:
			d = f.Nested.Depth()
		case ProtoGroup:
			d = f.Group.Depth()
		}
		if d > maxD {
			maxD = d
		}
	}
	return maxD + 1
}

// Count returns the total number of fields in the message tree (recursive,
// counting fields inside nested messages and groups).
func (m *ProtoMsg) Count() int {
	if m == nil {
		return 0
	}
	total := len(m.Fields)
	for _, f := range m.Fields {
		if f == nil {
			continue
		}
		switch f.Kind {
		case ProtoLenDel:
			total += f.Nested.Count()
		case ProtoGroup:
			total += f.Group.Count()
		}
	}
	return total
}

// appendProtoVarint appends the minimal varint encoding of v to b.
func appendProtoVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// appendProtoVarintPadded appends a non-minimal varint encoding of v padded with
// pad extra zero-value continuation bytes beyond the minimal encoding. pad==0
// gives the minimal form.
func appendProtoVarintPadded(b []byte, v uint64, pad uint8) []byte {
	for v >= 0x80 {
		b = append(b, byte(v&0x7f)|0x80)
		v >>= 7
	}
	if pad == 0 {
		return append(b, byte(v))
	}
	// Convert the terminal byte into a continuation byte and add `pad` extra bytes.
	b = append(b, byte(v)|0x80)
	for i := uint8(1); i < pad; i++ {
		b = append(b, 0x80) // zero-value continuation
	}
	return append(b, 0x00) // new terminal byte
}

// appendProtoVarintOverlong encodes v as a varint padded to 11 bytes, which
// exceeds the 10-byte maximum for a 64-bit varint. The
// google.golang.org/protobuf runtime rejects overlong varints.
func appendProtoVarintOverlong(b []byte, v uint64) []byte {
	start := len(b)
	for v >= 0x80 {
		b = append(b, byte(v&0x7f)|0x80)
		v >>= 7
	}
	// Convert the terminal byte into a continuation byte, then pad until the total
	// bytes written (from start) reaches 10, and add one more terminal byte at 11.
	b = append(b, byte(v)|0x80)
	for len(b)-start < 10 {
		b = append(b, 0x80)
	}
	return append(b, 0x00) // 11th byte: makes encoding overlong
}
