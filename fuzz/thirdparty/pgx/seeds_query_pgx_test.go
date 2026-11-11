package pgxfuzz

import "encoding/binary"

// Seeds for FuzzPgxHostileQuery: byte 0 selects the queryOp, the rest is the
// buildScript encoding of what the server sends AFTER the fixed handshake.

type fieldDesc struct {
	name   string
	oid    uint32
	format int16
}

func be16(v int16) []byte  { var b [2]byte; binary.BigEndian.PutUint16(b[:], uint16(v)); return b[:] }
func be32(v uint32) []byte { var b [4]byte; binary.BigEndian.PutUint32(b[:], v); return b[:] }

// rowDescription: int16 n; per field name\0, table oid, attr no, type oid,
// typlen, typmod, format.
func rowDescription(fs ...fieldDesc) []byte {
	out := be16(int16(len(fs)))
	for _, f := range fs {
		out = append(out, []byte(f.name)...)
		out = append(out, 0)
		out = append(out, be32(0)...)
		out = append(out, be16(0)...)
		out = append(out, be32(f.oid)...)
		out = append(out, be16(-1)...)
		out = append(out, be32(0xffffffff)...)
		out = append(out, be16(f.format)...)
	}
	return out
}

// dataRow: int16 n; per column int32 len (-1 = NULL) + bytes.
func dataRow(cols ...[]byte) []byte {
	out := be16(int16(len(cols)))
	for _, c := range cols {
		if c == nil {
			out = append(out, be32(0xffffffff)...)
			continue
		}
		out = append(out, be32(uint32(len(c)))...)
		out = append(out, c...)
	}
	return out
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func paramDescription(oids ...uint32) []byte {
	out := be16(int16(len(oids)))
	for _, o := range oids {
		out = append(out, be32(o)...)
	}
	return out
}

// copyResponse (CopyIn 'G' / CopyOut 'H' / CopyBoth 'W'): int8 format, int16 n, n×int16.
func copyResponse(n int) []byte {
	out := []byte{0}
	out = append(out, be16(int16(n))...)
	for range n {
		out = append(out, be16(0)...)
	}
	return out
}

// binary int4[] value: ndims, hasnull, elemoid, dims..., elements.
func binInt4Array(vals ...int32) []byte {
	out := be32(1)
	out = append(out, be32(0)...)
	out = append(out, be32(23)...)
	out = append(out, be32(uint32(len(vals)))...)
	out = append(out, be32(1)...)
	for _, v := range vals {
		out = append(out, be32(4)...)
		out = append(out, be32(uint32(v))...)
	}
	return out
}

const (
	oidBool, oidBytea, oidInt8, oidInt4, oidText = 16, 17, 20, 23, 25
	oidJSON, oidFloat8, oidInet, oidInt4Arr      = 114, 701, 869, 1007
	oidTextArr, oidTimestamptz, oidInterval      = 1009, 1184, 1186
	oidNumeric, oidJSONB, oidInt8Range, oidUUID  = 1700, 3802, 3926, 2950
)

func pgxQuerySeeds() [][]byte {
	mixedFields := rowDescription(
		fieldDesc{"a", oidText, 0}, fieldDesc{"b", oidInt8, 0}, fieldDesc{"c", oidNumeric, 0},
		fieldDesc{"d", oidJSONB, 0}, fieldDesc{"e", oidTimestamptz, 0}, fieldDesc{"f", oidInt4Arr, 0},
		fieldDesc{"g", oidInet, 0}, fieldDesc{"h", oidInterval, 0}, fieldDesc{"i", oidInt8Range, 0},
		fieldDesc{"j", oidUUID, 0}, fieldDesc{"k", oidBytea, 0},
	)
	mixedRow := dataRow([]byte("hello"), []byte("42"), []byte("3.14159"), []byte(`{"k":[1,2]}`),
		[]byte("2026-11-11 12:00:00+00"), []byte("{1,2,3}"), []byte("10.0.0.0/8"), []byte("1 day 02:03:04"),
		[]byte("[1,10)"), []byte("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"), []byte(`\xdeadbeef`))
	binFields := rowDescription(
		fieldDesc{"a", oidInt4Arr, 1}, fieldDesc{"b", oidNumeric, 1}, fieldDesc{"c", oidFloat8, 1},
		fieldDesc{"d", oidBool, 1}, fieldDesc{"e", oidTextArr, 1},
	)
	binRow := dataRow(binInt4Array(1, 2, 3),
		[]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 7}, // numeric 7 (ndigits=1, weight=0, sign=0, dscale=0, digit=7)
		[]byte{0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18},
		[]byte{1}, nil)
	simple := cat(
		encMsg('T', mixedFields), encMsg('D', mixedRow), encMsg('D', mixedRow),
		encMsg('C', cstr("SELECT 2")), encMsg('Z', readyForQuery()), encClose(),
	)
	withNoise := cat(
		encMsg('N', errorResponse(map[byte]string{'S': "NOTICE", 'M': "noise"})),
		encMsg('S', paramStatus("TimeZone", "UTC")),
		encMsg('A', append(append(be32(9), cstr("chan")...), cstr("payload")...)),
		encMsg('T', mixedFields), encMsg('D', mixedRow),
		encMsg('E', errorResponse(map[byte]string{'S': "ERROR", 'C': "XX000", 'M': "mid-result failure"})),
		encMsg('Z', readyForQuery()), encClose(),
	)
	extended := cat(
		encMsg('1', nil), encMsg('2', nil), encMsg('T', binFields), encMsg('D', binRow),
		encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose(),
	)
	prepared := cat(
		encMsg('1', nil), encMsg('t', paramDescription(oidText, oidInt8, oidBytea)),
		encMsg('T', binFields), encMsg('Z', readyForQuery()),
		encMsg('2', nil), encMsg('D', binRow), encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose(),
	)
	preparedOddTypes := cat(
		encMsg('1', nil), encMsg('t', paramDescription(oidInet, oidInterval, oidInt4Arr)),
		encMsg('n', nil), encMsg('Z', readyForQuery()), encClose(),
	)
	execTag := cat(encMsg('C', cstr("CREATE ROLE")), encMsg('Z', readyForQuery()), encClose())
	copyOut := cat(
		encMsg('H', copyResponse(2)), encMsg('d', []byte("1\tabc\n")), encMsg('d', []byte("2\tdef\n")),
		encMsg('c', nil), encMsg('C', cstr("COPY 2")), encMsg('Z', readyForQuery()), encClose(),
	)
	copyIn := cat(encMsg('G', copyResponse(2)), encMsg('C', cstr("COPY 2")), encMsg('Z', readyForQuery()), encClose())
	copyBoth := cat(encMsg('W', copyResponse(1)), encMsg('d', []byte("x")), encMsg('Z', readyForQuery()), encClose())
	multi := cat(
		encMsg('T', rowDescription(fieldDesc{"?column?", oidInt4, 0})), encMsg('D', dataRow([]byte("1"))), encMsg('C', cstr("SELECT 1")),
		encMsg('T', rowDescription(fieldDesc{"?column?", oidInt4, 0})), encMsg('D', dataRow([]byte("2"))), encMsg('C', cstr("SELECT 1")),
		encMsg('I', nil), encMsg('Z', readyForQuery()), encClose(),
	)
	withOp := func(op queryOp, body []byte) []byte { return append([]byte{byte(op)}, body...) }

	return [][]byte{
		withOp(opSimpleQuery, simple),
		withOp(opSimpleQuery, withNoise),
		withOp(opExecModeQuery, extended),
		withOp(opCachedPrepared, prepared),
		withOp(opCachedPrepared, preparedOddTypes),
		withOp(opSimpleExec, execTag),
		withOp(opCopyTo, copyOut),
		withOp(opCopyFrom, copyIn),
		withOp(opCopyTo, copyBoth),
		withOp(opMultiResult, multi),
		withOp(opTypedScan, simple),
		withOp(opTypedScan, cat(encMsg('T', binFields), encMsg('D', binRow), encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())),
		// known-bad: DataRow with more columns than RowDescription declared.
		withOp(opSimpleQuery, cat(encMsg('T', rowDescription(fieldDesc{"a", oidText, 0})), encMsg('D', dataRow([]byte("x"), []byte("y"))), encMsg('Z', readyForQuery()), encClose())),
		// known-bad: DataRow before any RowDescription.
		withOp(opSimpleQuery, cat(encMsg('D', dataRow([]byte("x"))), encMsg('Z', readyForQuery()), encClose())),
		// known-bad: binary int4[] claiming 2^31-1 elements in a tiny value.
		withOp(opTypedScan, cat(encMsg('T', rowDescription(fieldDesc{"a", oidInt4Arr, 1})),
			encMsg('D', dataRow(append(append(append(be32(1), be32(0)...), be32(23)...), append(be32(0x7fffffff), be32(1)...)...))),
			encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())),
		// known-bad: DataRow column length claims past the message end.
		withOp(opSimpleQuery, cat(encMsg('T', rowDescription(fieldDesc{"a", oidText, 0})), encMsg('D', append(be16(1), be32(0x7ffffff0)...)), encClose())),
		// known-bad: huge declared CopyData body with tiny payload.
		withOp(opCopyTo, cat(encMsg('H', copyResponse(1)), encMsgClaim('d', []byte("x"), 7), encClose())),
		{},
	}
}
