package mysqlfuzz

import "encoding/binary"

// This file builds the post-handshake MySQL *result-set* corpus: the wire
// packets a server sends in reply to COM_QUERY (text protocol) and to
// COM_STMT_PREPARE + COM_STMT_EXECUTE (binary protocol). Byte offsets match
// go-sql-driver/mysql@v1.10.1 packets.go exactly (readPrepareResultPacket,
// readColumns, readResultSetHeaderPacket, textRows.readRow, binaryRows.readRow;
// traced 2026-11-12). A mis-laid field makes the client reject the valid seed
// and the fuzzer never reaches the row parsers, so the seeds double as a wire
// conformance check (TestMySQLQuery_SeedsAreGreen).
//
// Field types (go-sql-driver const.go).
const (
	fieldTypeLongType   = 0x03 // fieldTypeLong (4-byte int in binary rows)
	fieldTypeStringType = 0xfd // fieldTypeVarString (length-encoded in binary rows)
)

// lenenc encodes a length-encoded integer (values < 251 are a single byte,
// which is all the seeds need).
func lenenc(n int) []byte {
	if n < 251 {
		return []byte{byte(n)}
	}
	if n < 1<<16 {
		return []byte{0xfc, byte(n), byte(n >> 8)}
	}
	return []byte{0xfd, byte(n), byte(n >> 8), byte(n >> 16)}
}

// lenstr encodes a length-encoded string.
func lenstr(s string) []byte {
	return append(lenenc(len(s)), []byte(s)...)
}

// prepareOKBody builds a COM_STMT_PREPARE OK response body (packet indicator
// 0x00): statement-id(4) column-count(2) param-count(2) reserved(1)
// warning-count(2). readPrepareResultPacket slices data[1:5]/[5:7]/[7:9] with NO
// length guard — a body shorter than 9 bytes panics it (see the reproducer).
func prepareOKBody(columnCount, paramCount uint16) []byte {
	b := []byte{0x00}                     // iOK indicator
	b = append(b, 0x01, 0x00, 0x00, 0x00) // statement id = 1
	b = le16(b, columnCount)              // column count
	b = le16(b, paramCount)               // param count
	b = append(b, 0x00)                   // reserved
	b = le16(b, 0x0000)                   // warning count
	return b
}

// columnDefBody builds a minimal ColumnDefinition41 body for the given column
// name and field type. Field order is pinned to readColumns: catalog "def",
// db "", table "", org_table "", name, org_name "", filler(1), charset(2),
// length(4), fieldType(1), flags(2), decimals(1).
func columnDefBody(name string, ft byte) []byte {
	var b []byte
	b = append(b, lenstr("def")...)       // catalog
	b = append(b, lenstr("")...)          // database
	b = append(b, lenstr("")...)          // table
	b = append(b, lenstr("")...)          // org_table
	b = append(b, lenstr(name)...)        // name
	b = append(b, lenstr("")...)          // org_name
	b = append(b, 0x0c)                   // filler / length-of-fixed-fields
	b = append(b, 0x21, 0x00)             // charset utf8_general_ci + collation
	b = append(b, 0x00, 0x00, 0x00, 0x00) // column length
	b = append(b, ft)                     // field type
	b = append(b, 0x00, 0x00)             // flags
	b = append(b, 0x00)                   // decimals
	return b
}

// eofBody is a classic EOF packet body (clientDeprecateEOF is NOT negotiated by
// this harness's handshake, so EOF packets are expected after column defs and
// after rows): 0xFE warnings(2) status(2). readStatus(data[3:]) reads the status.
func eofBody() []byte {
	return []byte{0xfe, 0x00, 0x00, 0x02, 0x00}
}

// resultHeaderBody is the text/binary result-set header: a length-encoded
// column count.
func resultHeaderBody(columnCount int) []byte {
	return lenenc(columnCount)
}

// textRowBody is a text-protocol result row: one length-encoded string per
// column.
func textRowBody(values ...string) []byte {
	var b []byte
	for _, v := range values {
		b = append(b, lenstr(v)...)
	}
	return b
}

// binaryRowBody builds a binary-protocol result row: 0x00 indicator, a NULL
// bitmap sized (numCols+7+2)/8, then each non-NULL value encoded for its type.
// binaryRows.readRow slices data[1:1+bitmapLen] with NO length guard — a row
// shorter than the bitmap its declared column count requires panics it.
func binaryRowBody(numCols int, values ...[]byte) []byte {
	bitmapLen := (numCols + 7 + 2) >> 3
	b := []byte{0x00}
	b = append(b, make([]byte, bitmapLen)...) // all columns non-NULL
	for _, v := range values {
		b = append(b, v...)
	}
	return b
}

// binStringVal encodes a length-encoded-string binary value.
func binStringVal(s string) []byte { return lenstr(s) }

// --- query-path group encoding (see buildQueryGroups in query_mysql_test.go) ---
//
// Encoding mirrors the handshake harness's buildScript: a stream of ops, each
// op byte's low 2 bits select an action. The difference: action 2 is a GROUP
// SEPARATOR (end the current response group) rather than a hard stop. A response
// group is the set of packets the fake server emits in reply to ONE client
// command, so the server can withhold the next group until the client has sent
// its next command (avoiding ErrBusyBuffer).

// encQPkt encodes one framed packet (action 0): [op][seq][plen:2 BE][payload].
func encQPkt(seq byte, payload []byte) []byte {
	out := []byte{0x00, seq}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	return append(append(out, l[:]...), payload...)
}

// encQPktClaim is encQPkt but declares extra body bytes (claim idx 0..7) so the
// server under-delivers (truncation oracle).
func encQPktClaim(seq byte, payload []byte, claimIdx byte) []byte {
	out := []byte{(claimIdx << 2) & 0x1c, seq}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	return append(append(out, l[:]...), payload...)
}

// encQSep is the group separator (action 2).
func encQSep() []byte { return []byte{0x02} }

// --- valid response groups (building blocks for seeds and oracles) ---

// prepareGroup is the full, valid COM_STMT_PREPARE response for a query with
// paramCount params and columnCount result columns: prepare-OK(seq1), then
// paramCount param col-defs + EOF, then columnCount result col-defs + EOF.
// Sequence numbers increment within the group starting at 1.
func prepareGroup(columnCount, paramCount uint16) []byte {
	seq := byte(1)
	var parts [][]byte
	parts = append(parts, encQPkt(seq, prepareOKBody(columnCount, paramCount)))
	seq++
	for i := 0; i < int(paramCount); i++ {
		parts = append(parts, encQPkt(seq, columnDefBody("p", fieldTypeStringType)))
		seq++
	}
	if paramCount > 0 {
		parts = append(parts, encQPkt(seq, eofBody()))
		seq++
	}
	for i := 0; i < int(columnCount); i++ {
		parts = append(parts, encQPkt(seq, columnDefBody("c", fieldTypeStringType)))
		seq++
	}
	if columnCount > 0 {
		parts = append(parts, encQPkt(seq, eofBody()))
	}
	return cat(parts...)
}

// executeBinaryGroup is a valid COM_STMT_EXECUTE response: header(seq1, N cols),
// N col-defs + EOF, one binary row + EOF.
func executeBinaryGroup(rowValue string) []byte {
	seq := byte(1)
	var parts [][]byte
	parts = append(parts, encQPkt(seq, resultHeaderBody(1)))
	seq++
	parts = append(parts, encQPkt(seq, columnDefBody("c", fieldTypeStringType)))
	seq++
	parts = append(parts, encQPkt(seq, eofBody()))
	seq++
	parts = append(parts, encQPkt(seq, binaryRowBody(1, binStringVal(rowValue))))
	seq++
	parts = append(parts, encQPkt(seq, eofBody()))
	return cat(parts...)
}

// textQueryGroup is a valid COM_QUERY text response: header(seq1, 1 col), one
// col-def + EOF, one text row + EOF.
func textQueryGroup(rowValue string) []byte {
	seq := byte(1)
	var parts [][]byte
	parts = append(parts, encQPkt(seq, resultHeaderBody(1)))
	seq++
	parts = append(parts, encQPkt(seq, columnDefBody("c", fieldTypeStringType)))
	seq++
	parts = append(parts, encQPkt(seq, eofBody()))
	seq++
	parts = append(parts, encQPkt(seq, textRowBody(rowValue)))
	seq++
	parts = append(parts, encQPkt(seq, eofBody()))
	return cat(parts...)
}

// mysqlQuerySeeds builds the result-set seed corpus. The first byte of each seed
// selects the client operation (see queryOp); the remainder decodes into
// response groups by buildQueryGroups.
func mysqlQuerySeeds() [][]byte {
	// Valid binary prepared-statement exchange: prepare group, separator,
	// execute group.
	validBinary := cat(
		[]byte{byte(opBinaryQuery)},
		prepareGroup(1, 1), encQSep(),
		executeBinaryGroup("ok-binary"),
	)

	// Valid text query exchange: a single group (COM_QUERY has one response).
	validText := cat(
		[]byte{byte(opTextQuery)},
		textQueryGroup("ok-text"),
	)

	// Prepare that returns an immediate ERR (e.g. syntax error) — a normal,
	// non-crashing path.
	prepareErr := cat(
		[]byte{byte(opBinaryQuery)},
		encQPkt(1, errPayload(1064, "42000", "You have an error in your SQL syntax")),
	)

	// Text query that returns 0 columns then OK (e.g. a statement that returns
	// no result set).
	textOK := cat(
		[]byte{byte(opTextQuery)},
		encQPkt(1, okPayload()),
	)

	// Binary prepare OK but execute returns an ERR.
	executeErr := cat(
		[]byte{byte(opBinaryQuery)},
		prepareGroup(1, 1), encQSep(),
		encQPkt(1, errPayload(1105, "HY000", "unknown error")),
	)

	return [][]byte{
		validBinary,
		validText,
		prepareErr,
		textOK,
		executeErr,
		// known-bad (non-crashing): truncated binary row — declares +16 body.
		cat([]byte{byte(opBinaryQuery)}, prepareGroup(1, 1), encQSep(),
			encQPkt(1, resultHeaderBody(1)), encQPkt(2, columnDefBody("c", fieldTypeStringType)),
			encQPkt(3, eofBody()), encQPktClaim(4, binaryRowBody(1, binStringVal("x")), 3), encQSep()),
		// empty.
		{byte(opBinaryQuery)},
		{byte(opTextQuery)},
	}
}
