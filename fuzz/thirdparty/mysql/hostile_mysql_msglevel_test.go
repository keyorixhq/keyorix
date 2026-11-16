// Message-level (structure-aware) hostile-SERVER fuzzing of go-sql-driver/mysql,
// complementing the byte-level harness in hostile_mysql_test.go (PR #4136).
//
// Where #4136 streams raw framed bytes, this file HAND-BUILDS valid MySQL packets
// (column-count header, column definitions, text rows, OK/ERR/EOF, LOCAL INFILE request)
// and mutates individual fields from the fuzz input — column count, column type byte and
// flags, row value framing — so the driver's text-protocol decode path is driven with
// semantic disagreements (column-def type vs row bytes, declared vs delivered column
// count) that a raw-byte seed rarely reaches.
//
// Oracles (sound only; each has a red proof in hostile_mysql_msglevel_redproof_test.go):
//  1. No panic escapes the driver's error path (except the ALREADY-KNOWN short-packet
//     class, recorded by isKnownShortPacketPanic); bounded time (runWithOracles).
//  4. No credential leak: the canary password never appears in any error the driver
//     returns to the caller (internal/fuzzutil/canary).
//  5. Decoding parity: for a coherent one-row result set, the []byte the driver Scans
//     equals the exact value bytes this harness length-encoded into the row. A mismatch
//     means the driver mis-framed the value — a genuine finding.
//
// Oracle 3 (LOCAL INFILE) is in hostile_mysql_localinfile_canary_test.go; oracle 6
// (response mixing) in hostile_mysql_mixing_test.go; oracle 2 (TLS) in
// hostile_mysql_tls_test.go. What these do NOT verify: see the report.
package mysqlhostile

import (
	"bufio"
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
)

// lenencStr prefixes b with a MySQL length-encoded-integer length (values < 251 use a
// single length byte, which is all the harness needs).
func lenencStr(b []byte) []byte {
	if len(b) < 251 {
		return append([]byte{byte(len(b))}, b...)
	}
	// 0xfc + 2-byte LE length for mid-size values.
	n := len(b)
	return append([]byte{0xfc, byte(n), byte(n >> 8)}, b...)
}

// columnDef builds one COM_QUERY column-definition packet (protocol 41) for a column
// named "c" of the given MySQL type byte and flags.
func columnDef(seq, colType byte, flags uint16) []byte {
	var p []byte
	p = append(p, lenencStr([]byte("def"))...) // catalog
	p = append(p, lenencStr(nil)...)           // schema
	p = append(p, lenencStr(nil)...)           // table
	p = append(p, lenencStr(nil)...)           // org_table
	p = append(p, lenencStr([]byte("c"))...)   // name
	p = append(p, lenencStr(nil)...)           // org_name
	p = append(p, 0x0c)                        // length of fixed-length fields
	p = append(p, 0x2d, 0x00)                  // charset utf8mb4
	p = append(p, 0xff, 0x00, 0x00, 0x00)      // column length
	p = append(p, colType)                     // type
	p = append(p, byte(flags), byte(flags>>8)) // flags
	p = append(p, 0x00)                        // decimals
	p = append(p, 0x00, 0x00)                  // filler
	return frame(seq, p)
}

// eofPacket builds a classic EOF packet (warnings=0, status=autocommit).
func eofPacket(seq byte) []byte {
	return frame(seq, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
}

// mysqlTypeVarString etc — a few type bytes the mutator picks from.
var candTypes = []byte{0xfd /*VAR_STRING*/, 0x03 /*LONG*/, 0x08 /*LONGLONG*/, 0xf6 /*NEWDECIMAL*/, 0x0c /*DATETIME*/, 0xfc /*BLOB*/}

// buildResultSet assembles a text-protocol result set driven by cur, returning the full
// server bytes and the single row's column value bytes (for the parity oracle), or
// (bytes, nil) when the shape is incoherent and parity must not be asserted.
func buildResultSet(cur *cursor) ([]byte, [][]byte) {
	ctrl := cur.u8()
	numCols := int(cur.u8()%3) + 1 // 1..3 declared columns
	mismatchCount := ctrl&0x01 != 0
	colType := candTypes[int(cur.u8())%len(candTypes)]
	flags := uint16(cur.u8())

	var out []byte
	out = append(out, frame(1, []byte{byte(numCols)})...) // column-count header
	seq := byte(2)
	for range numCols {
		out = append(out, columnDef(seq, colType, flags)...)
		seq++
	}
	out = append(out, eofPacket(seq)...)
	seq++

	// One row. If mismatchCount, deliver a different number of column values than declared.
	deliver := numCols
	if mismatchCount {
		deliver = int(cur.u8() % 4)
	}
	vals := make([][]byte, deliver)
	var rowBody []byte
	for i := range vals {
		vals[i] = cur.blob(32)
		rowBody = append(rowBody, lenencStr(vals[i])...)
	}
	out = append(out, frame(seq, rowBody)...)
	seq++
	out = append(out, eofPacket(seq)...)

	// Parity (byte-identity) only holds for column types go-sql-driver returns VERBATIM in
	// the text protocol. Numeric/decimal/temporal types are CANONICALISED by the driver
	// (confirmed: an UNSIGNED INT text value "000…0" is returned as "0"), which is a
	// documented driver behaviour, not a mis-frame — so the byte-identity oracle must not
	// apply to them (they are still fuzzed for no-panic/leak, just not parity).
	if mismatchCount || numCols != 1 || !isTextVerbatimType(colType) {
		return out, nil
	}
	return out, vals
}

// isTextVerbatimType reports whether go-sql-driver returns a text-protocol column of this
// type as its raw field bytes (no numeric/temporal canonicalisation). Restricted to the
// string/blob types in candTypes; see the parity note in buildResultSet.
func isTextVerbatimType(colType byte) bool {
	switch colType {
	case 0xfd /*VAR_STRING*/, 0xfc /*BLOB*/, 0xfe /*STRING*/, 0x0f /*VARCHAR*/ :
		return true
	}
	return false
}

// cursor is a bounded reader over the fuzz input (same idea as the pgx harness).
type cursor struct {
	b []byte
	i int
}

func (c *cursor) u8() byte {
	if c.i >= len(c.b) {
		return 0
	}
	v := c.b[c.i]
	c.i++
	return v
}

func (c *cursor) blob(maxBlob int) []byte {
	n := int(c.u8())
	if n > maxBlob {
		n = maxBlob
	}
	out := make([]byte, 0, n)
	for range n {
		out = append(out, c.u8())
	}
	return out
}

// openDBPW mirrors openDB (same timeouts, same TLS-less config Keyorix's openMySQLConfig
// produces) but with a caller-chosen (canary) password, so the leak oracle has a unique
// needle to scan error text for.
func openDBPW(tb testing.TB, addr, pw string) *sql.DB {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.User = "kxadmin"
	cfg.Passwd = pw
	cfg.Timeout = 300 * time.Millisecond
	cfg.ReadTimeout = 300 * time.Millisecond
	cfg.WriteTimeout = 300 * time.Millisecond
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		tb.Fatalf("new connector: %v", err)
	}
	return sql.OpenDB(connector)
}

// FuzzMySQLMessageLevel drives db.QueryContext (the row-decoding path) against a
// hand-built, field-mutated text result set, asserting oracles 1/4/5.
func FuzzMySQLMessageLevel(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 'h', 'i'})       // 1 col VAR_STRING, row "hi"
	f.Add([]byte{0x01, 0x01, 0x01, 0x00, 0x00})           // column-count mismatch
	f.Add([]byte{0x00, 0x02, 0x02, 0x00, 0x03, 'a', 'b'}) // multi-col, LONG type
	f.Fuzz(func(t *testing.T, in []byte) {
		pw := canary.New("mysql-msglevel-password", canary.Secret, in, false)
		scanner := canary.NewScanner(pw)
		resp, wantVals := buildResultSet(&cursor{b: in})
		srv := hostile.NewServer(t, func(c net.Conn) {
			r := bufio.NewReader(c)
			if err := completeHandshake(c, r); err != nil {
				return
			}
			if _, _, err := readOnePacket(r, capBytes); err != nil { // client COM_QUERY
				return
			}
			_, _ = c.Write(resp)
			drainWrites(c)
		})
		defer srv.Close()
		db := openDBPW(t, srv.Addr(), pw.Raw)
		defer func() { _ = db.Close() }()
		runWithOracles(t, func(ctx context.Context) {
			rows, err := db.QueryContext(ctx, "SELECT c FROM t")
			if err != nil {
				scanLeak(t, scanner, "query-error", err.Error())
				return
			}
			defer func() { _ = rows.Close() }()
			cols, _ := rows.Columns()
			for rows.Next() {
				dst := make([]any, len(cols))
				raw := make([]sql.RawBytes, len(cols))
				for i := range dst {
					dst[i] = &raw[i]
				}
				if err := rows.Scan(dst...); err != nil {
					scanLeak(t, scanner, "scan-error", err.Error())
					continue
				}
				// ORACLE 5 (parity): the scanned bytes must equal the length-encoded value.
				if wantVals != nil && len(cols) == 1 && len(wantVals) == 1 {
					if string(raw[0]) != string(wantVals[0]) {
						t.Errorf("ORACLE parity: driver scanned %q, harness encoded %q", raw[0], wantVals[0])
					}
				}
			}
			if err := rows.Err(); err != nil {
				scanLeak(t, scanner, "rows-error", err.Error())
			}
		})
	})
}

func scanLeak(t *testing.T, scanner *canary.Scanner, channel, data string) {
	if hits := scanner.Scan(channel, []byte(data)); len(hits) > 0 {
		t.Errorf("ORACLE credential-leak: canary password leaked in %s: %v", channel, hits[0])
	}
}
