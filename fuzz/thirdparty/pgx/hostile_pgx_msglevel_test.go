// Message-level (structure-aware) hostile-SERVER fuzzing of jackc/pgx/v5, complementing
// the byte-level harness in hostile_pgx_test.go / hostile_pgx_more_test.go (PR #4136).
//
// Where #4136 streams raw fuzzer bytes, this file uses pgproto3 (the same wire package
// pgx uses) as a GENERATOR — never as the oracle — to emit STRUCTURALLY-VALID backend
// messages whose individual fields are fuzzer-mutated, so the driver's decode path is
// driven with semantic disagreements a raw-byte seed rarely reaches on its own:
//   - RowDescription OID / format-code that disagrees with the DataRow bytes,
//   - RowDescription column count that disagrees with the DataRow column count,
//   - NoticeResponse / ErrorResponse field-level content,
//   - unexpected message order (DataRow before RowDescription, missing ReadyForQuery).
//
// Oracles (sound only; each is also covered by a red proof — see msglevel_redproof_test):
//   1. No panic escapes pgx's error path; bounded time (runWithOracles).
//   4. No credential leak: the canary password/DSN never appears in any error pgx
//      returns to the caller (scanned with internal/fuzzutil/canary).
//   5. Decoding parity: for every row pgx returns, pgx's raw column bytes
//      (rows.RawValues()) equal the exact bytes this harness encoded into the DataRow.
//      A mismatch means pgx mis-framed a column — a genuine finding.
//   6. Response mixing: a hostile reply to statement A never contaminates the decoded
//      result of statement B on the same connection (FuzzPgxResponseMixing).
//
// What these oracles do NOT verify: see the report (.scratch/pp1-REPORT.md).
package pgxhostile

import (
	"context"
	"net"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
)

// cursor is a tiny bounded reader over the fuzz input: each helper consumes a little of
// the input to make one field decision. Past the end it returns zero values, so a short
// input still produces a well-defined (small) message.
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

// blob reads a length byte then that many bytes (bounded to maxBlob) as a column value.
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

// candidate OIDs the harness picks from — the value types Keyorix stores/reads
// (bytea, text, jsonb, timestamptz, int4/int8) plus a couple of decode-sensitive ones.
var candOIDs = []uint32{25, 17, 3802, 1184, 23, 20, 16, 1043, 0}

// genResponse builds a (possibly incoherent) simple-query response from cur and sends it
// through be. It returns the DataRow column bytes it actually encoded (nil if it did not
// emit a DataRow) so the parity oracle can compare against what pgx decodes.
func genResponse(be *pgproto3.Backend, cur *cursor) [][]byte {
	ctrl := cur.u8()
	emitError := ctrl&0x01 != 0
	emitNotice := ctrl&0x02 != 0
	rowFirst := ctrl&0x04 != 0 // DataRow before RowDescription (illegal order)
	omitRFQ := ctrl&0x08 != 0

	numDesc := int(cur.u8()%4) + 1 // 1..4 described columns
	fields := make([]pgproto3.FieldDescription, numDesc)
	for i := range fields {
		fields[i] = pgproto3.FieldDescription{
			Name:         []byte{'c', byte('0' + i)},
			DataTypeOID:  candOIDs[int(cur.u8())%len(candOIDs)],
			DataTypeSize: -1,
			TypeModifier: -1,
			Format:       int16(cur.u8() & 1), // 0 text / 1 binary — may disagree with data
		}
	}

	numData := int(cur.u8() % 6) // 0..5 delivered columns (may disagree with numDesc)
	data := make([][]byte, numData)
	for i := range data {
		data[i] = cur.blob(64)
	}

	desc := &pgproto3.RowDescription{Fields: fields}
	row := &pgproto3.DataRow{Values: data}

	if emitNotice {
		be.Send(&pgproto3.NoticeResponse{Severity: "NOTICE", Code: "01000", Message: string(cur.blob(16))})
	}
	if rowFirst {
		be.Send(row)
		be.Send(desc)
	} else {
		be.Send(desc)
		be.Send(row)
	}
	if emitError {
		be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "XX000", Message: string(cur.blob(16))})
	}
	be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	if !omitRFQ {
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	}
	_ = be.Flush()
	// The column bytes the client should see, in the normal (desc-before-row) order.
	if rowFirst {
		return nil // order is illegal; pgx should error, parity is not asserted
	}
	return data
}

// sendSimpleHandshake writes a startup-success sequence that pgx's SIMPLE query protocol
// requires: it includes ParameterStatus(standard_conforming_strings=on) and
// client_encoding=UTF8, without which conn.Query under QueryExecModeSimpleProtocol refuses
// to run. (cannedHandshake omits these, which is fine for the extended-protocol byte-level
// harness but not here.)
func sendSimpleHandshake(c net.Conn) {
	be := pgproto3.NewBackend(c, c)
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = be.Flush()
}

// scanner builds a leak scanner over the canary password planted in the connection config.
func newLeakScanner(seed []byte) (*canary.Scanner, string) {
	pw := canary.New("pgx-msglevel-password", canary.Secret, seed, false)
	return canary.NewScanner(pw), pw.Raw
}

// FuzzPgxMessageLevel drives pgx's real simple-query path (conn.Exec/Query, as
// internal/dynamic/postgres.go and internal/rotation/postgres.go do) against a
// pgproto3-generated response with fuzzer-mutated fields, and asserts oracles 1/4/5.
func FuzzPgxMessageLevel(f *testing.F) {
	// Coherent 1-desc/1-data text row — the shape that actually reaches the parity
	// oracle (matching column counts, desc-before-row, decodable). Keep this green.
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 'h', 'i'})
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x02, 'h', 'i'}) // 1 desc / 2 data cols (count mismatch)
	f.Add([]byte{0x02, 0x01, 0x04, 0x01, 0x00})           // notice + int4 OID, 0 data cols
	f.Add([]byte{0x04, 0x00, 0x00, 0x01, 0x01, 'x'})      // DataRow-first (illegal order)
	f.Add([]byte{0x08, 0x02, 0x07, 0x02, 0x01, 'a'})      // omit RFQ, jsonb+... OIDs
	f.Fuzz(func(t *testing.T, in []byte) {
		scanner, pw := newLeakScanner(in)
		var genData [][]byte
		srv := hostile.NewServer(t, func(c net.Conn) {
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			sendSimpleHandshake(c)
			drainBriefly(c) // drain the client's Query
			be := pgproto3.NewBackend(c, c)
			genData = genResponse(be, &cursor{b: in})
			drainBriefly(c)
		})
		defer srv.Close()
		cfg := newConfigPW(t, srv.Addr(), pw)
		runWithOracles(t, func(ctx context.Context) {
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				assertNoLeak(t, scanner, "connect-error", err.Error())
				return
			}
			defer func() { _ = conn.Close(ctx) }()
			rows, err := conn.Query(ctx, "SELECT 1")
			if err != nil {
				assertNoLeak(t, scanner, "query-error", err.Error())
				return
			}
			for rows.Next() {
				raw := rows.RawValues()
				// ORACLE 5 (parity): pgx's raw column bytes must equal exactly what the
				// harness encoded into the DataRow, column-for-column.
				assertParity(t, genData, raw)
			}
			if err := rows.Err(); err != nil {
				assertNoLeak(t, scanner, "rows-error", err.Error())
			}
			rows.Close()
		})
	})
}

// assertParity compares pgx's decoded raw column bytes to the bytes the harness encoded.
// Only compared when genData is non-nil (coherent desc-before-row order) and pgx actually
// returned a row; a column-count or per-byte disagreement is a genuine finding.
func assertParity(t *testing.T, want, got [][]byte) {
	if want == nil {
		return
	}
	if len(got) != len(want) {
		t.Errorf("ORACLE parity: pgx decoded %d columns, harness encoded %d", len(got), len(want))
		return
	}
	for i := range want {
		if !bytesEqual(want[i], got[i]) {
			t.Errorf("ORACLE parity: column %d: pgx=%q harness=%q", i, got[i], want[i])
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// assertNoLeak fails if the canary password appears in channel (oracle 4).
func assertNoLeak(t *testing.T, scanner *canary.Scanner, channel, data string) {
	if hits := scanner.Scan(channel, []byte(data)); len(hits) > 0 {
		t.Errorf("ORACLE credential-leak: canary password leaked in %s: %v", channel, hits[0])
	}
}

// newConfigPW is newConfig with a caller-chosen (canary) password, so the password-leak
// oracle has a unique needle to scan for.
func newConfigPW(tb testing.TB, addr, pw string) *pgx.ConnConfig {
	host, port, _ := net.SplitHostPort(addr)
	cfg, err := pgx.ParseConfig("host=" + host + " port=" + port + " user=kx dbname=kx sslmode=disable")
	if err != nil {
		tb.Fatalf("parse config: %v", err)
	}
	cfg.Password = pw
	// Drive the SIMPLE query protocol so conn.Query emits a 'Q' and expects the
	// RowDescription/DataRow/CommandComplete/ReadyForQuery sequence this harness generates
	// (pgx's QueryExecModeSimpleProtocol — one of the modes pgx supports; the extended
	// default would instead expect Parse/Bind/Describe/Execute replies).
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return cfg
}

// newSimpleConfig is newConfig (fixed password) but driving the simple query protocol, so
// the generated RowDescription/DataRow responses are what pgx expects.
func newSimpleConfig(tb testing.TB, addr string) *pgx.ConnConfig {
	cfg := newConfig(tb, addr)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return cfg
}
