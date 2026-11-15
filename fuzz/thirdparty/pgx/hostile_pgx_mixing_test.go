// Oracle 6 (response mixing) for pgx: a hostile reply to statement A on a connection must
// never contaminate the decoded result of statement B on the SAME connection. pgx
// multiplexes every statement over one socket and relies on the protocol's
// ReadyForQuery framing to know where one statement's response ends; a hostile server
// that omits/duplicates RFQ or over-runs its DataRows could, in a buggy client, bleed
// bytes from A's response into B's. The oracle plants a unique sentinel as B's only
// column value and asserts that if B returns a row, that row is EXACTLY the sentinel.
package pgxhostile

import (
	"context"
	"net"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// stmt2Sentinel is the single column value statement B's response carries. It is chosen
// to be unlikely to appear in an arbitrary statement-A payload.
const stmt2Sentinel = "KX_PP1_STMT2_SENTINEL_e9f1"

// fixedSentinelResponse is the coherent, valid response to statement B.
func fixedSentinelResponse(be *pgproto3.Backend) {
	be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{
		Name: []byte("s"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0,
	}}})
	be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(stmt2Sentinel)}})
	be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = be.Flush()
}

// FuzzPgxResponseMixing drives two sequential queries on one connection: statement A gets
// a fuzzer-generated (possibly out-of-sync) response, statement B gets the fixed sentinel.
func FuzzPgxResponseMixing(f *testing.F) {
	// Coherent A that leaves the connection in sync — the shape under which statement B
	// actually returns the sentinel, so the mixing oracle is genuinely exercised.
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 'a', 'b'})
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x02, 'a', 'b'}) // A: count mismatch (poisons conn)
	f.Add([]byte{0x08, 0x00, 0x00, 0x02, 0x00})           // A omits RFQ (out of sync)
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00})           // A is an ErrorResponse
	f.Fuzz(func(t *testing.T, in []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			sendSimpleHandshake(c)
			be := pgproto3.NewBackend(c, c)
			drainBriefly(c) // client Query A
			genResponse(be, &cursor{b: in})
			drainBriefly(c) // client Query B (only sent after A's response is consumed)
			fixedSentinelResponse(be)
			drainBriefly(c)
		})
		defer srv.Close()
		cfg := newSimpleConfig(t, srv.Addr())
		runWithOracles(t, func(ctx context.Context) {
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close(ctx) }()
			// Statement A — hostile response. Drain whatever it yields; ignore errors.
			if rowsA, err := conn.Query(ctx, "SELECT 1"); err == nil {
				for rowsA.Next() {
					_ = rowsA.RawValues()
				}
				rowsA.Close()
			}
			// Statement B — must be the sentinel or nothing, never A's bytes.
			rowsB, err := conn.Query(ctx, "SELECT 2")
			if err != nil {
				return
			}
			defer rowsB.Close()
			for rowsB.Next() {
				vals := rowsB.RawValues()
				if len(vals) != 1 || string(vals[0]) != stmt2Sentinel {
					t.Errorf("ORACLE response-mixing: statement B returned %q, not the sentinel %q "+
						"(statement A's hostile response contaminated it)", vals, stmt2Sentinel)
				}
			}
		})
	})
}
