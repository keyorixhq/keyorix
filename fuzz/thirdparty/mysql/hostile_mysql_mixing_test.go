// Oracle 6 (response mixing) for MySQL: a hostile reply to statement A must never
// contaminate the decoded result of statement B on the same *sql.DB connection. The
// server answers query A with a fuzzer-generated (possibly out-of-sync) response and
// query B with a fixed sentinel row; if B returns a row it must be EXACTLY the sentinel.
package mysqlhostile

import (
	"bufio"
	"context"
	"database/sql"
	"net"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

const mysqlStmt2Sentinel = "KX_PP1_MYSQL_STMT2_SENTINEL_7a3c"

// sentinelResultSet builds a coherent one-column, one-row text result set carrying the
// sentinel, sequenced to follow the client's second COM_QUERY (sequence resets to 0 per
// command, so the result starts at seq 1).
func sentinelResultSet() []byte {
	var out []byte
	out = append(out, frame(1, []byte{0x01})...) // column count 1
	out = append(out, columnDef(2, 0xfd, 0)...)  // VAR_STRING
	out = append(out, eofPacket(3)...)
	out = append(out, frame(4, lenencStr([]byte(mysqlStmt2Sentinel)))...)
	out = append(out, eofPacket(5)...)
	return out
}

// FuzzMySQLResponseMixing runs two sequential queries on one *sql.DB: A gets a hostile
// result set, B gets the sentinel.
func FuzzMySQLResponseMixing(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 'a', 'b'}) // coherent A
	f.Add([]byte{0x01, 0x01, 0x00, 0x00})           // column-count mismatch A
	f.Add([]byte{0x00, 0x02, 0x08, 0x00})           // multi-col LONGLONG A
	f.Fuzz(func(t *testing.T, in []byte) {
		respA, _ := buildResultSet(&cursor{b: in})
		respB := sentinelResultSet()
		// answeredA is shared by every handler goroutine: hostile.NewServer runs one per
		// connection, and the driver reconnects after a hostile A poisons the socket. The
		// first COM_QUERY on any connection gets A, every later one gets B.
		var answeredA atomic.Bool
		srv := hostile.NewServer(t, func(c net.Conn) {
			r := bufio.NewReader(c)
			if err := completeHandshake(c, r); err != nil {
				return
			}
			for {
				if _, _, err := readOnePacket(r, capBytes); err != nil { // a COM_QUERY
					return
				}
				if answeredA.CompareAndSwap(false, true) {
					_, _ = c.Write(respA)
				} else {
					_, _ = c.Write(respB)
				}
			}
		})
		defer srv.Close()
		db := openDB(t, srv.Addr())
		defer func() { _ = db.Close() }()
		// Pin to a single underlying connection so A and B share one socket.
		db.SetMaxOpenConns(1)
		runWithOracles(t, func(ctx context.Context) {
			// Statement A — hostile. Drain and ignore.
			if rowsA, err := db.QueryContext(ctx, "SELECT c FROM a"); err == nil {
				for rowsA.Next() {
				}
				_ = rowsA.Close()
			}
			// Statement B — must be the sentinel or nothing.
			rowsB, err := db.QueryContext(ctx, "SELECT c FROM b")
			if err != nil {
				return
			}
			defer func() { _ = rowsB.Close() }()
			for rowsB.Next() {
				var v sql.RawBytes
				if err := rowsB.Scan(&v); err != nil {
					continue
				}
				if string(v) != mysqlStmt2Sentinel {
					t.Errorf("ORACLE response-mixing: statement B returned %q, not sentinel %q "+
						"(statement A contaminated it)", v, mysqlStmt2Sentinel)
				}
			}
		})
	})
}
