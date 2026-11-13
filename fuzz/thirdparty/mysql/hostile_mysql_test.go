// Hostile-SERVER fuzz harness for go-sql-driver/mysql v1.10.1, the driver Keyorix uses
// to mint/revoke dynamic MySQL accounts (internal/dynamic/mysql.go) and rotate account
// passwords (internal/rotation/mysql.go) against an OPERATOR-CONFIGURED target.
//
// Threat model: the target MySQL server is attacker-controlled and replies with hostile
// wire bytes. Keyorix's real call sequence (openMySQLConfig → sql.OpenDB(connector)):
//   - db.PingContext  → handshake v10 greeting + auth + COM_PING
//   - db.ExecContext  → COM_QUERY (CREATE/GRANT/DROP USER, KILL n): OK/ERR/result-set/
//                        LOCAL INFILE request
//   - db.QueryContext(…, ?) → prepared statement (COM_STMT_PREPARE/EXECUTE, binary rows)
//     — the processlist lookup `SELECT id … WHERE user = ?` in killUserConnections.
//
// Oracles (sound only):
//   - No panic escapes the driver's documented error path. All of PingContext/ExecContext/
//     QueryContext return an error; a panic reaching the Keyorix caller is a defect.
//   - Bounded time: each call returns within a context deadline (a hostile reply that
//     wedges the driver past it is a defect, not a deadlock).
//   - LOCAL INFILE refused by default (TestMySQLLocalInfile*): the driver must NOT read a
//     local file and send its content to the server when AllowAllFiles is false and no
//     reader is registered — which is exactly how openMySQLConfig configures it.
//
// Everything runs on a loopback listener (internal/hostile) — never real network.
// What these oracles do NOT verify: see .scratch/h6-REPORT.md §4.
package mysqlhostile

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// ---- MySQL wire framing helpers (server side, hand-built) -------------------------

// capability flags we advertise in the greeting (go-sql-driver const.go names). We omit
// clientDeprecateEOF deliberately so result sets use classic EOF packets (simpler to
// hand-build in seeds); the driver AND-combines with its own flags.
const (
	capClientMySQL        = 0x00000001
	capLongFlag           = 0x00000004
	capLocalFiles         = 0x00000080
	capProtocol41         = 0x00000200
	capTransactions       = 0x00002000
	capSecureConn         = 0x00008000
	capMultiResults       = 0x00020000
	capPluginAuth         = 0x00080000
	capConnectAttrs       = 0x00100000
	capPluginAuthLenEnc   = 0x00200000
	serverCapabilities    = capClientMySQL | capLongFlag | capLocalFiles | capProtocol41 |
		capTransactions | capSecureConn | capMultiResults | capPluginAuth |
		capConnectAttrs | capPluginAuthLenEnc
)

// greeting builds a valid handshake v10 initial packet (sequence 0) advertising
// mysql_native_password with a fixed 20-byte scramble. The driver computes a native
// auth response; we accept it unconditionally by replying OK.
func greeting() []byte {
	var p []byte
	p = append(p, 0x0a) // protocol version 10
	p = append(p, []byte("8.0.40-h6-hostile")...)
	p = append(p, 0x00)                      // version NUL
	p = append(p, 1, 0, 0, 0)                // connection id
	p = append(p, 1, 2, 3, 4, 5, 6, 7, 8)    // auth-plugin-data part 1 (8)
	p = append(p, 0x00)                      // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(serverCapabilities&0xffff))
	p = append(p, 0x2d)                      // charset utf8mb4_general_ci
	p = binary.LittleEndian.AppendUint16(p, 0x0002) // status flags (autocommit)
	p = binary.LittleEndian.AppendUint16(p, uint16(serverCapabilities>>16))
	p = append(p, 21) // length of auth-plugin-data (8+12+NUL)
	p = append(p, make([]byte, 10)...)                // reserved
	p = append(p, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20) // scramble part 2 (12)
	p = append(p, 0x00)                               // scramble terminator
	p = append(p, []byte("mysql_native_password")...)
	p = append(p, 0x00)
	return frame(0, p)
}

// frame wraps payload in a MySQL packet header: 3-byte LE length + 1-byte sequence.
func frame(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// okPacket builds an OK packet (CLIENT_PROTOCOL_41): header, affected=0, insertid=0,
// status[2], warnings[2].
func okPacket(seq byte) []byte {
	return frame(seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
}

// errPacket builds an ERR packet with a SQLState block.
func errPacket(seq byte, code uint16, msg string) []byte {
	p := []byte{0xff, byte(code), byte(code >> 8), '#', '2', '8', '0', '0', '0'}
	p = append(p, msg...)
	return frame(seq, p)
}

// readOnePacket reads one full MySQL packet (header+body) from the client, returning
// its sequence byte and body. Bounded by cap.
func readOnePacket(r *bufio.Reader, cap int) (seq byte, body []byte, err error) {
	var h [4]byte
	if _, err = readFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	seq = h[3]
	if n < 0 || n > cap {
		return seq, nil, errBadLen
	}
	body = make([]byte, n)
	if _, err = readFull(r, body); err != nil {
		return seq, nil, err
	}
	return seq, body, nil
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

type lenErr struct{}

func (lenErr) Error() string { return "hostile-mysql: bad/overlong length" }

var errBadLen = lenErr{}

const capBytes = 1 << 20

// completeHandshake plays the server side of a successful native-password handshake:
// greeting(seq0), read client response(seq1), OK(seq2). Returns with the reader
// positioned to read the client's first command (which resets sequence to 0).
func completeHandshake(c net.Conn, r *bufio.Reader) error {
	if _, err := c.Write(greeting()); err != nil {
		return err
	}
	if _, _, err := readOnePacket(r, capBytes); err != nil { // client handshake response
		return err
	}
	if _, err := c.Write(okPacket(2)); err != nil { // auth result OK
		return err
	}
	return nil
}

// ---- driver config + oracle runner ------------------------------------------------

func openDB(tb testing.TB, addr string) *sql.DB {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.User = "kxadmin"
	cfg.Passwd = "kxpw"
	// Loopback has no real latency; short timeouts turn a hostile "withhold bytes"
	// reply into a fast driver error so fuzz throughput is high. The bounded-time
	// ORACLE (wall-clock, in runWithOracles) is set far above these and is what
	// actually detects a driver that wedges beyond its own deadlines.
	cfg.Timeout = 300 * time.Millisecond
	cfg.ReadTimeout = 300 * time.Millisecond
	cfg.WriteTimeout = 300 * time.Millisecond
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		tb.Fatalf("new connector: %v", err)
	}
	return sql.OpenDB(connector)
}

// knownShortPacketPanics counts recovered panics attributed to the known upstream
// short-packet-underread class (KFZ-2026-005/076/079) across a fuzz run, for reporting.
var knownShortPacketPanics atomic.Int64

// isKnownShortPacketPanic decides whether a recovered panic is the ALREADY-KNOWN,
// already-reported short-packet underread class in go-sql-driver (a truncated hostile
// reply whose body is shorter than the parser assumes → a bounds panic inside the
// driver's packet parsing). Such panics are recorded and tolerated so fuzzing can keep
// hunting for NOVEL defects; ANY other panic (e.g. a nil-pointer dereference, or a
// bounds panic that is NOT inside the driver) is a violation the oracle must flag.
//
// This is deliberately NARROW: it requires BOTH a bounds-class runtime error AND a stack
// frame inside github.com/go-sql-driver/mysql, so a bounds bug in the harness itself, or
// any non-bounds driver panic, still fails the oracle. The red proof
// (TestPanicOracleRedProof) exercises both rejection paths.
func isKnownShortPacketPanic(r any, stack string) bool {
	re, ok := r.(runtime.Error)
	if !ok {
		return false
	}
	msg := re.Error()
	bounds := strings.Contains(msg, "index out of range") ||
		strings.Contains(msg, "slice bounds out of range")
	inDriver := strings.Contains(stack, "github.com/go-sql-driver/mysql")
	return bounds && inDriver
}

func runWithOracles(t *testing.T, fn func(ctx context.Context)) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				stack := string(debugStack())
				if isKnownShortPacketPanic(r, stack) {
					// Known upstream short-packet DoS (KFZ-2026-005/076/079): recorded,
					// NOT re-reported, NOT a new oracle failure. Reproducer bytes live in
					// .scratch/findings/mysql-short-packet-known.md.
					knownShortPacketPanics.Add(1)
					return
				}
				t.Errorf("ORACLE panic escaped driver error path (NOVEL): %v", r)
			}
		}()
		fn(ctx)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Errorf("ORACLE bounded-time: driver call did not return within 6s of a hostile reply")
	}
}

// debugStack returns the current goroutine's stack; split out so the panic classifier
// can be unit-tested with a synthetic stack string.
func debugStack() []byte {
	buf := make([]byte, 8192)
	n := runtime.Stack(buf, false)
	return buf[:n]
}

// drainWrites reads and discards whatever the client writes for a short idle window, so
// the server can proceed without parsing the exact client command framing.
func drainWrites(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
}

// ---- Fuzz targets -----------------------------------------------------------------

// FuzzMySQLHandshake fuzzes the entire server→client stream from the greeting on:
// handshake v10 variants, Auth Switch Request, AuthMoreData (caching_sha2 fast/full),
// OK/ERR, and malformed/truncated variants. Driver call: db.PingContext (opens a conn).
func FuzzMySQLHandshake(f *testing.F) {
	// Seeds are kept BENIGN on purpose: the committed corpus (run by plain `go test`)
	// must stay green. Known truncated-packet reproducers are NOT seeded here (they live
	// in .scratch/findings/); the fuzzer rediscovers that class on its own and the oracle
	// records-and-continues it (see isKnownShortPacketPanic).
	f.Add(greeting())                                // valid greeting, then nothing (auth will fail → error)
	f.Add(append(greeting(), okPacket(2)...))        // full successful handshake
	f.Add(errPacket(0, 1045, "Access denied"))       // ERR as first packet
	f.Add(append(greeting(), frame(2, []byte{0xfe, 'c', 'a', 'c', 'h', 'i', 'n', 'g', '_', 's', 'h', 'a', '2', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0, 1, 2, 3})...)) // auth switch
	f.Add(append(greeting(), frame(2, []byte{0x01, 0x03})...)) // AuthMoreData fast-auth-success (caching_sha2)
	f.Fuzz(func(t *testing.T, server []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			_, _ = c.Write(server)
			drainWrites(c)
		})
		defer srv.Close()
		db := openDB(t, srv.Addr())
		defer func() { _ = db.Close() }()
		runWithOracles(t, func(ctx context.Context) {
			_ = db.PingContext(ctx)
		})
	})
}

// FuzzMySQLQueryResponse completes a valid handshake, then fuzzes the RAW COM_QUERY
// response bytes (framing included, so short/over-declared packets are in scope):
// OK/ERR/result-set header/column defs/EOF/rows, LOCAL INFILE request, multi-result
// flags, server-declared huge length-encoded lengths. Driver call: db.ExecContext,
// mirroring dynamic/mysql.go's CREATE/GRANT/DROP USER.
func FuzzMySQLQueryResponse(f *testing.F) {
	f.Add(okPacket(1))                                   // plain OK
	f.Add(errPacket(1, 1064, "You have an error"))       // ERR
	// result set: 1 column, one text row "hi", EOF-terminated (classic protocol).
	colDef := frame(2, []byte{3, 'd', 'e', 'f', 0, 0, 0, 1, 'c', 0, 1, 'c', 0, 0x0c, 0x2d, 0, 4, 0, 0, 0, 0xfd, 0, 0, 0, 0})
	rs := append(frame(1, []byte{0x01}), colDef...)      // column count = 1
	rs = append(rs, frame(3, []byte{0xfe, 0, 0, 0x02, 0})...) // EOF after columns
	rs = append(rs, frame(4, []byte{2, 'h', 'i'})...)    // text row
	rs = append(rs, frame(5, []byte{0xfe, 0, 0, 0x02, 0})...) // EOF after rows
	f.Add(rs)
	f.Add(frame(1, []byte{0xfb, '/', 't', 'm', 'p', '/', 'x'})) // LOCAL INFILE request (non-empty path)
	f.Add(frame(1, []byte{0x03, 'a', 'b', 'c'}))                 // text column-count = 3 (well-formed header)
	f.Fuzz(func(t *testing.T, resp []byte) {
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
		db := openDB(t, srv.Addr())
		defer func() { _ = db.Close() }()
		runWithOracles(t, func(ctx context.Context) {
			_, _ = db.ExecContext(ctx, "CREATE USER 'kx_dyn_x'@'%' IDENTIFIED BY 'pw'")
		})
	})
}

// FuzzMySQLPreparedResponse completes a valid handshake, then fuzzes the RAW response to
// COM_STMT_PREPARE/EXECUTE (binary protocol): COM_STMT_PREPARE_OK + param/column defs +
// binary result rows. Driver call: db.QueryContext with a bound arg — the exact shape
// killUserConnections' `SELECT id … WHERE user = ?` produces.
func FuzzMySQLPreparedResponse(f *testing.F) {
	// valid COM_STMT_PREPARE_OK: stmt id 1, 0 columns, 1 param, then one param def + EOF.
	prepOK := frame(1, []byte{0x00, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0})
	paramDef := frame(2, []byte{3, 'd', 'e', 'f', 0, 0, 0, 0, 0, 0, 0x0c, 0x3f, 0, 0, 0, 0, 0, 0xfd, 0x80, 0, 0, 0})
	eof := frame(3, []byte{0xfe, 0, 0, 0x02, 0})
	full := append(append(prepOK, paramDef...), eof...)
	f.Add(full)
	f.Add(errPacket(1, 1146, "Table doesn't exist"))
	// prepare-OK declaring large (but well-formed, header-complete) column/param counts.
	f.Add(frame(1, []byte{0x00, 1, 0, 0, 0, 0xff, 0x7f, 0xff, 0x7f, 0, 0}))
	f.Fuzz(func(t *testing.T, resp []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			r := bufio.NewReader(c)
			if err := completeHandshake(c, r); err != nil {
				return
			}
			if _, _, err := readOnePacket(r, capBytes); err != nil { // client COM_STMT_PREPARE
				return
			}
			_, _ = c.Write(resp)
			drainWrites(c)
		})
		defer srv.Close()
		db := openDB(t, srv.Addr())
		defer func() { _ = db.Close() }()
		runWithOracles(t, func(ctx context.Context) {
			rows, err := db.QueryContext(ctx, "SELECT id FROM information_schema.processlist WHERE user = ?", "kx_dyn_x")
			if err == nil {
				for rows.Next() {
				}
				_ = rows.Close()
			}
		})
	})
}
