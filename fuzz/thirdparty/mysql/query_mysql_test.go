package mysqlfuzz

// FuzzMySQLHostileQuery drives github.com/go-sql-driver/mysql PAST the handshake,
// into the result-set parsers that the existing FuzzMySQLHostileServer never
// reaches. The fake server completes a fixed, valid handshake + native-password
// auth, then — in reply to the client's COM_QUERY or COM_STMT_PREPARE /
// COM_STMT_EXECUTE — streams fuzz-controlled response packets while the client
// runs one of three operations through the database/sql public API:
//
//	opTextQuery   db.QueryContext("SELECT id FROM t")            -> text protocol
//	              (readResultSetHeaderPacket, readColumns, textRows.readRow)
//	opBinaryQuery db.QueryContext("... WHERE user = ?", "x")      -> binary protocol
//	              (COM_STMT_PREPARE: readPrepareResultPacket, skipColumns;
//	               COM_STMT_EXECUTE: readResultSetHeaderPacket, readColumns,
//	               binaryRows.readRow incl. the NULL bitmap)
//	opExec        db.ExecContext("DELETE ...")                    -> text protocol exec
//
// WHY THESE PATHS / KEYORIX REACHABILITY. Keyorix's dynamic-secrets MySQL engine
// reaches the *binary prepared-statement* path on every revoke:
// internal/dynamic/mysql.go killUserConnections runs
//
//	db.QueryContext(ctx, "SELECT id FROM information_schema.processlist WHERE user = ?", user)
//
// The `?` placeholder with the driver default InterpolateParams=false makes
// database/sql fall back to COM_STMT_PREPARE + COM_STMT_EXECUTE (binary protocol)
// — the exact path this harness drives. killUserConnections is called from the
// revoke path (mysql.go:128, drop user), which runs both request-driven and from
// the auto-revoke sweeper goroutine. So a malicious / compromised / MITM'd target
// MySQL controls every byte the binary-row parser sees on a live Keyorix path.
//
// ORACLES (and, explicitly, what each does NOT verify)
//
//	(a) no panic / no hang / bounded memory. A panic in the client goroutine is
//	    captured and classified against knownQueryPanicSites (confirmed library
//	    bugs with reproducers are swallowed so the fuzzer keeps exploring; any
//	    other panic fails). A hang is bounded by an 800ms ctx AND the server
//	    force-closing every socket after a hard deadline; if even that does not
//	    unblock the client the run fails with errLibraryHang. Memory: the per-
//	    packet declared length is capped at maxServerBody (1 MiB) by the frame
//	    decoder, so this does NOT exercise the driver's real 16 MiB ceiling
//	    (characterised in TestMySQL_LengthHeaderAmplification). Does NOT catch a
//	    slow-but-finishing parse.
//	(b) canary: neither the returned error nor the fmt of any decoded row value
//	    may contain canaryPassword. Skipped when the fuzz input itself carries the
//	    canary bytes (that would be echo). Does NOT scan the driver's statement
//	    cache or conn value via reflection.
//	(c) echo: server-controlled ERR text in an error is EXPECTED echo, never a
//	    failure; pinned in TestMySQLQuery_EchoIsNotCanary.
//	(d) truncated success: a server closing mid-row/mid-packet must make the
//	    driver error, not report a truncated row as success; pinned in
//	    TestMySQLQuery_TruncatedRow_Oracle.
//
// It does NOT exercise TLS, the compression layer (see FuzzMySQLHostileCompressed),
// multi-result-set streaming, or concurrent use of one connection.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// queryOp selects the client-side operation.
type queryOp int

const (
	opTextQuery   queryOp = iota // COM_QUERY, text result rows
	opBinaryQuery                // COM_STMT_PREPARE + COM_STMT_EXECUTE, binary rows
	opExec                       // COM_QUERY exec (no rows expected)
	numQueryOps
)

// queryAllocBudget bounds TotalAlloc growth for one query iteration. The per-
// packet length cap (maxServerBody, 1 MiB) times a handful of packets plus the
// driver's own buffers stays well below this; it only fires on a NEW
// amplification the length cap does not already bound.
const queryAllocBudget = 96 << 20

// maxGroups caps the number of response groups decoded from one input, bounding
// per-iteration time (each group costs one client round-trip).
const maxGroups = 6

// buildQueryGroups decodes the fuzz input (after the op-selector byte) into a
// list of response groups. A group is the framed bytes the fake server writes in
// reply to ONE client command; the server withholds group N+1 until the client
// sends its (N+1)th command, which is what keeps go-sql-driver from tripping
// ErrBusyBuffer on unread buffered data. Encoding mirrors buildScript, but
// action 2 ends the current group instead of stopping.
func buildQueryGroups(in []byte) [][]byte {
	r := in
	var groups [][]byte
	var cur []byte
	pkts := 0
	flush := func() {
		groups = append(groups, cur)
		cur = nil
		pkts = 0
	}
	for len(r) >= 1 {
		op := r[0]
		r = r[1:]
		switch op & 0x03 {
		case 2: // group separator
			flush()
			if len(groups) >= maxGroups {
				return groups
			}
			continue
		case 1: // raw bytes
			if len(r) < 2 {
				cur = append(cur, r...)
				flush()
				return groups
			}
			plen := int(r[0])<<8 | int(r[1])
			r = r[2:]
			if plen > len(r) {
				plen = len(r)
			}
			cur = append(cur, r[:plen]...)
			r = r[plen:]
		default: // framed packet
			if len(r) < 3 {
				flush()
				return groups
			}
			seq := r[0]
			plen := int(r[1])<<8 | int(r[2])
			r = r[3:]
			if plen > len(r) {
				plen = len(r)
			}
			payload := r[:plen]
			r = r[plen:]
			declared := min(len(payload)+claimTable[(op>>2)&0x07], maxServerBody)
			cur = append(cur, mysqlFrame(seq, payload, declared)...)
		}
		pkts++
		if pkts >= maxWrites {
			flush()
			if len(groups) >= maxGroups {
				return groups
			}
		}
	}
	if cur != nil || len(groups) == 0 {
		flush()
	}
	return groups
}

// queryServer serves a fixed valid handshake+auth, then replies to each client
// command with the next response group, tracking sockets for force-close.
type queryServer struct {
	ln     net.Listener
	groups [][]byte
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func startQueryServer(ln net.Listener, groups [][]byte) *queryServer {
	s := &queryServer{ln: ln, groups: groups}
	go s.accept()
	return s
}

func (s *queryServer) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.serve(c)
	}
}

func (s *queryServer) shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := s.conns
	s.mu.Unlock()
	_ = s.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

// readCommand waits up to d for the client to send its next command packet.
func readCommand(c net.Conn, d time.Duration) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	var tmp [4096]byte
	_, _ = c.Read(tmp[:])
}

func (s *queryServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	// 1. server-first handshake (seq 0), fixed valid.
	hs := mysqlHandshake("mysql_native_password", fixedScramble)
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(mysqlFrame(0, hs, len(hs))); err != nil {
		return
	}
	// 2. read client HandshakeResponse (seq 1).
	readCommand(c, 200*time.Millisecond)
	// 3. auth OK (seq 2), fixed valid.
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(mysqlFrame(2, okPayload(), len(okPayload()))); err != nil {
		return
	}
	// 4. one response group per client command.
	for _, g := range s.groups {
		readCommand(c, 150*time.Millisecond)
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := c.Write(g); err != nil {
			return
		}
	}
	// drain whatever the client sends next (COM_STMT_CLOSE / COM_QUIT) then EOF.
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	var tmp [4096]byte
	for {
		n, err := c.Read(tmp[:])
		if n > 0 {
			_, _ = io.Discard.Write(tmp[:n])
		}
		if err != nil {
			return
		}
	}
}

// queryOutcome is everything the canary oracle scans.
type queryOutcome struct {
	err      error
	rendered strings.Builder
}

// runHostileQuery drives one op against a hostile result-set stream, guaranteeing
// a return within the hard bound via force-close. A panic in the client goroutine
// is returned as *panicErr for classification by the caller.
func runHostileQuery(t *testing.T, in []byte) (*queryOutcome, uint64) {
	t.Helper()
	op := opTextQuery
	if len(in) > 0 {
		op = queryOp(int(in[0]) % int(numQueryOps))
		in = in[1:]
	}
	groups := buildQueryGroups(in)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	s := startQueryServer(ln, groups)
	defer s.shutdown()

	cfg := newConfig(ln.Addr().String())
	connector, cerr := mysql.NewConnector(cfg)
	if cerr != nil {
		t.Fatalf("harness: NewConnector: %v", cerr)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	defer func() { _ = db.Close() }()

	out := &queryOutcome{}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	before := ms.TotalAlloc

	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				out.err = &panicErr{val: r, stack: string(debug.Stack())}
			}
			done <- struct{}{}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer cancel()
		out.err = driveQueryOp(ctx, db, op, &out.rendered)
	}()

	select {
	case <-done:
	case <-time.After(hardBound):
		s.shutdown()
		select {
		case <-done:
		case <-time.After(postCloseGrace):
			out.err = errLibraryHang
		}
	}

	runtime.ReadMemStats(&ms)
	return out, ms.TotalAlloc - before
}

func driveQueryOp(ctx context.Context, db *sql.DB, op queryOp, w *strings.Builder) error {
	switch op {
	case opTextQuery:
		rows, err := db.QueryContext(ctx, "SELECT id FROM t")
		if err != nil {
			return err
		}
		return renderSQLRows(rows, w)
	case opBinaryQuery:
		// `?` placeholder + InterpolateParams=false -> COM_STMT_PREPARE +
		// COM_STMT_EXECUTE (binary protocol). This is killUserConnections' path.
		rows, err := db.QueryContext(ctx, "SELECT id FROM information_schema.processlist WHERE user = ?", canaryUser)
		if err != nil {
			return err
		}
		return renderSQLRows(rows, w)
	case opExec:
		res, err := db.ExecContext(ctx, "DELETE FROM t WHERE 1=1")
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		fmt.Fprintf(w, "affected=%d|", n)
		return nil
	}
	return nil
}

const canaryUser = "canaryuser"

// renderSQLRows drains rows, rendering every scanned value so the canary oracle
// can inspect it, and returns rows.Err(). Each value is scanned into a
// sql.RawBytes-free interface so decoded content (not a pointer) is rendered.
func renderSQLRows(rows *sql.Rows, w *strings.Builder) error {
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		dst := make([]any, len(cols))
		holders := make([]sql.NullString, len(cols))
		for i := range dst {
			dst[i] = &holders[i]
		}
		if err := rows.Scan(dst...); err != nil {
			fmt.Fprintf(w, "scanerr:%v|", err)
			continue
		}
		for _, h := range holders {
			fmt.Fprintf(w, "%q|", h.String)
		}
	}
	return rows.Err()
}

// checkQueryCanary is oracle (b).
func checkQueryCanary(in []byte, o *queryOutcome) string {
	if strings.Contains(string(in), canaryPassword) {
		return "" // server echoed the canary bytes: echo, not a leak
	}
	if o.err != nil {
		var pe *panicErr
		if !errors.As(o.err, &pe) && strings.Contains(o.err.Error(), canaryPassword) {
			return "error: " + o.err.Error()
		}
	}
	if strings.Contains(o.rendered.String(), canaryPassword) {
		return "decoded values contain the canary"
	}
	return ""
}

// knownQueryPanicSites are CONFIRMED go-sql-driver/mysql v1.10.1 panics on the
// result-set path, each with a deterministic reproducer (repro_query_mysql_test.go)
// and a red/green allowlist test. A panic is swallowed ONLY if its stack hits one
// of these; any other panic fails the run as a novel finding. Matched by function
// (and, where a single function has several unvalidated slices, by function) so
// every manifestation line of one root cause counts as the same known bug.
var knownQueryPanicSites = []string{
	// MYSQL-Q1: readPrepareResultPacket slices a server-controlled
	// COM_STMT_PREPARE OK response with no length guard:
	// data[1:5] stmtID, data[5:7] columnCount, data[7:9] paramCount
	// (packets.go:980-986). A prepare-OK body shorter than 9 bytes panics.
	"mysql.(*mysqlStmt).readPrepareResultPacket",
	// MYSQL-Q2: binaryRows.readRow slices the NULL bitmap
	// data[1:1+(len(dest)+9)/8] with no length guard (packets.go:1299-1300),
	// and each fixed-width column read (data[pos:pos+N]) likewise. A binary row
	// packet shorter than the bitmap its declared column count requires panics.
	"mysql.(*binaryRows).readRow",
	// MYSQL-Q3: handleOkPacket reads the server_status field as
	// readStatus(data[1+n+m : 1+n+m+2]) with no length guard (packets.go:692),
	// after two length-encoded integers (affected-rows, last-insert-id). A
	// result-set header / auth-result OK packet too short for the status field
	// panics. Reached via readResultSetHeaderPacket on every query path (text
	// COM_QUERY, binary COM_STMT_EXECUTE) and on ExecContext.
	"mysql.(*okHandler).handleOkPacket",
	// MYSQL-Q4: readColumns advances pos through a column-definition packet's
	// length-encoded string fields and then slices data[pos:] for the next field
	// (packets.go:743 and siblings) with no check that pos <= len(data). Because
	// readLengthEncodedInteger returns n=1 on an EMPTY slice (utils.go:567), a
	// field landing exactly at the packet end skips one byte PAST it without an
	// error, so the next data[pos:] is out of range. A short column-definition
	// packet panics. Reached by readColumns on the text COM_QUERY result columns
	// and the binary COM_STMT_EXECUTE result columns.
	"mysql.(*mysqlConn).readColumns",
	// MYSQL-Q5: readLengthEncodedInteger (utils.go:578/582/586) reads the
	// trailing bytes of a multi-byte length prefix — 0xfc:b[1:3], 0xfd:b[1:4],
	// 0xfe:b[1:9] — with no check that the slice is long enough. A result-set
	// header packet of a single 0xfe byte (not matched by the iOK/iERR/
	// iLocalInFile fast paths in readResultSetHeaderPacket) reaches this and
	// panics "index out of range". The helper is on the hot path of every
	// length-encoded field; a panic anywhere inside it is this one root cause.
	"mysql.readLengthEncodedInteger",
	// MYSQL-Q6: textRows.readRow treats a row packet beginning with 0xFE as a
	// trailing EOF packet and reads its status as readStatus(data[3:])
	// (packets.go:829) with no length guard. A text result row of a single 0xFE
	// byte panics. Same class as MYSQL-Q2's EOF branch, but on the text path.
	"mysql.(*textRows).readRow",
	// MYSQL-Q7: handleErrorPacket reads the error number as
	// binary.LittleEndian.Uint16(data[1:3]) (packets.go:596), the SQL-state as
	// data[4:9] and the message as data[pos:], all with no length guard. A short
	// ERR packet (0xff and fewer than 3 bytes) panics. Reached from every
	// response reader (readResultSetHeaderPacket, readRow, readPrepareResultPacket,
	// the handshake) the moment the server sends a malformed ERR.
	"mysql.(*mysqlConn).handleErrorPacket",
}

func classifyQueryPanic(val any, stack string) string {
	for _, site := range knownQueryPanicSites {
		if strings.Contains(stack, site) {
			return ""
		}
	}
	return fmt.Sprintf("NEW panic (not a known mysql result-set bug site): %v\n%s", val, stack)
}

func FuzzMySQLHostileQuery(f *testing.F) {
	for _, seed := range mysqlQuerySeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		o, alloc := runHostileQuery(t, in)

		if errors.Is(o.err, errLibraryHang) {
			t.Fatalf("HANG: driver did not return even after the server force-closed all sockets")
		}
		if pe, ok := errors.AsType[*panicErr](o.err); ok {
			if msg := classifyQueryPanic(pe.val, pe.stack); msg != "" {
				t.Fatal(msg)
			}
			return // confirmed library bug with a reproducer
		}
		if leak := checkQueryCanary(in, o); leak != "" {
			t.Fatalf("CANARY LEAK: %s", leak)
		}
		if alloc > queryAllocBudget {
			t.Fatalf("AMPLIFICATION: one query iteration allocated %d bytes from a %d-byte input (budget %d)", alloc, len(in), queryAllocBudget)
		}
	})
}
