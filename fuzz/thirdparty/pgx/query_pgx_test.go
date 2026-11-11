package pgxfuzz

// FuzzPgxHostileQuery extends FuzzPgxHostileServer past the handshake: the fake
// server completes a fixed, valid startup (AuthenticationOk, ParameterStatus,
// BackendKeyData, ReadyForQuery) and then streams fuzz-controlled bytes while the
// client runs a full query-path operation through pgx's public API. The byte
// stream is free to contain RowDescription, DataRow, CommandComplete,
// ParseComplete/ParameterDescription/BindComplete/NoData, CopyOutResponse /
// CopyInResponse / CopyBothResponse / CopyData / CopyDone, ErrorResponse,
// NoticeResponse, ParameterStatus and NotificationResponse in any order, framed
// or raw. The first input byte selects the client operation (see queryOps); the
// rest is decoded by buildScript, exactly as in FuzzPgxHostileServer.
//
// ORACLES (and what each does NOT verify)
//
//	(a) no panic / no hang / bounded memory. A panic anywhere in the client
//	    goroutine crashes the iteration. The watchdog (hangBudget) catches a
//	    parser that ignores context cancellation. Memory: TotalAlloc growth over
//	    one iteration must stay below allocBudget; the declared-body cap
//	    (maxServerBody, 8 MiB) is already a characterised, bounded
//	    amplification (h2 Finding 3), so allocBudget is set well above it and
//	    only fires on a NEW amplification (e.g. a decoder sizing a slice from a
//	    server-declared count). Does NOT catch a slow-but-finishing parse, nor
//	    an allocation that is freed and re-made below the budget each time;
//	    TotalAlloc includes runtime/background allocation so the budget is
//	    deliberately loose.
//	(b) canary: neither the returned error, nor fmt("%#v") of any decoded row
//	    value, nor any NoticeResponse/Notification delivered to the handlers,
//	    may contain canaryPassword. The server never receives the password in
//	    this harness (AuthenticationOk is unconditional), so the canary can only
//	    surface if the client copies its own memory into a result. Skipped when
//	    the fuzz input itself contains the canary bytes (that would be echo).
//	    Does NOT scan the *pgx.Conn via reflection, nor pgx's statement cache.
//	(c) echo: server text appearing in an error is expected and never fails the
//	    loop; TestPgxQuery_EchoIsNotCanary pins the distinction on this path.
//	(d) truncated success: TestPgxQuery_TruncatedDataRow_Oracle pins that a
//	    server closing mid-DataRow yields an error from rows.Err(), not rows.
//
// It does NOT exercise TLS, pgxpool, the database/sql stdlib adapter, or
// concurrent use of one connection.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// allocBudget bounds TotalAlloc growth for one query iteration. h2 Finding 3
// already characterises up to maxServerBody (8 MiB) per declared message; a few
// such messages plus pgx's own buffers stay well below 96 MiB.
const allocBudget = 96 << 20

// queryOp is one client-side operation driven against the hostile stream.
type queryOp int

const (
	opSimpleQuery    queryOp = iota // Query, QueryExecModeSimpleProtocol, rows.Values
	opExecModeQuery                 // Query, QueryExecModeExec (Parse/Bind/Describe portal)
	opCachedPrepared                // Query with args, QueryExecModeCacheStatement (ParameterDescription drives arg encoding)
	opSimpleExec                    // Exec, simple protocol
	opCopyTo                        // PgConn.CopyTo
	opCopyFrom                      // PgConn.CopyFrom
	opMultiResult                   // PgConn.Exec multi-statement ReadAll
	opTypedScan                     // Query simple + scan every raw value into many typed destinations
	numQueryOps
)

// handshakeOK is the fixed, valid startup every query iteration begins with.
func handshakeOK() [][]byte {
	return [][]byte{
		frame('R', authPayload(0), 4),
		frame('S', paramStatus("server_version", "16.0"), len(paramStatus("server_version", "16.0"))),
		frame('S', paramStatus("client_encoding", "UTF8"), len(paramStatus("client_encoding", "UTF8"))),
		frame('S', paramStatus("standard_conforming_strings", "on"), len(paramStatus("standard_conforming_strings", "on"))),
		frame('K', backendKeyData(), 8),
		frame('Z', readyForQuery(), 1),
	}
}

// queryOutcome is everything the client produced that the canary oracle scans.
type queryOutcome struct {
	connectErr error
	opErr      error
	rendered   strings.Builder // fmt of decoded values, notices, notifications
}

func runHostileQuery(t *testing.T, in []byte) (*queryOutcome, uint64) {
	t.Helper()
	op := opSimpleQuery
	if len(in) > 0 {
		op = queryOp(int(in[0]) % int(numQueryOps))
		in = in[1:]
	}
	writes := append(handshakeOK(), buildScript(in)...)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer ln.Close()
	go serveQuery(ln, writes)

	out := &queryOutcome{}
	port := ln.Addr().(*net.TCPAddr).Port
	dsn := fmt.Sprintf("postgres://canaryuser:%s@127.0.0.1:%d/postgres?sslmode=disable", canaryPassword, port)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("harness: ParseConfig failed: %v", err)
	}
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { fmt.Fprintf(&out.rendered, "%#v|", *n) }
	cfg.OnNotification = func(_ *pgconn.PgConn, n *pgconn.Notification) { fmt.Fprintf(&out.rendered, "%#v|", *n) }

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(hangBudget):
			panic("pgx query path did not return within hang budget (possible infinite loop)")
		}
	}()
	defer close(done)

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	before := ms.TotalAlloc

	conn, cerr := pgx.ConnectConfig(ctx, cfg)
	if cerr != nil {
		out.connectErr = cerr
		runtime.ReadMemStats(&ms)
		return out, ms.TotalAlloc - before
	}
	out.opErr = driveOp(ctx, conn, op, &out.rendered)
	_ = conn.Close(ctx)

	runtime.ReadMemStats(&ms)
	return out, ms.TotalAlloc - before
}

// serveQuery is serveOnce for the query path. serveOnce closes as soon as its
// writes are out, which on the query path races the client's own query write
// (the client then fails with "broken pipe" before it parses a single
// post-handshake byte, so the decoders are never reached). serveQuery instead
// reads the startup message, writes the whole script, then keeps the socket
// open until the client has sent its query (or queryWait passes) and a short
// linger after that, so the client's read sees the scripted bytes and then EOF.
func serveQuery(ln net.Listener, writes [][]byte) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(queryWait + time.Second))
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(hdr[:])) - 4
	if n < 0 || n > 1<<16 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
		return
	}
	got := make(chan struct{}, 1)
	go func() {
		var buf [4096]byte
		for {
			k, err := c.Read(buf[:])
			if k > 0 {
				select {
				case got <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for _, w := range writes {
		if _, err := c.Write(w); err != nil {
			return
		}
	}
	select {
	case <-got:
		time.Sleep(queryLinger)
	case <-time.After(queryWait):
	}
}

// queryWait bounds how long serveQuery waits for the client's query; queryLinger
// is how long it stays open after it (covers CopyFrom data and a Terminate).
const (
	queryWait   = 300 * time.Millisecond
	queryLinger = 5 * time.Millisecond
)

// renderRows drains rows, rendering every decoded value so the canary oracle
// can scan it, and returns rows.Err().
func renderRows(rows pgx.Rows, w io.Writer) error {
	defer rows.Close()
	for rows.Next() {
		fmt.Fprintf(w, "%#v|", rows.FieldDescriptions())
		vals, err := rows.Values()
		if err != nil {
			fmt.Fprintf(w, "valerr:%v|", err)
			continue
		}
		fmt.Fprintf(w, "%#v|", vals)
	}
	fmt.Fprintf(w, "%s|", rows.CommandTag().String())
	return rows.Err()
}

// typedScanAll scans each raw column into a spread of destination types via the
// connection's type map, exercising scan plans the server's OIDs/format codes
// select. Errors are expected (type mismatch) and only rendered.
func typedScanAll(m *pgtype.Map, fds []pgconn.FieldDescription, raw [][]byte, w io.Writer) {
	for i, fd := range fds {
		if i >= len(raw) {
			return
		}
		dsts := []any{
			new(string), new(int64), new(float64), new(bool), new(time.Time),
			new([]byte), new(map[string]any), new(netip.Prefix), new(pgtype.Numeric),
			new([]string), new([][]int32), new(pgtype.Interval), new(pgtype.Range[pgtype.Int8]),
			new(any),
		}
		for _, d := range dsts {
			err := m.Scan(fd.DataTypeOID, fd.Format, raw[i], d)
			// Render the pointee, not the pointer: the canary oracle must see
			// the decoded content.
			fmt.Fprintf(w, "%v %#v|", err, reflect.ValueOf(d).Elem().Interface())
		}
	}
}

func driveOp(ctx context.Context, conn *pgx.Conn, op queryOp, w io.Writer) error {
	switch op {
	case opSimpleQuery:
		rows, err := conn.Query(ctx, "select * from t", pgx.QueryExecModeSimpleProtocol)
		if err != nil {
			return err
		}
		return renderRows(rows, w)
	case opExecModeQuery:
		rows, err := conn.Query(ctx, "select * from t", pgx.QueryExecModeExec)
		if err != nil {
			return err
		}
		return renderRows(rows, w)
	case opCachedPrepared:
		rows, err := conn.Query(ctx, "select * from t where a=$1 and b=$2 and c=$3", "v", int64(7), []byte{1, 2})
		if err != nil {
			return err
		}
		return renderRows(rows, w)
	case opSimpleExec:
		tag, err := conn.Exec(ctx, "create role x", pgx.QueryExecModeSimpleProtocol)
		fmt.Fprintf(w, "%s|", tag.String())
		return err
	case opCopyTo:
		var buf bytes.Buffer
		tag, err := conn.PgConn().CopyTo(ctx, &buf, "copy t to stdout")
		fmt.Fprintf(w, "%s|%q|", tag.String(), buf.Bytes())
		return err
	case opCopyFrom:
		tag, err := conn.PgConn().CopyFrom(ctx, strings.NewReader("1\tabc\n2\tdef\n"), "copy t from stdin")
		fmt.Fprintf(w, "%s|", tag.String())
		return err
	case opMultiResult:
		results, err := conn.PgConn().Exec(ctx, "select 1; select 2; select 3").ReadAll()
		for _, r := range results {
			fmt.Fprintf(w, "%#v|%q|%s|%v|", r.FieldDescriptions, r.Rows, r.CommandTag.String(), r.Err)
		}
		return err
	case opTypedScan:
		rows, err := conn.Query(ctx, "select * from t", pgx.QueryExecModeSimpleProtocol)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			typedScanAll(conn.TypeMap(), rows.FieldDescriptions(), rows.RawValues(), w)
		}
		return rows.Err()
	}
	return nil
}

// checkQueryCanary is oracle (b). It returns a description of the first leak,
// or "" if none. Kept separate so TestPgxQuery_CanaryOracle_RedGreen can prove
// it fires on a planted leak.
func checkQueryCanary(in []byte, o *queryOutcome) string {
	if bytes.Contains(in, []byte(canaryPassword)) {
		return "" // the server itself sent the canary: echo, not a leak
	}
	for _, e := range []error{o.connectErr, o.opErr} {
		if e != nil && strings.Contains(e.Error(), canaryPassword) {
			return "error: " + e.Error()
		}
	}
	if strings.Contains(o.rendered.String(), canaryPassword) {
		return "decoded values/notices contain the canary"
	}
	return ""
}

func FuzzPgxHostileQuery(f *testing.F) {
	for _, seed := range pgxQuerySeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		o, alloc := runHostileQuery(t, in)
		if leak := checkQueryCanary(in, o); leak != "" {
			t.Fatalf("CANARY LEAK: %s", leak)
		}
		if alloc > allocBudget {
			t.Fatalf("AMPLIFICATION: one query iteration allocated %d bytes from a %d-byte input (budget %d)", alloc, len(in), allocBudget)
		}
	})
}
