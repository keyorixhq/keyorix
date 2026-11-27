package netutil

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- seeded, reproducible test-input generator, not a secret
	"net"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// myServe is a scripted MySQL server on one end of a net.Pipe: it completes the
// handshake (as MariaDB with cache metadata when maria is set), answers pings and
// prepares, and answers the first query or statement execution with reply (payloads
// sent as sequence 1, 2, ...), then hangs up.
func myServe(c net.Conn, maria bool, reply [][]byte) {
	defer func() { _ = c.Close() }()
	readPkt := func() ([]byte, error) {
		h := make([]byte, 4)
		if _, err := io.ReadFull(c, h); err != nil {
			return nil, err
		}
		p := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
		_, err := io.ReadFull(c, p)
		return p, err
	}
	capsLow, ext := byte(0x01), uint32(0) // LONG_PASSWORD (CLIENT_MYSQL): a MySQL server
	if maria {
		capsLow, ext = 0x00, 0x10 // MariaDB, MARIADB_CLIENT_CACHE_METADATA
	}
	g := []byte{0x0a}
	g = append(g, "8.0.0-fake\x00"...)
	g = append(g, 1, 0, 0, 0)                // connection id
	g = append(g, 1, 2, 3, 4, 5, 6, 7, 8, 0) // auth data part 1 + filler
	g = append(g, capsLow, 0x82)             // caps low: PROTOCOL_41|SECURE_CONNECTION
	g = append(g, 45, 2, 0)                  // charset, status
	g = append(g, 0x08, 0x00)                // caps high: PLUGIN_AUTH
	g = append(g, 21, 0, 0, 0, 0, 0, 0)      // auth data length, reserved
	g = binary.LittleEndian.AppendUint32(g, ext)
	g = append(g, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0) // auth data part 2
	g = append(g, "mysql_native_password\x00"...)
	ok := []byte{0, 0, 0, 2, 0, 0, 0}
	if _, err := c.Write(myPkt(0, g)); err != nil {
		return
	}
	if _, err := readPkt(); err != nil {
		return
	}
	if _, err := c.Write(myPkt(2, ok)); err != nil {
		return
	}
	for {
		p, err := readPkt()
		if err != nil || len(p) == 0 {
			return
		}
		switch p[0] {
		case 0x0e: // COM_PING
			_, _ = c.Write(myPkt(1, ok))
		case 0x16: // COM_STMT_PREPARE: statement 1, no columns, one parameter
			param := []byte{3, 'd', 'e', 'f', 0, 0, 0, 1, '?', 0, 0x0c, 0x3f, 0, 0x0a, 0, 0, 0, 0xfd, 0, 0, 0}
			b := myPkt(1, []byte{0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
			b = append(b, myPkt(2, param)...)
			_, _ = c.Write(append(b, myPkt(3, []byte{0xfe, 0, 0, 2, 0})...))
		case 0x03, 0x17: // COM_QUERY, COM_STMT_EXECUTE
			go func() { _, _ = io.Copy(io.Discard, c) }()
			var b []byte
			for i, pl := range reply {
				b = append(b, myPkt(byte(i+1), pl)...)
			}
			_, _ = c.Write(b) // returns once the client read it all, or closed the pipe
			return
		case 0x01: // COM_QUIT
			return
		}
	}
}

type myLogSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *myLogSink) Print(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(&l.buf, v...)
}

func (l *myLogSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Query shapes that reach readResultSetHeaderPacket: a text query, a text query with
// client-side interpolation, and the default prepared statement (COM_STMT_EXECUTE).
var myQueryShapes = []string{"text", "interpolate", "prepared"}

type myDriverRun struct {
	panicked any
	allocMiB uint64
	rejected bool // the guard's reason reached the driver's logger
	err      error
}

// myRunDriver connects the pinned go-sql-driver/mysql to a scripted server, through
// MySQLGuardDialer when guarded, and runs one query of the given shape.
func myRunDriver(t *testing.T, guarded, maria bool, shape string, reply [][]byte) (r myDriverRun) {
	t.Helper()
	dial := func(context.Context, string, string) (net.Conn, error) {
		cli, srv := net.Pipe()
		go myServe(srv, maria, reply)
		return cli, nil
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Net, cfg.Addr = "root", "tcp", "fake:3306"
	cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 5*time.Second
	cfg.InterpolateParams = shape == "interpolate"
	log := &myLogSink{}
	cfg.Logger = log
	cfg.DialFunc = dial
	if guarded {
		cfg.DialFunc = MySQLGuardDialer(dial, MySQLLimits{})
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := connector.Connect(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	func() {
		defer func() { r.panicked = recover() }()
		var rows driver.Rows
		args := []driver.NamedValue{{Ordinal: 1, Value: int64(1)}}
		switch shape {
		case "text":
			rows, r.err = conn.(driver.QueryerContext).QueryContext(ctx, "SELECT 1", nil)
		case "interpolate":
			rows, r.err = conn.(driver.QueryerContext).QueryContext(ctx, "SELECT ?", args)
		default:
			var st driver.Stmt
			if st, r.err = conn.(driver.ConnPrepareContext).PrepareContext(ctx, "SELECT ?"); r.err != nil {
				return
			}
			defer func() { _ = st.Close() }()
			rows, r.err = st.(driver.StmtQueryContext).QueryContext(ctx, args)
		}
		if r.err == nil {
			_ = rows.Close()
		}
	}()
	runtime.ReadMemStats(&after)
	r.allocMiB = (after.TotalAlloc - before.TotalAlloc) >> 20
	r.rejected = strings.Contains(log.String(), ErrMySQLLimit.Error())
	return r
}

func (r myDriverRun) harmful() bool { return r.panicked != nil || r.allocMiB > 64 }

// myDriverHasTruncatedErrorFix reports whether the go-sql-driver/mysql linked into this
// test binary is >= v1.10.2 (upstream #1858). ok is false when the version cannot be
// read or parsed (no build info, a pseudo-version or a replace), so callers skip rather
// than guess.
func myDriverHasTruncatedErrorFix() (fixed, ok bool) {
	bi, found := debug.ReadBuildInfo()
	if !found {
		return false, false
	}
	for _, d := range bi.Deps {
		if d.Path != "github.com/go-sql-driver/mysql" {
			continue
		}
		if d.Replace != nil {
			return false, false
		}
		// Only a plain release "vX.Y.Z" counts: a pre-release or pseudo-version has a
		// "-" suffix and its position relative to v1.10.2 is not knowable from the string.
		parts := strings.Split(strings.TrimPrefix(d.Version, "v"), ".")
		if len(parts) != 3 {
			return false, false
		}
		var v [3]int
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return false, false
			}
			v[i] = n
		}
		return v[0] > 1 || (v[0] == 1 && (v[1] > 10 || (v[1] == 10 && v[2] >= 2))), true
	}
	return false, false
}

func myOKPkt(status uint16) []byte { return []byte{0, 0, 0, byte(status), byte(status >> 8), 0, 0} }

// TestMySQLDriverVersionReadable keeps the truncated-error calibration below from
// skipping silently: the version must be readable from the test binary's build info,
// and must agree with go.mod's pin (a plain release, no replace).
func TestMySQLDriverVersionReadable(t *testing.T) {
	fixed, ok := myDriverHasTruncatedErrorFix()
	if !ok {
		t.Fatal("go-sql-driver/mysql release version not readable from build info (replace directive or pseudo-version?): the truncated-error calibration would be skipped")
	}
	bi, _ := debug.ReadBuildInfo()
	for _, d := range bi.Deps {
		if d.Path == "github.com/go-sql-driver/mysql" {
			t.Logf("go-sql-driver/mysql %s: truncated-error fix (#1858) present=%v", d.Version, fixed)
		}
	}
}

// TestMySQLGuardAgreesWithDriver checks the guard against the pinned driver itself,
// not against a model of it: every reply the guard lets through must leave the real
// driver without a panic and without a large allocation. The named harmful replies are
// first run unguarded and must misbehave there, so the harness is seen to detect the
// failure it guards against.
func TestMySQLGuardAgreesWithDriver(t *testing.T) {
	cnt5M := []byte{0xfd, 0x20, 0x4e, 0x4c} // 5,000,000 columns
	// Above makeslice's limit, so the unguarded driver panics instead of trying to
	// allocate it (a count like 1<<40 makes it reserve tens of terabytes).
	cnt2e62 := myLenEnc(1 << 62)
	// textOnly: the binary protocol does not follow SERVER_MORE_RESULTS_EXISTS after a
	// first-packet OK (binaryRows has no connection then, so NextResultSet returns
	// io.EOF), so those replies harm only the text shapes; the guard refuses them on
	// every shape, since it does not know which protocol the driver will use.
	harmful := []struct {
		name     string
		maria    bool
		textOnly bool
		reply    [][]byte
	}{
		{"3-byte count", false, false, [][]byte{cnt5M}},
		{"8-byte count", false, false, [][]byte{cnt2e62}},
		{"more results then 3-byte count", false, true, [][]byte{myOKPkt(0x0008), cnt5M}},
		{"two empty results then 8-byte count", false, true, [][]byte{myOKPkt(0x000a), myOKPkt(0x0008), cnt2e62}},
		{"0xfe alone", false, false, [][]byte{{0xfe}}},
		{"short 0xfe", false, false, [][]byte{{0xfe, 1, 0, 0, 0}}},
		{"more results then short 0xfe", false, true, [][]byte{myOKPkt(0x0008), {0xfe, 1, 0, 0, 0}}},
		{"mariadb count without metadata flag", true, false, [][]byte{{0x01}}},
	}
	for _, tc := range harmful {
		for _, shape := range myQueryShapes {
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				r := myRunDriver(t, false, tc.maria, shape, tc.reply)
				if want := !tc.textOnly || shape != "prepared"; r.harmful() != want {
					t.Fatalf("calibration: unguarded driver harmful=%v (panic %v, %d MiB, err %v), want %v", r.harmful(), r.panicked, r.allocMiB, r.err, want)
				}
				r = myRunDriver(t, true, tc.maria, shape, tc.reply)
				if r.harmful() {
					t.Fatalf("through the guard: panic %v, allocated %d MiB", r.panicked, r.allocMiB)
				}
				if !r.rejected {
					t.Fatalf("the guard did not refuse the reply (err %v)", r.err)
				}
			})
		}
	}

	// A truncated error ({0xff, 0x15}) is harmful to an unguarded driver before
	// go-sql-driver/mysql v1.10.2 (upstream #1858: the driver now returns ErrMalformPkt
	// for it). The guard refuses it on every driver version (defence in depth), so this
	// test must agree with both 1.10.1 and 1.10.2: the guarded run is always asserted,
	// and the unguarded calibration follows the driver version the test binary was built
	// with. If the version cannot be read the calibration is skipped, not guessed.
	// The count cases above stay harmful: upstream #1866 (readColumns sized from the
	// announced count) is still open.
	for _, shape := range myQueryShapes {
		t.Run("truncated error/"+shape, func(t *testing.T) {
			reply := [][]byte{{0xff, 0x15}}
			if fixed, ok := myDriverHasTruncatedErrorFix(); ok {
				r := myRunDriver(t, false, false, shape, reply)
				if r.harmful() == fixed {
					t.Fatalf("calibration: unguarded driver harmful=%v (panic %v, %d MiB, err %v), want %v for go-sql-driver/mysql fixed-in-1.10.2=%v", r.harmful(), r.panicked, r.allocMiB, r.err, !fixed, fixed)
				}
			} else {
				t.Log("go-sql-driver/mysql version not readable from build info: unguarded calibration skipped")
			}
			r := myRunDriver(t, true, false, shape, reply)
			if r.harmful() {
				t.Fatalf("through the guard: panic %v, allocated %d MiB", r.panicked, r.allocMiB)
			}
			if !r.rejected {
				t.Fatalf("the guard did not refuse the reply (err %v)", r.err)
			}
		})
	}

	// Random response heads: OK chains with random status and length encodings, cut at
	// random lengths, followed by a column count, an ERR, a LOCAL INFILE request or noise.
	rng := rand.New(rand.NewSource(11))
	heads := []byte{0, 1, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
	counts := []uint64{1, 250, 251, 65535, 65536, 65537, 1 << 24, 1 << 40}
	pass := 0
	for i := range 150 {
		var reply [][]byte
		for range rng.Intn(3) {
			ok := []byte{0, heads[rng.Intn(len(heads))], 1, 2, 3, 4, 5, 6, 7, 8, heads[rng.Intn(len(heads))], 1, 2, 3, 4, 5, 6, 7, 8}
			ok = append(ok, byte(rng.Intn(16)), 0, 0, 0)
			reply = append(reply, ok[:1+rng.Intn(len(ok))])
		}
		switch rng.Intn(4) {
		case 0:
			c := myLenEnc(counts[rng.Intn(len(counts))])
			reply = append(reply, c[:1+rng.Intn(len(c))])
		case 1:
			e := []byte{0xff, 0x15, 0x04, '#', '4', '2', '0', '0', '0', 'x'}
			reply = append(reply, e[:1+rng.Intn(len(e))])
		case 2:
			reply = append(reply, []byte{0xfb, 'f'})
		default:
			pl := make([]byte, 1+rng.Intn(10))
			rng.Read(pl)
			reply = append(reply, pl)
		}
		maria := rng.Intn(3) == 0
		shape := myQueryShapes[rng.Intn(len(myQueryShapes))]
		r := myRunDriver(t, true, maria, shape, reply)
		if r.harmful() {
			t.Fatalf("case %d (%s, maria=%v, reply %x): through the guard the driver panicked (%v) or allocated %d MiB", i, shape, maria, reply, r.panicked, r.allocMiB)
		}
		if !r.rejected {
			pass++
		}
	}
	if pass == 0 {
		t.Fatal("the guard refused every random reply: the property was never exercised on an accepted one")
	}
}
