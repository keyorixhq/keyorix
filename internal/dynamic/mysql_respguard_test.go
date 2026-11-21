package dynamic

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// fakeMySQLHostile speaks just enough of the MySQL protocol for go-sql-driver/mysql to
// connect, answers pings and prepares, and answers the first query or statement
// execution with hostile (raw response payloads, sent as sequence 1, 2, ...).
// Returns host:port.
func fakeMySQLHostile(t *testing.T, hostile ...[]byte) string {
	t.Helper()
	pkt := func(seq byte, payload []byte) []byte {
		return append([]byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}, payload...)
	}
	readPkt := func(c net.Conn) ([]byte, error) {
		h := make([]byte, 4)
		if _, err := io.ReadFull(c, h); err != nil {
			return nil, err
		}
		p := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
		_, err := io.ReadFull(c, p)
		return p, err
	}
	ok := []byte{0, 0, 0, 2, 0, 0, 0}
	greeting := []byte{0x0a}
	greeting = append(greeting, "8.0.0-fake\x00"...)
	greeting = append(greeting, 1, 0, 0, 0)                                       // connection id
	greeting = append(greeting, 1, 2, 3, 4, 5, 6, 7, 8, 0)                        // auth data part 1 + filler
	greeting = append(greeting, 0x01, 0x82)                                       // caps low: LONG_PASSWORD|PROTOCOL_41|SECURE_CONNECTION
	greeting = append(greeting, 45, 2, 0)                                         // charset, status
	greeting = append(greeting, 0x08, 0x00)                                       // caps high: PLUGIN_AUTH
	greeting = append(greeting, 21)                                               // auth data length
	greeting = append(greeting, make([]byte, 10)...)                              // reserved
	greeting = append(greeting, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0) // auth data part 2
	greeting = append(greeting, "mysql_native_password\x00"...)
	paramDef := []byte{3, 'd', 'e', 'f', 0, 0, 0, 1, '?', 0, 0x0c, 0x3f, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00}
	prepareOK := []byte{0x00, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0} // stmt id 1, 0 columns, 1 param

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if _, err := c.Write(pkt(0, greeting)); err != nil {
					return
				}
				if _, err := readPkt(c); err != nil { // handshake response
					return
				}
				if _, err := c.Write(pkt(2, ok)); err != nil {
					return
				}
				for {
					p, err := readPkt(c)
					if err != nil || len(p) == 0 {
						return
					}
					switch p[0] {
					case 0x0e: // COM_PING
						_, _ = c.Write(pkt(1, ok))
					case 0x16: // COM_STMT_PREPARE
						_, _ = c.Write(append(append(pkt(1, prepareOK), pkt(2, paramDef)...), pkt(3, []byte{0xfe, 0, 0, 2, 0})...))
					case 0x03, 0x17: // COM_QUERY, COM_STMT_EXECUTE
						var reply []byte
						for i, pl := range hostile {
							reply = append(reply, pkt(byte(i+1), pl)...)
						}
						_, _ = c.Write(reply)
						_, _ = io.Copy(io.Discard, c) // hold the connection until the client closes it
						return
					case 0x01: // COM_QUIT
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

type mysqlLogSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *mysqlLogSink) Print(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(&l.buf, v...)
}

func (l *mysqlLogSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// A hostile server announcing millions of columns must be cut off on the wire, before the
// driver sizes its column slice from the announced count: as the first packet of the
// reply, after empty results whose OK says more results follow (which the driver reads
// inside Query itself, with no multi-statement setting), and for every query shape the
// revoke path can produce. Short length-encoded heads that make the driver panic are
// refused the same way.
func TestOpenMySQLRejectsHostileColumnCount(t *testing.T) {
	okMore := []byte{0, 0, 0, 0x08, 0, 0, 0} // OK, status SERVER_MORE_RESULTS_EXISTS
	cases := []struct {
		name  string
		reply [][]byte
	}{
		{"3-byte count", [][]byte{{0xfd, 0x20, 0x4e, 0x4c}}}, // 5,000,000
		{"8-byte count", [][]byte{{0xfe, 0, 0, 0, 0, 0, 0, 0, 0x40}}},
		{"more results then 3-byte count", [][]byte{okMore, {0xfd, 0x20, 0x4e, 0x4c}}},
		{"two empty results then 3-byte count", [][]byte{okMore, okMore, {0xfd, 0x20, 0x4e, 0x4c}}},
		{"0xfe alone", [][]byte{{0xfe}}},
		{"short 0xfe", [][]byte{{0xfe, 1, 0, 0, 0}}},
	}
	// The revoke path's processlist query, as COM_QUERY (interpolateParams=true) and as a
	// prepared statement (the default), and an argument-free text query.
	shapes := []struct {
		name, params, query string
		args                []any
	}{
		{"text", "", "SELECT 1", nil},
		{"interpolated", "?interpolateParams=true", "SELECT id FROM information_schema.processlist WHERE user = ?", []any{"app_user"}},
		{"prepared", "", "SELECT id FROM information_schema.processlist WHERE user = ?", []any{"app_user"}},
	}
	for _, tc := range cases {
		for _, sh := range shapes {
			t.Run(tc.name+"/"+sh.name, func(t *testing.T) {
				addr := fakeMySQLHostile(t, tc.reply...)
				cfg, err := mysql.ParseDSN("root@tcp(" + addr + ")/db" + sh.params)
				if err != nil {
					t.Fatal(err)
				}
				log := &mysqlLogSink{}
				cfg.Logger = log
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				db, err := openMySQLConfig(ctx, cfg, true)
				if err != nil {
					t.Fatalf("connect (handshake and ping must pass the guard): %v", err)
				}
				defer func() { _ = db.Close() }()

				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				start := time.Now()
				err = func() (err error) {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("driver panicked on the reply: %v", r)
						}
					}()
					rows, err := db.QueryContext(ctx, sh.query, sh.args...)
					if err == nil {
						_ = rows.Close()
					}
					return err
				}()
				elapsed := time.Since(start)
				runtime.ReadMemStats(&after)
				if err == nil {
					t.Fatal("query against a hostile server succeeded")
				}
				if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
					t.Fatalf("allocated %d MiB for a reply of a few bytes", grew>>20)
				}
				if elapsed > 10*time.Second {
					t.Fatalf("took %s; the guard should fail the query immediately", elapsed)
				}
				// The driver turns the guard's read error into ErrInvalidConn and logs the
				// original, so the reason is asserted on the driver's log.
				if !strings.Contains(log.String(), netutil.ErrMySQLLimit.Error()) {
					t.Fatalf("query failed (%v), but not because the guard refused the reply; driver log: %q", err, log.String())
				}
			})
		}
	}
}
