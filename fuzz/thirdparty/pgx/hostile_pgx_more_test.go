// H6 extensions to the pgx hostile-server harness: COPY-subprotocol message types in a
// query response, a NoticeResponse flood (bounded time/memory), and the TLS negotiation
// answer (SSLRequest → 'S'/'N'/'E' then a hostile ServerHello). These close the Phase-0
// gaps the base FuzzPgx* targets left open.
//
// Reachability: Keyorix's dynamic/rotation Postgres callers issue conn.Exec against an
// operator-configured target. A hostile server chooses the message TYPES it replies with
// regardless of the SQL issued, so CopyOut/CopyBoth/CopyData/CopyIn and a NoticeResponse
// flood are all reachable in the simple-query response path. TLS negotiation is reachable
// whenever the admin DSN uses sslmode=require/verify-* (the common production shape).
//
// GSSAPI negotiation is NOT built: pgx only sends a GSSEncRequest when a GSSAPICredsFunc
// is configured, and Keyorix never configures one — so that answer is unreachable through
// these callers (stated, not fuzzed). See the PR description.
package pgxhostile

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// FuzzPgxCopyResponse completes a valid handshake, then replies to conn.Exec with
// COPY-subprotocol messages: CopyInResponse('G')/CopyOutResponse('H')/CopyBothResponse
// ('W')/CopyData('d')/CopyDone('c')/CopyFail('f'). A hostile server can emit these in
// response to the plain DDL Keyorix issues; pgx must parse (or reject) them without a
// panic and within the bounded-time deadline.
func FuzzPgxCopyResponse(f *testing.F) {
	// CopyOutResponse: 'H', len, format(0=text), numcols(2 bytes), then CopyData/CopyDone.
	f.Add([]byte{'H', 0, 0, 0, 7, 0, 0, 1, 0, 0, 'd', 0, 0, 0, 6, 'h', 'i', 'c', 0, 0, 0, 4, 'Z', 0, 0, 0, 5, 'I'})
	// CopyBothResponse ('W') — only valid for replication, hostile here.
	f.Add([]byte{'W', 0, 0, 0, 7, 0, 0, 1, 0, 0, 'Z', 0, 0, 0, 5, 'I'})
	// CopyInResponse ('G') then ErrorResponse.
	f.Add([]byte{'G', 0, 0, 0, 7, 0, 0, 1, 0, 0, 'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0})
	// CopyData with an over-declared length (server-declared huge length).
	f.Add([]byte{'d', 0x7f, 0xff, 0xff, 0xff, 'x'})
	f.Fuzz(func(t *testing.T, server []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			writeAll(c, cannedHandshake)
			drainBriefly(c)
			writeAll(c, server)
			drainBriefly(c)
		})
		defer srv.Close()
		cfg := newConfig(t, srv.Addr())
		runWithOracles(t, func(ctx context.Context) {
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close(ctx) }()
			_, _ = conn.Exec(ctx, "ALTER ROLE kx_dyn WITH PASSWORD 'x'")
		})
	})
}

// buildNoticeFlood returns a handshake-completing stream that sends n NoticeResponse
// messages before CommandComplete+ReadyForQuery. A NoticeResponse is 'N' + int32 len +
// a sequence of (fieldcode byte, value CString) ending with a 0 byte.
func buildNoticeFlood(n int) []byte {
	notice := []byte{'N', 0, 0, 0, 11, 'S', 'L', 'O', 'G', 0, 0} // field 'S'=LOG then terminator
	out := make([]byte, 0, n*len(notice)+8)
	for range n {
		out = append(out, notice...)
	}
	out = append(out, 'C', 0, 0, 0, 5, 0)   // CommandComplete (empty tag)
	out = append(out, 'Z', 0, 0, 0, 5, 'I') // ReadyForQuery
	return out
}

// TestPgxNoticeFloodBounded is the bounded-time/memory oracle for a NoticeResponse flood:
// a hostile server that precedes every CommandComplete with a huge run of NoticeResponse
// messages must not wedge or blow up pgx — the Exec returns within the deadline.
func TestPgxNoticeFloodBounded(t *testing.T) {
	flood := buildNoticeFlood(200_000)
	srv := hostile.NewServer(t, func(c net.Conn) {
		if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
			return
		}
		writeAll(c, cannedHandshake)
		drainBriefly(c)
		writeAll(c, flood)
		drainBriefly(c)
	})
	defer srv.Close()
	cfg := newConfig(t, srv.Addr())

	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ORACLE panic on notice flood: %v", r)
			}
		}()
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		_, _ = conn.Exec(ctx, "ALTER ROLE kx_dyn WITH PASSWORD 'x'")
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("ORACLE bounded-time: pgx did not return within 10s under a NoticeResponse flood")
	}
}

// newTLSConfig parses a config whose admin DSN requires TLS (sslmode=require), the common
// production shape. pgx then sends an SSLRequest before startup and the hostile server
// answers the negotiation.
func newTLSConfig(tb testing.TB, addr string) *pgx.ConnConfig {
	host, port, _ := net.SplitHostPort(addr)
	cfg, err := pgx.ParseConfig("host=" + host + " port=" + port + " user=kx dbname=kx password=p sslmode=require")
	if err != nil {
		tb.Fatalf("parse tls config: %v", err)
	}
	return cfg
}

// FuzzPgxSSLNegotiation fuzzes the server's answer to pgx's SSLRequest: the single
// negotiation byte ('S' accept TLS / 'N' refuse / 'E' error) followed by hostile bytes
// (a malformed TLS ServerHello when 'S' was sent). pgx must fail the handshake without a
// panic and within the deadline — never hang on a half-open TLS negotiation.
func FuzzPgxSSLNegotiation(f *testing.F) {
	f.Add([]byte{'N'})                         // refuse TLS → pgx falls back / errors
	f.Add([]byte{'E', 'x'})                    // error byte
	f.Add([]byte{'S', 0x16, 0x03, 0x03, 0, 0}) // accept, then truncated TLS record
	f.Add([]byte{'S'})                         // accept, then nothing
	f.Add([]byte{0x00})                        // junk negotiation byte
	f.Fuzz(func(t *testing.T, server []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			// pgx sends SSLRequest first (8 bytes, no type byte). Drain it.
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			writeAll(c, server)
			drainBriefly(c)
		})
		defer srv.Close()
		cfg := newTLSConfig(t, srv.Addr())
		runWithOracles(t, func(ctx context.Context) {
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err == nil {
				_ = conn.Close(ctx)
			}
		})
	})
}
