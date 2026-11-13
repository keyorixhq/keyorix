// Hostile-SERVER fuzz harness for jackc/pgx/v5 (PostgreSQL), the driver Keyorix uses
// to mint/revoke dynamic DB credentials (internal/dynamic/postgres.go) and rotate role
// passwords (internal/rotation/postgres.go) against an OPERATOR-CONFIGURED target.
//
// Threat model: the target PostgreSQL server is attacker-controlled and replies with
// hostile wire bytes. Keyorix's real call sequence is ConnectConfig (startup+auth
// handshake) then conn.Exec (simple query, no args: CREATE/DROP/ALTER ROLE) and —
// for rotation's parameterized ALTER and any Query-with-args — the extended protocol.
//
// Oracles (sound only):
//   - No panic escapes pgx's documented error path. pgx.ConnectConfig / conn.Exec /
//     conn.Query return (conn,error)/(result,error); a panic is a defect.
//   - Bounded time: each call completes within a context deadline; a hostile reply that
//     hangs the driver past it is a defect (timeout, not deadlock).
//   - Bounded memory is approximated by Go's own alloc behaviour under -fuzz (an
//     unbounded alloc trips the fuzzing OOM/limit); not asserted numerically here.
//
// What these oracles do NOT verify: stated in the PR description, not fuzzed here.
package pgxhostile

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

const capBytes = 1 << 20 // refuse client messages longer than 1 MiB in the harness server

// drainBriefly reads and discards whatever the client has already written, until a
// short idle gap. Lets the server move on to its reply without knowing the exact client
// message framing (simple-query 'Q' vs extended P/B/D/E/S).
func drainBriefly(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
}

// writeAll writes b, tolerating a hostile-closed peer.
func writeAll(c net.Conn, b []byte) {
	_, _ = c.Write(b)
}

// cannedHandshake is the minimal valid server side of a trust-auth startup:
// AuthenticationOk then ReadyForQuery(idle). Lets ConnectConfig succeed so the
// query-phase fuzz targets reach conn.Exec / conn.Query parsing.
var cannedHandshake = []byte{
	'R', 0, 0, 0, 8, 0, 0, 0, 0, // AuthenticationOk
	'Z', 0, 0, 0, 5, 'I', // ReadyForQuery, status 'I' (idle)
}

func newConfig(tb testing.TB, addr string) *pgx.ConnConfig {
	host, port, _ := net.SplitHostPort(addr)
	cfg, err := pgx.ParseConfig("host=" + host + " port=" + port + " user=kx dbname=kx password=p sslmode=disable")
	if err != nil {
		tb.Fatalf("parse config: %v", err)
	}
	return cfg
}

// runWithOracles runs fn (a driver call sequence) under the no-panic + bounded-time
// oracles. Returns normally; fails the fuzz test on violation.
func runWithOracles(t *testing.T, fn func(ctx context.Context)) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				// A panic escaping the driver into the Keyorix caller is a defect.
				t.Errorf("ORACLE panic escaped driver error path: %v", r)
			}
		}()
		fn(ctx)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		// The 2s ctx deadline should have returned the call long before this.
		t.Errorf("ORACLE bounded-time: driver call did not return within 6s of a hostile reply")
	}
}

// FuzzPgxHandshake fuzzes the entire server→client stream from the auth phase on:
// Authentication* (cleartext/md5/SCRAM subtypes), ParameterStatus, BackendKeyData,
// NoticeResponse, ErrorResponse, ReadyForQuery, and malformed variants of each.
func FuzzPgxHandshake(f *testing.F) {
	f.Add([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I'})                      // ok
	f.Add([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})                                            // cleartext req
	f.Add([]byte{'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4})                               // md5 req
	f.Add([]byte{'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0})                             // ErrorResponse
	f.Add([]byte{'R', 0, 0, 0, 23, 0, 0, 0, 10, 'S', 'C', 'R', 'A', 'M', '-', 'X', 0, 0}) // SASL
	f.Fuzz(func(t *testing.T, server []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			writeAll(c, server)
			// Keep reading any auth response the client writes, so a SASL/md5 client
			// write does not block; then close.
			drainBriefly(c)
		})
		defer srv.Close()
		cfg := newConfig(t, srv.Addr())
		runWithOracles(t, func(ctx context.Context) {
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err == nil {
				_ = conn.Close(ctx)
			}
		})
	})
}

// FuzzPgxSimpleQueryResponse completes a valid handshake, then fuzzes the response to a
// conn.Exec (simple query protocol: RowDescription/DataRow/CommandComplete/CopyOut/
// NoticeResponse flood/ErrorResponse). This is Keyorix's actual Issue/Revoke/Rotate path.
func FuzzPgxSimpleQueryResponse(f *testing.F) {
	f.Add([]byte{'C', 0, 0, 0, 11, 'C', 'R', 'E', 'A', 'T', 'E', 0, 'Z', 0, 0, 0, 5, 'I'}) // CommandComplete+RFQ
	f.Add([]byte{'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0})                              // ErrorResponse
	f.Add([]byte{'T', 0, 0, 0, 6, 0, 1, 'D', 0, 0, 0, 10, 0, 1, 0, 0, 0, 2, 'h', 'i'})     // RowDescription+DataRow
	f.Fuzz(func(t *testing.T, server []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			writeAll(c, cannedHandshake)
			drainBriefly(c) // drain the client's Query message
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
			// Mirror internal/dynamic/postgres.go and internal/rotation/postgres.go.
			_, _ = conn.Exec(ctx, "ALTER ROLE kx_dyn WITH PASSWORD 'x'")
		})
	})
}

// FuzzPgxExtendedResponse fuzzes the extended-protocol response (Parse/Bind/Describe/
// RowDescription/DataRow/CommandComplete/ReadyForQuery) that pgx drives for a
// Query-with-args — the shape rotation's parameterized ALTER and any arg query produce.
func FuzzPgxExtendedResponse(f *testing.F) {
	f.Add([]byte{'1', 0, 0, 0, 4, '2', 0, 0, 0, 4, 'C', 0, 0, 0, 5, 0, 'Z', 0, 0, 0, 5, 'I'}) // Parse/BindComplete/CC/RFQ
	f.Add([]byte{'t', 0, 0, 0, 6, 0, 0, 'n', 0, 0, 0, 4})                                     // ParameterDescription/NoData
	f.Fuzz(func(t *testing.T, server []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
				return
			}
			writeAll(c, cannedHandshake)
			drainBriefly(c) // drain P/B/D/E/S
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
			rows, err := conn.Query(ctx, "SELECT $1::int", 1)
			if err == nil {
				for rows.Next() {
					_ = rows.RawValues()
				}
				rows.Close()
			}
		})
	})
}
