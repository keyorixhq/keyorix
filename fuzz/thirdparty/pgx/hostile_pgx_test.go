// Hostile-SERVER fuzz harnesses for jackc/pgx/v5 (PostgreSQL).
//
// Two harness families coexist in this file:
//
// h6 (FuzzPgxHandshake / FuzzPgxSimpleQueryResponse / FuzzPgxExtendedResponse):
//
//	Attack the full call sequence Keyorix uses against an operator-configured
//	target (ConnectConfig + conn.Exec + conn.Query), metered by the resguard
//	resource layer. Uses the hostile-server infrastructure package.
//
// h2 (FuzzPgxHostileServer):
//
//	Canary-focused harness: drives ConnectConfig against a fully fuzz-controlled
//	server whose every post-startup byte comes from the fuzz input. Oracles:
//	(a) no panic / no hang (watchdog), (b) canary password never in error,
//	(c) echo class expected, (d) ignored-read-error.
//	Each oracle pinned red/green in oracle_pgx_test.go.
package pgxhostile

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/pgxlimits"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// ---- h6: infrastructure (hostile-package-based) ------------------------------------

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
	// Fuzz the configuration that ships: the same per-message bound the production dial path sets.
	pgxlimits.Apply(cfg)
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

// drivePgxHandshake runs one FuzzPgxHandshake input under the no-panic/bounded-time
// oracles. Extracted so the resguard Probe (resguard_pgx_test.go) can measure it and
// the calibration/red-green tests can replay the same path.
func drivePgxHandshake(t *testing.T, server []byte) {
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
	probe, budget, haveBudget := pgxResguardProbe(f, pgxBudgetHandshake)
	f.Fuzz(func(t *testing.T, server []byte) {
		measurePgx(t, probe, budget, haveBudget, server, drivePgxHandshake)
	})
}

// drivePgxSimpleQuery runs one FuzzPgxSimpleQueryResponse input under the oracles.
func drivePgxSimpleQuery(t *testing.T, server []byte) {
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
}

// FuzzPgxSimpleQueryResponse completes a valid handshake, then fuzzes the response to a
// conn.Exec (simple query protocol: RowDescription/DataRow/CommandComplete/CopyOut/
// NoticeResponse flood/ErrorResponse). This is Keyorix's actual Issue/Revoke/Rotate path.
func FuzzPgxSimpleQueryResponse(f *testing.F) {
	f.Add([]byte{'C', 0, 0, 0, 11, 'C', 'R', 'E', 'A', 'T', 'E', 0, 'Z', 0, 0, 0, 5, 'I'}) // CommandComplete+RFQ
	f.Add([]byte{'E', 0, 0, 0, 11, 'S', 'E', 'R', 'R', 0, 0})                              // ErrorResponse
	f.Add([]byte{'T', 0, 0, 0, 6, 0, 1, 'D', 0, 0, 0, 10, 0, 1, 0, 0, 0, 2, 'h', 'i'})     // RowDescription+DataRow
	probe, budget, haveBudget := pgxResguardProbe(f, pgxBudgetSimpleQuery)
	f.Fuzz(func(t *testing.T, server []byte) {
		measurePgx(t, probe, budget, haveBudget, server, drivePgxSimpleQuery)
	})
}

// FuzzPgxExtendedResponse fuzzes the extended-protocol response (Parse/Bind/Describe/
// RowDescription/DataRow/CommandComplete/ReadyForQuery) that pgx drives for a
// Query-with-args — the shape rotation's parameterized ALTER and any arg query produce.
// drivePgxExtended runs one FuzzPgxExtendedResponse input under the oracles.
func drivePgxExtended(t *testing.T, server []byte) {
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
}

func FuzzPgxExtendedResponse(f *testing.F) {
	f.Add([]byte{'1', 0, 0, 0, 4, '2', 0, 0, 0, 4, 'C', 0, 0, 0, 5, 0, 'Z', 0, 0, 0, 5, 'I'}) // Parse/BindComplete/CC/RFQ
	f.Add([]byte{'t', 0, 0, 0, 6, 0, 0, 'n', 0, 0, 0, 4})                                     // ParameterDescription/NoData
	probe, budget, haveBudget := pgxResguardProbe(f, pgxBudgetExtended)
	f.Fuzz(func(t *testing.T, server []byte) {
		measurePgx(t, probe, budget, haveBudget, server, drivePgxExtended)
	})
}

// ---- h2: canary-focused hostile-server harness (buildScript encoding) ---------------

// canaryPassword is the client-side secret. The hostile server never learns it
// (pgx only sends it after an auth request, and even then the server discards
// everything the client writes), so it must never surface in any pgx error.
const canaryPassword = "s3cr3t-canary-pw-9f3a2b1c"

// maxServerBody caps the message-body length the fake server may *declare*. It
// exists purely to protect this shared host: pgx allocates the declared body
// length up front (pgproto3 chunkreader.Next -> iobufpool.Get(n)), so an
// uncapped fuzzer could drive ~1 GiB allocations per iteration. 8 MiB is large
// enough to make the amplification visible yet safe to allocate repeatedly.
const maxServerBody = 8 << 20

// hangBudget bounds a single ConnectConfig+Ping. ConnectConfig itself is given a
// 2s context; the watchdog at hangBudget only fires on a parser that ignores
// context cancellation entirely (a true infinite loop).
const hangBudget = 6 * time.Second

// claimTable maps a 3-bit selector to the number of body bytes the server
// DECLARES beyond what it actually sends. Non-zero entries force pgx to expect
// more bytes than arrive (truncation / up-front allocation). All capped by
// maxServerBody downstream.
var claimTable = [8]int{0, 0, 1, 16, 4096, 1 << 16, 1 << 20, 4 << 20}

// frame renders one backend message: type byte, big-endian int32 length
// (declaredBody+4, i.e. INCLUDING the 4 length bytes), then the payload actually
// transmitted. declaredBody may exceed len(payload) to simulate a short/hostile
// server.
func frame(typ byte, payload []byte, declaredBody int) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:5], uint32(declaredBody+4))
	copy(out[5:], payload)
	return out
}

// buildScript decodes the fuzz input into a list of byte blobs the server writes
// to the client, in order, then closes the connection. The encoding:
//
//	op byte: bits 0-1 = action, bits 2-4 = claim selector (for action 0/3)
//	 action 0 or 3: framed message -> [typ:1][plen:2 BE][payload:plen]
//	 action 1:      raw bytes      -> [plen:2 BE][bytes:plen]  (unframed garbage)
//	 action 2:      stop (close)
func buildScript(in []byte) [][]byte {
	r := in
	var out [][]byte
	for len(r) >= 1 {
		op := r[0]
		r = r[1:]
		switch op & 0x03 {
		case 2:
			return out
		case 1:
			if len(r) < 2 {
				return out
			}
			plen := int(binary.BigEndian.Uint16(r[:2]))
			r = r[2:]
			if plen > len(r) {
				plen = len(r)
			}
			out = append(out, append([]byte(nil), r[:plen]...))
			r = r[plen:]
		default: // 0 or 3: framed message
			if len(r) < 3 {
				return out
			}
			typ := r[0]
			plen := int(binary.BigEndian.Uint16(r[1:3]))
			r = r[3:]
			if plen > len(r) {
				plen = len(r)
			}
			payload := r[:plen]
			r = r[plen:]
			declared := len(payload) + claimTable[(op>>2)&0x07]
			if declared > maxServerBody {
				declared = maxServerBody
			}
			out = append(out, frame(typ, payload, declared))
		}
	}
	return out
}

// serveOnce accepts exactly one connection, drains everything the client sends
// (so the client's writes never block on a full socket buffer), writes every
// scripted blob, then closes. Any accept/write error is ignored: the client
// seeing a closed connection is a legitimate hostile-server outcome.
func serveOnce(ln net.Listener, writes [][]byte) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	go io.Copy(io.Discard, c) //nolint:errcheck // draining; errors are expected on close
	for _, w := range writes {
		if _, err := c.Write(w); err != nil {
			return
		}
	}
}

// runHostile is the shared driver used by both the fuzz target and the explicit
// oracle tests. It decodes the script into server writes, drives pgx against the
// resulting hostile server, and returns the error pgx produced (nil on a
// successful connect).
func runHostile(t *testing.T, script []byte) (connectErr error) {
	t.Helper()
	writes := buildScript(script)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer ln.Close()
	go serveOnce(ln, writes)

	port := ln.Addr().(*net.TCPAddr).Port
	dsn := fmt.Sprintf("postgres://canaryuser:%s@127.0.0.1:%d/postgres?sslmode=disable", canaryPassword, port)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		// A fixed, well-formed DSN must always parse; a failure here is a harness bug.
		t.Fatalf("harness: ParseConfig failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(hangBudget):
			panic("pgx ConnectConfig did not return within hang budget (possible infinite loop)")
		}
	}()
	conn, cerr := pgx.ConnectConfig(ctx, cfg)
	if cerr == nil && conn != nil {
		_ = conn.Ping(ctx)
		_ = conn.Close(ctx)
	}
	close(done)
	return cerr
}

func FuzzPgxHostileServer(f *testing.F) {
	for _, seed := range pgxSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, script []byte) {
		cerr := runHostile(t, script)

		// Oracle (b): the canary password must never appear in a pgx error.
		if cerr != nil && strings.Contains(cerr.Error(), canaryPassword) {
			t.Fatalf("CANARY LEAK: client password appeared in pgx error: %q", cerr.Error())
		}
		// Oracles (a) panic/hang are enforced by Go's crash recovery and the
		// watchdog panic above. Oracle (c): server text inside an error is
		// expected echo and is deliberately not treated as a failure here.
	})
}
