// Package pgxfuzz drives the real github.com/jackc/pgx/v5 client against a
// hostile PostgreSQL server whose entire post-startup byte stream is controlled
// by the fuzz input. The goal is to find bugs in pgx itself (parsing of the
// authentication handshake, SCRAM/MD5/cleartext auth, ParameterStatus,
// BackendKeyData, ErrorResponse/NoticeResponse and the pgproto3 frame reader),
// reachable through pgx's public API only (pgx.ParseConfig + pgx.ConnectConfig +
// Conn.Ping). No Keyorix wrapper is involved, so any finding is a library bug.
//
// Threat model: Keyorix connects pgx to operator-configured *target* databases
// (dynamic-secret engines mint/drop short-lived LOGIN roles, see
// internal/dynamic/postgres.go dialPostgres -> pgx.ConnectConfig). If such a
// target DB is malicious or compromised it fully controls every wire byte the
// client parses before (and during) a query.
//
// ---------------------------------------------------------------------------
// ORACLES (and, explicitly, what each does NOT verify)
// ---------------------------------------------------------------------------
//
//	(a) no panic / no unbounded hang / bounded memory.
//	    - panic: a parser panic fails the fuzz iteration (Go recovers it as a crash).
//	    - hang: a watchdog goroutine fails the run if a single ConnectConfig does
//	      not return within hangBudget. Does NOT detect a *slow* O(n^2) parse that
//	      still finishes under the budget, nor a hang inside Go's own netpoller.
//	    - memory: the server's declared message-body length is CAPPED at
//	      maxServerBody (8 MiB) by the decoder, so pgx can never be driven to
//	      allocate more than ~8 MiB per message from THIS harness. This protects
//	      the shared host. It therefore does NOT exercise pgx's real ceiling
//	      (~1 GiB, pgproto3.maxMessageBodyLen); the amplification itself (a 5-byte
//	      header provoking a multi-MiB up-front allocation) is demonstrated and
//	      bounded separately in TestPgx_LengthHeaderAmplification (oracle_pgx_test.go).
//
//	(b) canary: the client is configured with a secret password (canaryPassword).
//	    The oracle asserts the canary never appears in the returned error string.
//	    It does NOT scan: the *pgx.Conn value via reflection (its Config field
//	    legitimately stores the password; reflecting it is not a library leak),
//	    nor any logger output (pgx logs nothing by default and we install no
//	    tracer). It only covers error strings produced by the public API calls.
//
//	(c) echo class: text the *server* sends (e.g. an ErrorResponse Message field)
//	    that pgx surfaces inside an error is EXPECTED behaviour, not a bug. The
//	    fuzz loop therefore never fails on server-controlled text in an error; it
//	    only fails on the canary (a client-side secret the server never receives).
//	    The echo/canary distinction is pinned red/green in
//	    TestPgx_EchoAndCanary_Oracle.
//
//	(d) ignored-read-error: when the server closes mid-body the client must return
//	    an error rather than a truncated success. In the fuzz loop a truncated
//	    stream naturally yields ErrUnexpectedEOF from ConnectConfig; the explicit
//	    query-path version (server truncates a DataRow) is pinned red/green in
//	    TestPgx_TruncatedMidBody_Oracle.
package pgxfuzz

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
)

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
			declared := min(len(payload)+claimTable[(op>>2)&0x07], maxServerBody)
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
	defer func() { _ = c.Close() }()
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
	defer func() { _ = ln.Close() }()
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
