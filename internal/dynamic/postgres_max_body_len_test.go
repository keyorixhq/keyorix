package dynamic

// postgres_max_body_len_test.go — the admin_dsn host is project-admin input, so
// the PostgreSQL server it names is not trusted. pgx sizes its read buffer from
// the length a server CLAIMS in a message header, before any body byte arrives;
// its own default ceiling is ~1 GiB. A 5-byte header from a rogue server was
// measured to cost the keyorix process ~775 MB per connection (~1.5 GB peak RSS
// over repeated dials, and an OOM kill inside a 512 MiB cgroup within three
// dials). pgxlimits.MaxProtocolMessageBodyLen bounds that.
//
// These tests assert the EFFECT (allocation across the dial), not just the
// returned error: a swallowed or wrapped error would pass an error-only check
// whether or not the buffer was ever allocated.
//
// What they do NOT verify: peak RSS or cgroup behaviour (they measure Go's
// TotalAlloc delta only), nor that no other keyorix package dials an untrusted
// PostgreSQL server (see TestEveryPgxConnectInDynamicUsesTheBoundedConfig for the
// dynamic package's own sites).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/keyorixhq/keyorix/internal/pgxlimits"
)

// hostileClaimedLen is the claimed body length the rogue server announces:
// 0x2e2e2e2e - 4 = ~775 MB, far over pgxlimits.MaxProtocolMessageBodyLen and under
// pgx's own ~1 GiB default, i.e. exactly the window the bound closes.
var hostileClaimedLen = []byte{0x2e, 0x2e, 0x2e, 0x2e}

// startHostileLengthServer serves loopback connections. afterHandshake=false
// answers the startup packet with an Authentication header claiming a huge body;
// afterHandshake=true completes the handshake (AuthenticationOk, ReadyForQuery)
// and answers the first query with a CommandComplete header claiming a huge body.
// In both cases it sends only the 5-byte header and then closes.
func startHostileLengthServer(t *testing.T, afterHandshake bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHostileLength(conn, afterHandshake)
		}
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("host=%s port=%s user=u password=p dbname=d sslmode=disable", host, port)
}

func serveHostileLength(conn net.Conn, afterHandshake bool) {
	defer func() { _ = conn.Close() }()
	be := pgproto3.NewBackend(conn, conn)
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return
	}
	header := append([]byte{'R'}, hostileClaimedLen...)
	if afterHandshake {
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if err := be.Flush(); err != nil {
			return
		}
		if _, err := be.Receive(); err != nil { // the Exec's Query message
			return
		}
		header = append([]byte{'C'}, hostileClaimedLen...)
	}
	_, _ = conn.Write(header)
	time.Sleep(300 * time.Millisecond) // let the client act on the header, then EOF
}

// allocAcross returns the Go heap bytes allocated process-wide while fn ran. The
// package's tests do not run in parallel, so this attributes to fn.
func allocAcross(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestPostgresEngineBoundsServerClaimedMessageLength(t *testing.T) {
	isolatePGEnv(t)
	const ceiling = 64 << 20 // measured unbounded: ~775 MB; bounded: ~1-8 MB of pgx setup

	cases := []struct {
		name           string
		afterHandshake bool
		call           func(ctx context.Context, e *PostgresEngine, dsn string) error
	}{
		{"issue/handshake", false, func(ctx context.Context, e *PostgresEngine, dsn string) error {
			_, _, err := e.Issue(ctx, dsn, "", time.Hour)
			return err
		}},
		{"renew/query-reply", true, func(ctx context.Context, e *PostgresEngine, dsn string) error {
			return e.Renew(ctx, dsn, "kx_dyn_x", time.Now().Add(time.Hour))
		}},
		{"revoke/query-reply", true, func(ctx context.Context, e *PostgresEngine, dsn string) error {
			return e.Revoke(ctx, dsn, "kx_dyn_x")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dsn := startHostileLengthServer(t, tc.afterHandshake)
			e := &PostgresEngine{allowPrivateNetwork: true, transport: plaintextFakeServer} // loopback rogue server
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			var err error
			alloc := allocAcross(func() { err = tc.call(ctx, e, dsn) })

			if alloc > ceiling {
				t.Errorf("a %d-byte header claiming a ~775 MB body cost %d bytes of allocation (ceiling %d): "+
					"the server-claimed length is not bounded", len(hostileClaimedLen)+1, alloc, ceiling)
			}
			// Only the connect stage surfaces the typed error: once the session is
			// established pgx closes the connection and reports a generic "conn
			// closed" (Renew), and Revoke swallows best-effort statement errors by
			// design. The allocation bound above is the property under test.
			switch tc.name {
			case "issue/handshake":
				ex, ok := errors.AsType[*pgproto3.ExceededMaxBodyLenErr](err)
				if !ok {
					t.Errorf("want *pgproto3.ExceededMaxBodyLenErr in the error chain, got %v", err)
				} else if ex.MaxExpectedBodyLen != pgxlimits.MaxProtocolMessageBodyLen {
					// The 64 MiB allocation ceiling above would also pass a much looser
					// effective bound; this pins what pgx was actually configured with.
					t.Errorf("effective MaxExpectedBodyLen = %d, want pgxlimits.MaxProtocolMessageBodyLen (%d)",
						ex.MaxExpectedBodyLen, pgxlimits.MaxProtocolMessageBodyLen)
				}
			case "renew/query-reply":
				if err == nil {
					t.Error("Renew must fail when the server's reply exceeds the bound")
				}
			}
		})
	}
}
