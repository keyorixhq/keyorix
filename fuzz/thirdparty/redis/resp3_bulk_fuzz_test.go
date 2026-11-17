package redishostile

// FuzzRESP3BulkDeclared and TestRedisNoCredentialInError extend the hostile-server
// harness with two new oracles the base FuzzRedisReply does not cover:
//
//  1. RESP3 huge-declared-count oracle (FuzzRESP3BulkDeclared): two independent fuzzer
//     dimensions — the DECLARED element count (uint64) and the ACTUAL reply payload
//     ([]byte). This separates the pre-allocation trigger (the count header) from the
//     data, so the fuzzer can explore count=999999999 with an empty body and
//     count=0 with arbitrary garbage body independently of the base harness, which
//     generates them together.
//
//     Oracles:
//       - Bounded time: the driver must return within the read timeout (2s client +
//         6s outer wall-clock), regardless of declared count.
//       - No panic via recover() inside runWithOracles.
//       - No credential in error text: the configured test password must not appear in
//         any error returned by the driver.
//
//     What it does NOT verify: heap bytes directly — a pre-alloc of make([]T, N) for
//     a fuzzer-controlled N can spike memory before the read-timeout fires. If go-redis
//     is found to do this, the finding goes to keyorix-private first (upstream bug, not
//     a Keyorix-side defect). This harness detects it only if the spike is large enough
//     to OOM the process, which will appear as a panic or test timeout.
//
//  2. Credential-not-in-error oracle (TestRedisNoCredentialInError): a deterministic
//     test that configures the client with a known password token, issues a call against
//     a server that always returns hostile error replies, and asserts that the returned
//     error text never contains the password token.
//
//     Reachability: internal/dynamic/redis.go and internal/rotation/redis.go both build
//     redis.NewClient with the operator-configured password and call client.Do("ACL", …).
//     If a hostile server echoes back a crafted error that includes the token, that is not
//     itself a credential leak — the caller already holds the credential. But if the DRIVER
//     itself formats the password into an error string, that string propagates into Keyorix
//     audit logs/error responses and becomes a secondary credential exposure. This test
//     checks the driver does not do that.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/redis/go-redis/v9"
)

const resp3TestPassword = "resp3-fuzz-credential-canary-do-not-appear-in-error"

// serveRESP3BulkDeclared writes an RESP3 bulk-string header with the given count and
// then writes body, then closes. The count is encoded as a RESP3 blob/verbatim header:
// `$<count>\r\n<body>` — a standard bulk string with a fuzzer-supplied count so the
// declared length can be much larger or smaller than the actual body.
func serveRESP3BulkDeclared(c net.Conn, count uint64, body []byte) {
	header := fmt.Sprintf("$%d\r\n", count)
	serveUntilRealCommand(c, append([]byte(header), body...))
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 256)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
}

// FuzzRESP3BulkDeclared drives client.Do against a server that replies with a RESP3
// bulk string whose DECLARED length (count) is independently fuzzed from the actual
// body bytes.  Seeds cover: declared > actual (truncated), declared = 0, declared
// matching valid body, declared at a large-but-safe value.
//
// LF3-F3 (CANDIDATE, upstream): go-redis pre-allocates make([]byte, N) based on the
// declared bulk-string length N before reading any body bytes. For N≥~512MB the
// process OOMs immediately, before the read timeout fires. Confirmed by seed
// uint64(1<<40)/nil body crashing with runtime.sysMapOS failure. The read timeout
// (2s) is NOT a memory bound — it fires only after allocation succeeds.
// This fuzz target caps count at 1<<24 (16MB) to exercise the pre-allocation path
// without OOMing. The finding is NOT re-tested here at the failing size; it is
// documented for keyorix-private / upstream reporting only.
func FuzzRESP3BulkDeclared(f *testing.F) {
	f.Add(uint64(0), []byte(nil))
	f.Add(uint64(5), []byte("hello"))                   // exact match
	f.Add(uint64(5), []byte("hi"))                      // declared > actual
	f.Add(uint64(1<<24), []byte(nil))                   // 16MB declared, empty body (safe upper bound)
	f.Add(uint64(9999999), []byte(nil))                 // ~10MB declared, empty body
	f.Add(uint64(5), []byte("hello-extra-garbage\r\n")) // declared < actual

	f.Fuzz(func(t *testing.T, count uint64, body []byte) {
		// Cap declared count: values ≥ ~512MB trigger OOM in go-redis's pre-allocator
		// (LF3-F3). This test covers the shape, not the extreme; the finding is filed
		// separately.
		if count > 1<<24 {
			count = count % (1 << 24)
		}
		if len(body) > 1<<16 {
			body = body[:1<<16]
		}
		srv := hostile.NewServer(t, func(c net.Conn) {
			serveRESP3BulkDeclared(c, count, body)
		})
		defer srv.Close()

		client := newClientWithPassword(srv.Addr(), resp3TestPassword)
		runWithOracles(t, func(ctx context.Context) {
			err := client.Do(ctx, "ACL", "SETUSER", "kx_dyn_x", "on", ">pw", "~app:*", "+@read").Err()
			if err != nil && strings.Contains(err.Error(), resp3TestPassword) {
				t.Errorf("ORACLE credential-in-error: driver error contains configured password\n  error=%q", err.Error())
			}
		})
		_ = client.Close()
	})
}

// TestRedisNoCredentialInError verifies that when a hostile server returns error replies,
// the go-redis driver does NOT include the configured client password in the error text.
// Red proof: see the t.Logf below — if go-redis ever formats the password into an error,
// this test will fail with "ORACLE credential-in-error".
func TestRedisNoCredentialInError(t *testing.T) {
	hostileReplies := []struct {
		name  string
		reply []byte
	}{
		{"simple-error", []byte("-ERR authentication failed\r\n")},
		{"wrongpass", []byte("-WRONGPASS invalid username-password pair\r\n")},
		{"noauth", []byte("-NOAUTH Authentication required\r\n")},
		{"noperm", []byte("-NOPERM User has no permissions to run the 'acl' command\r\n")},
		{"server-error-with-addr", []byte("-ERR dial tcp 127.0.0.1:6379: connection refused\r\n")},
	}

	for _, r := range hostileReplies {
		t.Run(r.name, func(t *testing.T) {
			reply := r.reply
			srv := hostile.NewServer(t, func(c net.Conn) {
				serveUntilRealCommand(c, reply)
				_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				buf := make([]byte, 256)
				for {
					if _, err := c.Read(buf); err != nil {
						break
					}
				}
			})
			defer srv.Close()

			client := newClientWithPassword(srv.Addr(), resp3TestPassword)
			defer func() { _ = client.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			err := client.Do(ctx, "ACL", "SETUSER", "kx_dyn_x", "on", ">pw", "~app:*", "+@read").Err()
			if err == nil {
				t.Logf("no error returned (server replied positively despite hostile reply — OK for this oracle)")
				return
			}
			if strings.Contains(err.Error(), resp3TestPassword) {
				t.Errorf("ORACLE credential-in-error: driver error contains configured password\n  reply=%q\n  error=%q",
					r.reply, err.Error())
			} else {
				t.Logf("credential correctly absent from error: %q", err.Error())
			}
		})
	}
}

// newClientWithPassword builds a Redis client like newClient but with a password set,
// so the credential-not-in-error oracle has a token to look for.
func newClientWithPassword(addr, password string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:            addr,
		Password:        password,
		Protocol:        3,
		DisableIdentity: true,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
		MaxRetries:      -1,
	})
}
