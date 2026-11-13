// Hostile-SERVER fuzz harness for redis/go-redis/v9, the driver Keyorix uses to mint/
// revoke dynamic Redis ACL users (internal/dynamic/redis.go) and rotate ACL passwords
// (internal/rotation/redis.go) against an OPERATOR-CONFIGURED target.
//
// Threat model: the target Redis server is attacker-controlled and replies with hostile
// RESP2/RESP3 wire bytes. Keyorix's real call sequence is redis.NewClient (single-node;
// NOT ClusterClient or FailoverClient) → client.Ping → client.Do("ACL", ...).
//
// Oracles (sound only):
//   - No panic escapes go-redis's documented error path (client.Do returns a *Cmd whose
//     .Err() carries the failure).
//   - Bounded time: each call returns within a context deadline.
//   - No credential and no connection to a host other than the configured one: a
//     MOVED/ASK redirect reply naming an attacker host must NOT be dialled and the
//     configured password must NOT be sent there. Verified by TestRedisMovedNotFollowed
//     with a red proof (a ClusterClient, which DOES follow the redirect).
//
// RESP3 nesting has no depth limit in go-redis (known: KFZ-2026-010 / KFZ-2026-080); per
// the task this is not re-reported — seeds use bounded depth only.
//
// What these oracles do NOT verify: see .scratch/h6-REPORT.md §6.
package redishostile

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// helloMap is a valid RESP3 HELLO reply so go-redis completes initConn and reaches the
// real command, where the fuzzed reply is delivered.
var helloMap = []byte("%7\r\n" +
	"$6\r\nserver\r\n$5\r\nredis\r\n" +
	"$7\r\nversion\r\n$5\r\n7.4.0\r\n" +
	"$5\r\nproto\r\n:3\r\n" +
	"$2\r\nid\r\n:1\r\n" +
	"$4\r\nmode\r\n$10\r\nstandalone\r\n" +
	"$4\r\nrole\r\n$6\r\nmaster\r\n" +
	"$7\r\nmodules\r\n*0\r\n")

// readCommand parses one RESP client command (array of bulk strings). Returns the
// uppercased command name and total arg count. Tolerates inline/partial on error.
func readCommand(r *bufio.Reader) (name string, nargs int, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", 0, err
	}
	if len(line) == 0 || line[0] != '*' {
		return "", 0, nil
	}
	n, _ := strconv.Atoi(trimCRLF(line[1:]))
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return "", 0, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return "", 0, nil
		}
		blen, _ := strconv.Atoi(trimCRLF(hdr[1:]))
		if blen < 0 || blen > 1<<20 {
			return "", 0, nil
		}
		buf := make([]byte, blen+2) // +CRLF
		if _, err := readFull(r, buf); err != nil {
			return "", 0, err
		}
		if i == 0 {
			name = upper(string(buf[:blen]))
		}
	}
	return name, n, nil
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

// serveUntilRealCommand replies to init commands (HELLO/CLIENT/AUTH) with valid stubs,
// then writes reply to the FIRST application command and returns.
func serveUntilRealCommand(c net.Conn, reply []byte) {
	r := bufio.NewReader(c)
	for {
		name, _, err := readCommand(r)
		if err != nil {
			return
		}
		switch name {
		case "HELLO":
			_, _ = c.Write(helloMap)
		case "CLIENT", "AUTH":
			_, _ = c.Write([]byte("+OK\r\n"))
		case "":
			return
		default:
			_, _ = c.Write(reply)
			return
		}
	}
}

func newClient(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:            addr,
		Protocol:        3,
		DisableIdentity: true,
		DialTimeout:     2 * time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    2 * time.Second,
		MaxRetries:      -1,
	})
}

func runWithOracles(t *testing.T, fn func(ctx context.Context)) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ORACLE panic escaped driver error path: %v", r)
			}
		}()
		fn(ctx)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Errorf("ORACLE bounded-time: driver call did not return within 6s of a hostile reply")
	}
}

// FuzzRedisReply fuzzes the server reply delivered to client.Do("ACL", ...): RESP2/RESP3
// simple strings, errors, integers, bulk ($ with huge declared lengths), arrays, maps,
// sets, attributes (|), push (>), doubles, booleans, nulls, verbatim, bignum.
func FuzzRedisReply(f *testing.F) {
	f.Add([]byte("+OK\r\n"))
	f.Add([]byte("-ERR nope\r\n"))
	f.Add([]byte(":123\r\n"))
	f.Add([]byte("$5\r\nhello\r\n"))
	f.Add([]byte("$9999999\r\nshort\r\n"))         // huge declared bulk length
	f.Add([]byte("*2\r\n:1\r\n:2\r\n"))            // RESP2 array
	f.Add([]byte("%1\r\n+k\r\n+v\r\n"))            // RESP3 map
	f.Add([]byte("|1\r\n+a\r\n+b\r\n+OK\r\n"))     // RESP3 attribute then value
	f.Add([]byte(">3\r\n+pubsub\r\n+ch\r\n+hi\r\n")) // RESP3 push
	f.Add([]byte(",3.14\r\n"))                     // double
	f.Add([]byte("#t\r\n"))                        // boolean
	f.Add([]byte("_\r\n"))                         // null
	f.Fuzz(func(t *testing.T, reply []byte) {
		srv := hostile.NewServer(t, func(c net.Conn) {
			serveUntilRealCommand(c, reply)
			_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 1024)
			for {
				if _, err := c.Read(buf); err != nil {
					break
				}
			}
		})
		defer srv.Close()
		client := newClient(srv.Addr())
		runWithOracles(t, func(ctx context.Context) {
			// Mirror internal/dynamic/redis.go: ACL SETUSER with discrete args.
			_ = client.Do(ctx, "ACL", "SETUSER", "kx_dyn_x", "on", ">pw", "~app:*", "+@read").Err()
		})
		_ = client.Close()
	})
}
