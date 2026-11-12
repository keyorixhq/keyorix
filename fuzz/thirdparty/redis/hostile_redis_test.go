// Package redisfuzz drives the real github.com/redis/go-redis/v9 client against
// a hostile Redis server whose command *reply* bytes come entirely from the fuzz
// input, through the client's public API only (redis.NewClient + client.Do). No
// Keyorix wrapper is in the path, so any crash is a go-redis bug.
//
// This is the h1 follow-up: h1 flagged the RESP3 reply parser (push messages,
// the attribute type, nested aggregate depth, blob length vs bytes sent, the
// pipeline/drain path that produced KFZ-2026-010) as the open lead. go-redis
// v9.23.0's internal/proto reader is reached through a generic client.Do, whose
// *Cmd calls proto.Reader.ReadReply — the full RESP3 type switch
// (array/set/push/map/attr/bulk/verbatim/bignum/double/bool).
//
// THREAT MODEL / KEYORIX REACHABILITY. internal/dynamic/redis.go connects this
// client to an operator-configured target Redis to mint/drop short-lived ACL
// users. client.Do(ctx, "ACL", "SETUSER", …) and client.Do(ctx, "ACL",
// "DELUSER", …) return a generic *Cmd whose reply is parsed by ReadReply — the
// exact recursive aggregate parser this harness drives. A malicious / compromised
// target Redis controls every reply byte. (client.Ping uses the single-line
// ReadString path, which does not recurse.) The admin-DSN password is the canary.
//
// ORACLES (and what each does NOT verify)
//
//	(a) no panic / no hang / bounded memory. A panic in the client goroutine
//	    fails the iteration. A hang is bounded by a 2s ctx AND a watchdog. Memory:
//	    clampRESP caps every length field at maxRESPLen (4 KiB) and truncates the
//	    reply at maxReplyBytes (32 KiB), so the loop does NOT exercise go-redis's
//	    true length-prefix amplification (h1 Finding 1, bounded by the socket read
//	    timeout) nor an unbounded-recursion stack overflow (characterised under a
//	    lowered max stack in TestRedis_NestedRecursion_Characterise). Does NOT
//	    catch a slow-but-finishing parse.
//	(b) canary: the client's configured password must never appear in the
//	    returned error or the fmt of the decoded value. Skipped when the fuzz
//	    input itself carries the canary bytes (echo). Does NOT scan the client
//	    value via reflection (it legitimately stores the password) nor logs.
//	(c) echo: server-controlled text in an error is EXPECTED echo, never a
//	    failure (TestRedis_EchoIsNotCanary).
//	(d) truncated success: a server closing mid-reply must make the client error,
//	    not return a truncated value (TestRedis_TruncatedReply_Oracle).
package redisfuzz

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisAllocBudget bounds TotalAlloc growth for one reply iteration. clampRESP
// already caps lengths and total bytes, so a normal iteration stays far below
// this; it fires only on a NEW amplification the clamp does not bound.
const redisAllocBudget = 96 << 20

const hangBudget = 6 * time.Second

// serveHostileReply answers -ERR to every handshake command (HELLO, legacy
// AUTH, …) and streams the fuzz-controlled reply bytes as the answer to the
// client's marker Do, then holds briefly and closes.
func serveHostileReply(ln net.Listener, reply []byte) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 8192)
	for {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(buf)
		if n > 0 {
			cmd := string(buf[:n])
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			switch {
			case strings.Contains(cmd, markerCmd):
				_, _ = c.Write(reply)
				// Give the client time to parse, then close so a truncated
				// reply surfaces EOF rather than hanging.
				time.Sleep(20 * time.Millisecond)
				return
			case strings.Contains(cmd, "hello"):
				// Reject HELLO with a redis ERROR so go-redis cleanly falls back
				// to RESP2 and then issues a legacy AUTH (a parse error here would
				// instead fail init). The reply parser the fuzzer targets is
				// reached regardless of RESP2/RESP3 negotiation.
				if _, werr := c.Write([]byte("-ERR unknown command 'HELLO'\r\n")); werr != nil {
					return
				}
			default:
				// Satisfy the legacy AUTH (and any other handshake command) so
				// init succeeds and the marker Do is sent.
				if _, werr := c.Write([]byte("+OK\r\n")); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

type redisOutcome struct {
	err      error
	rendered string
}

// runHostileRedis drives one client.Do(markerCmd) against a hostile reply and
// returns what the canary oracle scans plus the TotalAlloc delta.
func runHostileRedis(t *testing.T, in []byte) (*redisOutcome, uint64) {
	t.Helper()
	reply := clampRESP(in)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go serveHostileReply(ln, reply)

	opt := &redis.Options{
		Addr:            ln.Addr().String(),
		Protocol:        3,
		Username:        canaryUser,
		Password:        canaryPassword,
		DisableIdentity: true,
		DialTimeout:     time.Second,
		ReadTimeout:     2 * time.Second,
		WriteTimeout:    time.Second,
		MaxRetries:      -1,
		PoolSize:        1,
	}
	client := redis.NewClient(opt)
	defer func() { _ = client.Close() }()

	out := &redisOutcome{}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	before := ms.TotalAlloc

	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(hangBudget):
			panic("go-redis reply parse did not return within hang budget (possible infinite loop)")
		}
	}()
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := client.Do(ctx, markerCmd)
	out.err = res.Err()
	out.rendered = fmt.Sprintf("%#v", res.Val())

	runtime.ReadMemStats(&ms)
	return out, ms.TotalAlloc - before
}

// checkRedisCanary is oracle (b).
func checkRedisCanary(in []byte, o *redisOutcome) string {
	if strings.Contains(string(in), canaryPassword) {
		return "" // the server echoed the canary bytes: echo, not a leak
	}
	if o.err != nil && strings.Contains(o.err.Error(), canaryPassword) {
		return "error: " + o.err.Error()
	}
	if strings.Contains(o.rendered, canaryPassword) {
		return "decoded value contains the canary"
	}
	return ""
}

func recoverStack(fn func()) (val any, stack string) {
	defer func() {
		if r := recover(); r != nil {
			val, stack = r, string(debug.Stack())
		}
	}()
	fn()
	return nil, ""
}

func FuzzRedisReply(f *testing.F) {
	for _, seed := range redisSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var o *redisOutcome
		var alloc uint64
		val, stack := recoverStack(func() { o, alloc = runHostileRedis(t, in) })
		if val != nil {
			t.Fatalf("PANIC in go-redis reply parse: %v\n%s", val, stack)
		}
		if leak := checkRedisCanary(in, o); leak != "" {
			t.Fatalf("CANARY LEAK: %s", leak)
		}
		if alloc > redisAllocBudget {
			t.Fatalf("AMPLIFICATION: one reply iteration allocated %d bytes from a %d-byte input (budget %d)", alloc, len(in), redisAllocBudget)
		}
	})
}
