package redishostile

// resguard_redis_test.go — PK1 port of the go-redis hostile-server target onto the
// shared resguard resource layer. Same design as the pgx/mysql ports: the existing
// no-panic/bounded-time oracles are UNCHANGED (in driveRedisReply); a resguard.Probe
// meters alloc_bytes/mallocs (RAM-spike signal) + CPU (advisory) per input, checked
// against a per-byte-slope budget (RESP replies are a parser, small input → bounded
// alloc is the invariant; a huge declared bulk length that drives super-linear alloc
// is the defect — the `$9999999\r\nshort\r\n` seed shape).
//
// What this oracle does NOT verify: correctness (only alloc proportion); alloc is
// sampled; CPU is process-wide advisory; cannot separate the test server's alloc
// from the driver's. No net/sleep meters (loopback fake server, not a connector).

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const redisBudgetReply = "testdata/resguard-redis-reply.json"

var redisMemMeters = []string{"alloc_bytes", "mallocs", "cpu_ns"}

func redisResguardProbe(f *testing.F, budgetPath string) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(budgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", budgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

func measureRedis(t *testing.T, probe *resguard.Probe, budget resguard.Budget, haveBudget bool, reply []byte, drive func(*testing.T, []byte)) {
	cost := probe.Measure(len(reply), func() { drive(t, reply) })
	resguard.FeedCoverage(cost)
	if haveBudget {
		budget.Check(t.Fatalf, cost)
	}
}

// redisBenignReply: valid RESP2/RESP3 replies of modest size. A bulk string whose
// declared length MATCHES its data is benign; the fuzzer explores the over-declared
// shape ($9999999\r\nshort) against this slope budget.
func redisBenignReply() [][]byte {
	return [][]byte{
		[]byte("+OK\r\n"),
		[]byte("-ERR nope\r\n"),
		[]byte(":123\r\n"),
		[]byte("$5\r\nhello\r\n"),
		[]byte("*2\r\n:1\r\n:2\r\n"),
		[]byte("%1\r\n+k\r\n+v\r\n"),
		[]byte("$64\r\n" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + "\r\n"),
	}
}

func calibrateRedis(t testing.TB) resguard.Budget {
	t.Helper()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	tt := t.(*testing.T)
	var costs []resguard.Cost
	for range 3 {
		for _, seed := range redisBenignReply() {
			costs = append(costs, probe.Measure(len(seed), func() { driveRedisReply(tt, seed) }))
		}
	}
	b := resguard.Calibrate("redis_reply", costs, resguard.DefaultFactor)
	b.KeepOnly(redisMemMeters...)
	return b
}

func TestResguardRedisCalibrate(t *testing.T) {
	b := calibrateRedis(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no memory meter calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(redisBudgetReply); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", redisBudgetReply, b.Summary())
	}
}

func TestResguardRedisRedGreen(t *testing.T) {
	b := calibrateRedis(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	seed := []byte("$5\r\nhello\r\n")
	green := probe.Measure(len(seed), func() { driveRedisReply(t, seed) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign bulk reply (alloc=%d) must pass the budget", green.AllocBytes)
	}
	red := green
	red.Sampled = true
	red.AllocBytes = green.AllocBytes*1000 + 1<<30
	red.Mallocs = green.Mallocs*1000 + 1
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("RED: a 1000x alloc amplification must trip the budget")
	}
	if !strings.Contains(msg, "alloc_bytes") {
		t.Fatalf("RED: failure message should name alloc_bytes: %q", msg)
	}
	t.Logf("GREEN alloc=%d passes; RED alloc=%d fires: %s", green.AllocBytes, red.AllocBytes, msg)
}

// redisDeclaredAllowance is the largest RESP length header (bulk bytes or
// element/pair count) FuzzRedisReply will execute. go-redis sizes its buffers from
// the server-DECLARED length before any body bytes arrive and has no option to cap
// it, so allocation is proportional to a number the fuzzer can set freely. That is
// a known upstream behaviour (LF3-F3, details tracked privately), not something a
// per-input budget can police: calibrating the budget to one declared size only
// moves the failure to the next digit, and executing such inputs at -parallel=6
// would exhaust the rig's memory cgroup. So FuzzRedisReply skips them and
// TestRedisDeclaredLengthCharacterisation records what the driver does. Everything
// within the allowance (and every other amplification shape: nesting, many small
// elements) stays under the budget.
const redisDeclaredAllowance = 4096

// redisDeclaredLenExceeds reports whether any RESP header line in reply declares a
// length above redisDeclaredAllowance (or one too large to parse). It is
// deliberately conservative: a "$..." line inside a bulk body is treated as a header
// too, which only ever skips more, never less.
func redisDeclaredLenExceeds(reply []byte) bool {
	for line := range bytes.SplitSeq(reply, []byte("\r\n")) {
		if len(line) < 2 || !strings.ContainsRune("$*%~>|=!", rune(line[0])) {
			continue
		}
		n, err := strconv.ParseInt(string(line[1:]), 10, 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return true
			}
			continue
		}
		if n > redisDeclaredAllowance {
			return true
		}
	}
	return false
}

func TestRedisDeclaredLenExceeds(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"+OK\r\n", false},
		{"$5\r\nhello\r\n", false},
		{"$4096\r\nshort\r\n", false},
		{"$4097\r\nshort\r\n", true},
		{"$9999999\r\nshort\r\n", true},
		{"*100000000\r\n:1\r\n", true},
		{"%50000000\r\n+k\r\n+v\r\n", true},
		{"*2\r\n$99999999\r\nx\r\n:1\r\n", true},
		{"$9223372036854775807\r\n", true},
		{"$99999999999999999999999\r\n", true}, // overflows int64
		{"$-1\r\n", false},
		{",3.14\r\n", false},
		{"", false},
	} {
		if got := redisDeclaredLenExceeds([]byte(tc.in)); got != tc.want {
			t.Errorf("redisDeclaredLenExceeds(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestRedisDeclaredLengthCharacterisation records, without asserting, what go-redis
// does with a server-declared length far above the real body (LF3-F3). It is a log,
// not a gate: a go-redis fix would change the numbers, and the right response is
// then to revisit redisDeclaredAllowance, not to fail a dependency bump. Sizes stay
// at 16 MB-class so it is safe on CI; the unbounded extremes are described in
// FuzzRESP3BulkDeclared and not re-run here.
func TestRedisDeclaredLengthCharacterisation(t *testing.T) {
	for _, tc := range []struct{ name, reply string }{
		{"bulk 1e6 declared, 5 B body", "$1000000\r\nshort\r\n"},
		{"bulk 1e7 declared, 5 B body", "$9999999\r\nshort\r\n"},
		{"array 1e6 declared, 1 element", "*1000000\r\n:1\r\n"},
		{"map 5e5 declared, 1 pair", "%500000\r\n+k\r\n+v\r\n"},
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		srv := hostile.NewServer(t, func(c net.Conn) { serveUntilRealCommand(c, []byte(tc.reply)) })
		client := newClient(srv.Addr())
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("%s: driver panicked: %v", tc.name, r)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = client.Do(ctx, "ACL", "SETUSER", "kx_dyn_x", "on", ">pw").Err()
		}()
		runtime.ReadMemStats(&after)
		_ = client.Close()
		srv.Close()
		t.Logf("%-34s reply=%2d B  alloc=%6.1f MB", tc.name, len(tc.reply), float64(after.TotalAlloc-before.TotalAlloc)/(1<<20))
	}
}
