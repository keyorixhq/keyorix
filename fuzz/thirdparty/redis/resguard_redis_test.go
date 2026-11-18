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
	"fmt"
	"os"
	"strings"
	"testing"

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
