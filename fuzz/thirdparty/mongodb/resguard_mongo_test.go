package mongofuzz

// resguard_mongo_test.go — PK1 port of the mongodb hostile-reply target onto the
// shared resguard resource layer. FuzzMongoReply already carried an INLINE crude
// alloc bound (a fixed 32 MiB TotalAlloc-delta check inside runInteraction) plus
// canary/echo oracles; PK1 ADDS a calibrated per-byte-slope budget around the same
// call and keeps every existing oracle verbatim (never substituted).
//
// Budget model: per-byte slope on alloc_bytes/mallocs (BSON is a parser; the outer
// messageLength is structurally clamped to maxWireLen before the bytes reach the
// driver, so alloc is already bounded — the resguard budget is a calibrated,
// quantitative check complementing the structural clamp and the fixed 32 MiB bound).
// cpu_ns advisory. live_heap dropped (whole-process). No net/sleep (loopback).
//
// What it does NOT verify: correctness; alloc is sampled; CPU advisory/process-wide;
// cannot separate the fake server's alloc from the driver's; the inputLen used for
// the slope is len(body) (the attacker BSON bytes), not the 4 uint8 mode selectors.

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const mongoBudgetReply = "testdata/resguard-mongo-reply.json"

var mongoMemMeters = []string{"alloc_bytes", "mallocs", "cpu_ns"}

func mongoResguardProbe(f *testing.F, budgetPath string) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(budgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", budgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

type mongoSeed struct {
	mode, opSel, lenMode, driveMode uint8
	body                            []byte
}

// mongoBenignSeeds are the valid-ish exchanges from FuzzMongoReply's f.Add set: a
// valid hello reply and an error-document echo, under the normal (unclamped,
// length-honest) mode. These drive the real BSON parse path for calibration.
func mongoBenignSeeds() []mongoSeed {
	validHello, _ := bson.Marshal(cannedHelloDoc())
	helloBody := append([]byte{0, 0, 0, 0, 0}, validHello...)
	errDoc, _ := bson.Marshal(bson.D{{Key: "ok", Value: int32(0)}, {Key: "errmsg", Value: "auth failed: bad things"}, {Key: "code", Value: int32(18)}})
	return []mongoSeed{
		{0, 0, 0, 0, helloBody},
		{1, 0, 0, 0, helloBody},
		{1, 0, 0, 1, helloBody},
		{1, 0, 0, 0, append([]byte{0, 0, 0, 0, 0}, errDoc...)},
	}
}

func calibrateMongo(t testing.TB) resguard.Budget {
	t.Helper()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	tt := t.(*testing.T)
	var costs []resguard.Cost
	for range 3 {
		for _, s := range mongoBenignSeeds() {
			body := s.body
			if len(body) > maxWireLen {
				body = body[:maxWireLen]
			}
			costs = append(costs, probe.Measure(len(body), func() {
				runInteraction(tt, s.mode, s.opSel, s.lenMode, s.driveMode, body)
			}))
		}
	}
	b := resguard.Calibrate("mongo_reply", costs, resguard.DefaultFactor)
	b.KeepOnly(mongoMemMeters...)
	return b
}

func TestResguardMongoCalibrate(t *testing.T) {
	b := calibrateMongo(t)
	if len(b.Meters) == 0 {
		t.Fatalf("no memory meter calibrated; %s", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(mongoBudgetReply); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", mongoBudgetReply, b.Summary())
	}
}

func TestResguardMongoRedGreen(t *testing.T) {
	b := calibrateMongo(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	s := mongoBenignSeeds()[0]
	green := probe.Measure(len(s.body), func() {
		runInteraction(t, s.mode, s.opSel, s.lenMode, s.driveMode, s.body)
	})
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign hello reply (alloc=%d) must pass the budget", green.AllocBytes)
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
