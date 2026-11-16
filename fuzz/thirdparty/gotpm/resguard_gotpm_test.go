package gotpmhostile

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// PK2: port the go-tpm tpm2 unmarshal target onto resguard. The existing no-panic
// + bounded-wall + round-trip-stability oracle is UNCHANGED; resguard meters the
// decode's resource cost. Fatal meters: alloc_bytes / mallocs / live_heap
// (per-byte slope). A TPM2B framing carries a 2-byte big-endian size prefix; a
// decoder that trusted a lying size and pre-allocated it would amplify a tiny
// input — the RED case probes exactly that. CPU/wall/goroutines advisory.

const rgBudgetPath = "testdata/resguard-gotpm.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

func rgRun(sel uint8, data []byte) {
	switch sel % 5 {
	case 0:
		_ = rt[tpm2.TPM2BPublic](data)
	case 1:
		_ = rt[tpm2.TPM2BPrivate](data)
	case 2:
		_ = rt[tpm2.TPMTPublic](data)
	case 3:
		_ = rt[tpm2.TPM2BData](data)
	case 4:
		_ = rt[tpm2.TPM2BName](data)
	}
}

type rgSeed struct {
	sel  uint8
	data []byte
}

func rgBenignCorpus() []rgSeed {
	seeds := []rgSeed{
		{0, []byte{0x00, 0x00}},
		{1, []byte{0x00, 0x01, 0x00}},
		{2, []byte{0x00, 0x04, 0x00, 0x0b, 0x00, 0x22}},
		{3, []byte{0x00, 0x20}},
		{4, []byte{0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}},
	}
	// Well-framed TPM2B buffers of growing honest size (size prefix == payload).
	for _, n := range []int{16, 64, 256, 1024} {
		b := []byte{byte(n >> 8), byte(n)}
		b = append(b, make([]byte, n)...)
		seeds = append(seeds, rgSeed{3, b}) // TPM2BData accepts an arbitrary buffer
	}
	return seeds
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s.data), func() { rgRun(s.sel, s.data) }))
		}
	}
	return resguard.Calibrate("gotpm_unmarshal", costs, resguard.DefaultFactor)
}

func TestResguardGoTPMCalibrate(t *testing.T) {
	b := rgCalibrate(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes must be calibrated; got %s", b.Summary())
	}
	if *rgWrite {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardGoTPMRedGreen proves the oracle. GREEN: a small honest TPM2B passes.
// RED: a tiny input with a LYING huge size prefix (0xffff declaring 64 KiB from a
// 4-byte input). go-tpm was probed to see whether it pre-allocates the declared
// size; if it does the parse allocates super-linearly (real amplifier), if it
// rejects the short buffer first the test falls back to a budget self-test. Either
// way the guard is watched firing.
func TestResguardGoTPMRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := []byte{0x00, 0x20}
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(3, benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign TPM2B tripped the budget: alloc=%d", green.AllocBytes)
	}

	// Lying size prefix: 0xffff (65535) declared, only 2 payload bytes present.
	lying := []byte{0xff, 0xff, 0x01, 0x02}
	pr := resguard.New(t, resguard.Options{SampleEvery: 1})
	red := pr.Measure(len(lying), func() { rgRun(0, lying) })
	mb := b.Meters["alloc_bytes"]
	allowed := b.Factor * (mb.Floor + mb.PerByte*float64(len(lying)))
	natural := b.Check(func(string, ...any) {}, red)
	if !natural {
		// go-tpm did not pre-allocate the lie; fall back to a budget self-test so
		// the guard is still watched firing (tripwire for a future regression).
		red.AllocBytes = uint64(allowed*10) + 1
	}
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("red did not trip the budget (alloc=%d, ceiling=%.0f)", red.AllocBytes, allowed)
	}
	t.Logf("RED tripped (natural lying-size amplifier=%v; alloc=%d): %s", natural, red.AllocBytes, msg)
}
