package sshhostile

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"golang.org/x/crypto/ssh"
)

// PK2: port the x/crypto/ssh authorized-key target onto resguard. The existing
// round-trip-stability + no-panic oracle is UNCHANGED; resguard meters the
// parse's resource cost. Fatal meters: alloc_bytes / mallocs / live_heap
// (per-byte slope) — an authorized-key line whose parse allocates out of
// proportion to its bytes (e.g. a length-prefixed field claiming a huge size)
// is caught. CPU/wall/goroutines are advisory. The oracle meters
// ParseAuthorizedKey only, bounds ratio not correctness, and alloc is sampled
// (slow inputs force-sampled).

const rgBudgetPath = "testdata/resguard-ssh.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

// validEd25519 is a real authorized_keys line (same as a seed), the fully-parsed
// path; most hostile inputs reject early and are cheap.
const validEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCNPj70vRk7BvDxM2cSOWZ0f1ayczW+5stLTUgYD7D5 admin@keyorix"

func rgRun(data []byte) {
	// Meter ParseAuthorizedKey only — the same surface the fuzz body measures.
	_, _, _, _, _ = ssh.ParseAuthorizedKey(data)
}

func rgBenignCorpus() [][]byte {
	// Many valid ed25519 lines of varying comment length so the slope reflects
	// real parse cost across sizes.
	var seeds [][]byte
	seeds = append(seeds, []byte(validEd25519))
	for i := range 20 {
		seeds = append(seeds, []byte(validEd25519+strings.Repeat("x", i*8)))
	}
	seeds = append(seeds,
		[]byte("ssh-rsa AAAAB3NzaC1yc2E"),
		[]byte("# just a comment line\n"),
	)
	return seeds
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s), func() { rgRun(s) }))
		}
	}
	b := resguard.Calibrate("ssh_authorizedkey", costs, resguard.DefaultFactor)
	delete(b.Meters, "live_heap") // non-attributable process-heap snapshot (see yaml)
	return b
}

func TestResguardSSHCalibrate(t *testing.T) {
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

// TestResguardSSHRedGreen proves the oracle. GREEN: a valid key passes. RED:
// x/crypto/ssh's authorized-key parser was probed for a natural super-linear
// amplifier (oversized base64 blobs, lying internal length prefixes) and found
// to reject malformed length fields before allocating — robustly bounded. So RED
// is a budget self-test: a 100× alloc amplification of a benign-sized parse (the
// RAM-spike shape a future regression would produce) must trip this target's
// calibrated budget — a watched guard; the oracle's role here is a regression
// tripwire.
func TestResguardSSHRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := []byte(validEd25519)
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("valid key tripped the budget: alloc=%d", green.AllocBytes)
	}

	red := green
	red.AllocBytes = green.AllocBytes * 100
	red.Mallocs = green.Mallocs * 100
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("a 100× alloc amplification did NOT trip the budget (alloc=%d) — budget too loose", red.AllocBytes)
	}
	t.Logf("RED tripped (synthetic 100× alloc): %s", msg)
}
