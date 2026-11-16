package bcrypthostile

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"golang.org/x/crypto/bcrypt"
)

// PK2: port the bcrypt target onto resguard. The existing round-trip + fail-closed
// + hostile-hash oracle is UNCHANGED; resguard RECORDS the per-input resource cost.
//
// IMPORTANT, stated honestly: bcrypt's real DoS is the COST-BOMB — a hash whose
// declared cost is large makes CompareHashAndPassword run 2^cost rounds (CPU). In
// resguard, cpu_ns/wall_ns are ADVISORY meters (process-wide, load-noisy), so they
// are recorded and reported but NEVER fail an input alone. bcrypt's cost-bomb is
// already guarded by the existing harness, which SKIPS any hostile hash whose
// declared cost exceeds DefaultCost before comparing — that skip, not resguard, is
// the load-bearing guard. resguard's FATAL meter here is alloc_bytes (bcrypt
// allocates ~constant, so a super-linear alloc regression is the only thing it
// would fatally catch — a tripwire). The RED/GREEN below proves that fatal alloc
// tripwire; it does NOT claim to catch the cost-bomb (advisory + existing skip do).

const rgBudgetPath = "testdata/resguard-bcrypt.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

// rgRun mirrors the fuzz body's bcrypt work on a benign (cost-sane) input.
func rgRun(password, hostileHash []byte) {
	if len(password) > 72 {
		password = password[:72]
	}
	h, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if err != nil {
		return
	}
	_ = bcrypt.CompareHashAndPassword(h, password)
	if cost, cerr := bcrypt.Cost(hostileHash); cerr == nil && cost <= bcrypt.DefaultCost {
		_ = bcrypt.CompareHashAndPassword(hostileHash, password)
	}
}

type rgSeed struct {
	pw   []byte
	hash []byte
}

func rgBenignCorpus() []rgSeed {
	return []rgSeed{
		{[]byte("correct horse battery staple"), []byte("$2a$04$abcdefghijklmnopqrstuu")},
		{[]byte(""), []byte("not-a-hash")},
		{[]byte("p"), []byte("")},
		{[]byte("another-password-of-some-length"), []byte("$2a$04$abcdefghijklmnopqrstuu")},
	}
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s.pw)+len(s.hash), func() { rgRun(s.pw, s.hash) }))
		}
	}
	return resguard.Calibrate("bcrypt_roundtrip", costs, resguard.DefaultFactor)
}

func TestResguardBcryptCalibrate(t *testing.T) {
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

// TestResguardBcryptRedGreen proves the FATAL alloc tripwire (not the cost-bomb,
// which is advisory + handled by the existing cost-skip). GREEN: a benign bcrypt
// round-trip passes. RED: a 10×-ceiling alloc (a super-linear RAM regression)
// trips the budget — a watched guard.
func TestResguardBcryptRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	seed := rgBenignCorpus()[0]
	n := len(seed.pw) + len(seed.hash)
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(n, func() { rgRun(seed.pw, seed.hash) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign bcrypt round-trip tripped the budget: alloc=%d", green.AllocBytes)
	}

	mb := b.Meters["alloc_bytes"]
	allowed := b.Factor * (mb.Floor + mb.PerByte*float64(n))
	red := green
	red.AllocBytes = uint64(allowed*10) + 1
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("a 10×-ceiling alloc amplification did NOT trip the budget (alloc=%d, ceiling=%.0f)", red.AllocBytes, allowed)
	}
	t.Logf("RED tripped (synthetic alloc=%d > 10× ceiling %.0f; cpu_ns advisory recorded=%s): %s", red.AllocBytes, allowed, green.CPU, msg)
}
