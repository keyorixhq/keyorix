package libconformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// TestComplexityOracleRedGreen is the per-target red/green proof that each
// Fuzz*Complexity target's calibrated Budget both (green) passes the measured
// cost of a legitimate large input and (red) FIRES on an amplified cost at the
// same input size. The budgets here are the SAME literals the fuzz targets use;
// if a target's budget is retuned, update it here too (there is no shared
// constant because each target documents its own budget inline next to its
// rationale).
//
// Note the asymmetry by design: for yaml the red side uses the REAL parser on a
// real known-bad vector (duplicate keys), because yaml.v3 genuinely exhibits the
// amplification — no synthetic defect is needed. For the hardened parsers
// (etree/jwt/protobuf/identity) no real input blows up (that is the point — they
// are bounded), so the red side plants a synthetic O(n^2) amplifier in test code
// and shows the budget catches that shape at the target's threshold. The
// synthetic amplifier is never in a production path.
func TestComplexityOracleRedGreen(t *testing.T) {
	fired := func(b complexity.Budget, label string, n int, c complexity.Cost) bool {
		return b.Check(func(string, ...any) {}, label, n, c) // swallow the message; we only want the verdict
	}

	t.Run("yaml-real-vector", func(t *testing.T) {
		budget := complexity.Budget{MaxAllocBytesPerByte: 512, FloorBytes: 2 << 20}
		// GREEN: distinct keys (legit large map) must pass.
		green := complexity.Measure(func() { var v any; _ = yaml.Unmarshal(yamlDistinct(1500), &v) })
		if fired(budget, "yaml", len(yamlDistinct(1500)), green) {
			t.Fatalf("yaml budget fired on legitimate distinct-key map (alloc=%d)", green.AllocBytes)
		}
		// RED: duplicate keys (real amplification) must fire.
		dup := []byte(strings.Repeat("k: v\n", 1500))
		red := complexity.Measure(func() { var v any; _ = yaml.Unmarshal(dup, &v) })
		if !fired(budget, "yaml", len(dup), red) {
			t.Fatalf("yaml budget did NOT fire on duplicate-key amplification (alloc=%d for %d bytes)", red.AllocBytes, len(dup))
		}
	})

	// For the hardened parsers: green = measured legit cost passes; red = a cost
	// representing a quadratic amplification at the same size fires. The red Cost
	// is what Measure WOULD report if the parser allocated O(n^2); we assert the
	// chosen threshold separates the two.
	hardened := []struct {
		name   string
		budget complexity.Budget
		inLen  int
		legit  uint64 // a realistic measured alloc for inLen (from calibration)
	}{
		// etree: ~256 B/byte slope, 2 MiB floor. attr-bomb measured ~70 B/byte.
		{"etree", complexity.Budget{MaxAllocBytesPerByte: 256, FloorBytes: 2 << 20, AbsMaxAllocBytes: 256 << 20}, 64 << 10, 4 << 20},
		// jwt: 64 B/byte slope.
		{"jwt", complexity.Budget{MaxAllocBytesPerByte: 64, FloorBytes: 2 << 20, AbsMaxAllocBytes: 256 << 20}, 32 << 10, 3 << 20},
		// protobuf: 64 B/byte slope.
		{"protobuf", complexity.Budget{MaxAllocBytesPerByte: 64, FloorBytes: 2 << 20, AbsMaxAllocBytes: 256 << 20}, 32 << 10, 3 << 20},
		// identity: 512 B/byte slope.
		{"identity", complexity.Budget{MaxAllocBytesPerByte: 512, FloorBytes: 2 << 20, AbsMaxAllocBytes: 64 << 20}, 16 << 10, 2500 << 10},
	}
	for _, h := range hardened {
		t.Run(h.name+"-synthetic", func(t *testing.T) {
			// GREEN: legit cost under budget.
			if fired(h.budget, h.name, h.inLen, complexity.Cost{AllocBytes: h.legit}) {
				t.Fatalf("%s budget fired on a legitimate cost %d for %d bytes", h.name, h.legit, h.inLen)
			}
			// RED: a quadratic amplifier — alloc = inLen^2 (planted shape).
			quad := uint64(h.inLen) * uint64(h.inLen)
			if !fired(h.budget, h.name, h.inLen, complexity.Cost{AllocBytes: quad}) {
				t.Fatalf("%s budget did NOT fire on O(n^2) alloc %d for %d bytes", h.name, quad, h.inLen)
			}
		})
	}
}
