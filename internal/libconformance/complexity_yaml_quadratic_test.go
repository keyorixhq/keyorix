package libconformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// TestYAMLDuplicateKeyQuadratic is the standing characterization of FINDING Y1:
// gopkg.in/yaml.v3 (v3.0.1, the version Keyorix pins) decodes a mapping whose
// keys are all identical in O(n^2) time AND memory, and returns its
// "mapping key already defined" error only AFTER the full quadratic work.
// Distinct keys are linear; duplicate keys are quadratic.
//
// This asserts the CURRENT (super-linear) upstream behaviour on purpose: it is a
// regression tripwire pointing the OTHER way. The day a yaml.v3 bump makes
// duplicate-key decoding linear, this test FAILS — which is the signal to
// tighten the import/config size caps that today must assume quadratic cost, and
// to update the report. It does NOT assert the cost is bounded (it is not).
//
// Reachability (see report §1): yaml.v3 is operator-reachable in Keyorix —
// `keyorix secret import --format vault` (cli/cmd/secret_import_parsers.go:197,
// capped at 100 MiB) and config/k8ssync loads — not network-reachable. The
// 100 MiB import cap is calibrated for a linear parser and does NOT prevent OOM
// here: the quadratic turns a ~1-2 MiB duplicate-key file into multi-GB alloc.
//
// Bounded to N<=2000 (~350 MiB, <1.5s) so it is safe on the shared rig; skipped
// in -short. The full growth table is in the report.
func TestYAMLDuplicateKeyQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a few hundred MiB; skipped in -short")
	}
	measure := func(n int) complexity.Cost {
		dup := []byte(strings.Repeat("k: v\n", n))
		return complexity.Measure(func() { var v any; _ = yaml.Unmarshal(dup, &v) })
	}

	// alloc-per-input-byte at N and at 2N: for a linear parser this ratio is
	// flat; for the quadratic duplicate-key path it roughly DOUBLES each time N
	// doubles. Require it to grow by at least 1.6x to call it super-linear
	// (headroom below the observed ~2x so GC noise cannot flip the verdict).
	c1 := measure(1000)
	c2 := measure(2000)
	r1 := float64(c1.AllocBytes) / float64(5000)  // 1000 lines * 5 bytes
	r2 := float64(c2.AllocBytes) / float64(10000) // 2000 lines * 5 bytes
	t.Logf("dup N=1000: alloc=%d (%.0f B/byte) wall=%s", c1.AllocBytes, r1, c1.Wall)
	t.Logf("dup N=2000: alloc=%d (%.0f B/byte) wall=%s", c2.AllocBytes, r2, c2.Wall)
	if r2 < r1*1.6 {
		t.Fatalf("expected super-linear duplicate-key growth (r2 >= 1.6*r1); got r1=%.0f r2=%.0f — has yaml.v3 been fixed? Update the size caps and this test.", r1, r2)
	}

	// Distinct keys must stay linear (flat ratio) — the contrast that makes the
	// duplicate-key result a real amplification and not just "big map".
	d1 := complexity.Measure(func() { var v any; _ = yaml.Unmarshal(yamlDistinct(1000), &v) })
	d2 := complexity.Measure(func() { var v any; _ = yaml.Unmarshal(yamlDistinct(2000), &v) })
	dr1 := float64(d1.AllocBytes) / float64(len(yamlDistinct(1000)))
	dr2 := float64(d2.AllocBytes) / float64(len(yamlDistinct(2000)))
	t.Logf("distinct N=1000: %.0f B/byte; N=2000: %.0f B/byte", dr1, dr2)
	if dr2 > dr1*1.5 {
		t.Fatalf("distinct-key decode is also growing super-linearly (dr1=%.0f dr2=%.0f) — the finding is not specific to duplicate keys", dr1, dr2)
	}
}
