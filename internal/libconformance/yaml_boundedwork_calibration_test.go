package libconformance

import (
	"fmt"
	"testing"

	goyamlin "go.yaml.in/yaml/v3"
	gopkgyaml "gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/boundedwork"
)

// This file is the CALIBRATION of the boundedwork oracle against a real,
// reproducible super-linear defect: both yaml.v3 forks available offline
// (gopkg.in/yaml.v3 v3.0.1 and go.yaml.in/yaml/v3 v3.0.5) decode a mapping of N
// DUPLICATE keys in O(N^2) time AND O(N^2) memory (KFZ-2026-085 shape). It is an
// oracle-characterisation test, not a defect tripwire: it asserts the DETECTOR
// correctly classifies a known-positive (duplicate keys -> super-linear) and a
// known-negative (distinct keys -> linear). If a future yaml bump fixes the
// quadratic, the known-positive assertion flips — which is the signal to pick a
// new positive fixture, exactly as intended. Measured curve (gopkg.in, dup->map,
// alloc, from the calibration sweep): len 320->20480 grows ~4.2x per doubling,
// reaching 1.6 GB for a 20 KB input. The distinct-key control grows ~1.9x.
//
// What this does NOT verify: that keyorix is reachable by the defect (yaml here
// is parsed from admin/operator-controlled config, traced separately in the
// bw1 report), and nothing about yaml's output correctness — only cost shape.

// calibCfg is the config the yaml bounded-work measurement uses. It is the same
// shape a generated fuzz target would use: normalise the seed into the
// asymptotic regime (>=512 B), measure sizes 512..4096 B, judge only above the
// 3 ms / 1 MiB floors, fail above 3x per input-doubling.
func calibCfg() boundedwork.Config {
	return boundedwork.Config{
		Factors:     []int{1, 2, 4, 8},
		Repeats:     3,
		MaxInputLen: 1 << 20,
		MaxDoubling: 3.0,
	}
}

func dupKeyUnmarshalGopkg(in []byte) {
	var m map[string]any
	_ = gopkgyaml.Unmarshal(in, &m)
}

func dupKeyUnmarshalGoYAMLin(in []byte) {
	var m map[string]any
	_ = goyamlin.Unmarshal(in, &m)
}

// TestCalib_YAMLDuplicateKey_FiresRed is the RED proof: the oracle must classify
// the duplicate-key decode as super-linear for BOTH forks.
func TestCalib_YAMLDuplicateKey_FiresRed(t *testing.T) {
	scale := boundedwork.ScaleRepeat(512)
	for _, tc := range []struct {
		name string
		call func([]byte)
	}{
		{"gopkg.in/yaml.v3", dupKeyUnmarshalGopkg},
		{"go.yaml.in/yaml/v3", dupKeyUnmarshalGoYAMLin},
	} {
		v := boundedwork.Analyze(tc.name, []byte("a: 1\n"), scale, tc.call, calibCfg())
		t.Logf("%s dup->map: judged=%v super=%v time=%.2fx alloc=%.2fx",
			tc.name, v.Judged, v.SuperLinear, v.TimeDoubling, v.AllocDoubling)
		if !v.Judged {
			t.Fatalf("%s: oracle drew no verdict (below floors) — fixture too small to calibrate", tc.name)
		}
		if !v.SuperLinear {
			t.Fatalf("%s: oracle FAILED to detect the known duplicate-key quadratic (alloc %.2fx, time %.2fx per doubling) — detector regression",
				tc.name, v.AllocDoubling, v.TimeDoubling)
		}
		if v.AllocDoubling <= 3.0 {
			t.Fatalf("%s: expected alloc arm > 3x/doubling on the memory quadratic, got %.2fx", tc.name, v.AllocDoubling)
		}
	}
}

// TestCalib_YAMLUniqueKey_QuietGreen is the GREEN proof: distinct keys are
// linear, so the oracle must NOT fire — this is what shows the detector keys on
// "duplicate key", not merely "large mapping".
func TestCalib_YAMLUniqueKey_QuietGreen(t *testing.T) {
	uniqueScale := func(_ []byte, factor int) []byte {
		// Normalise into the asymptotic regime: 512 distinct keys as the unit,
		// then factor units. Each key is distinct across the whole document.
		const unit = 512
		n := unit * factor
		var b []byte
		for i := range n {
			b = append(b, fmt.Sprintf("k%d: 1\n", i)...)
		}
		return b
	}
	v := boundedwork.Analyze("gopkg.in/yaml.v3 uniq", nil, uniqueScale, dupKeyUnmarshalGopkg, calibCfg())
	t.Logf("unique->map: judged=%v super=%v time=%.2fx alloc=%.2fx",
		v.Judged, v.SuperLinear, v.TimeDoubling, v.AllocDoubling)
	if v.SuperLinear {
		t.Fatalf("oracle FALSE-POSITIVED on distinct keys (linear control): time %.2fx alloc %.2fx per doubling — floor/threshold miscalibrated",
			v.TimeDoubling, v.AllocDoubling)
	}
	if !v.Judged {
		t.Logf("note: unique-key control stayed below floors (not judged) — acceptable, no false positive")
	}
}
