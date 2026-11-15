package libconformance

import (
	"fmt"
	"math"
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
// The distinct-key control is linear in ALLOCATION only. Its CPU time is
// quadratic too, with a small constant: yaml.v3's decoder.mapping()
// (gopkg.in/yaml.v3@v3.0.1 decode.go:769) compares every key of a mapping with
// every later key to reject duplicates, distinct or not. It reads ~3.0-3.5x per
// doubling on an idle host, on the threshold, which is why PR #4284's queue
// round read it as super-linear (3.23x) once a loaded runner added wall-clock
// noise on top. So the distinct-key control is judged on the memory arm alone,
// and the time arm is calibrated on its own pair: a sequence of small mappings
// (linear in both arms, the time-arm green control) and the same sequence with
// a planted O(n^2) CPU pass and linear allocation (the time-arm red proof).
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

// TestCalib_YAMLUniqueKey_QuietGreen is the memory-arm GREEN proof: distinct
// keys allocate linearly, so the memory arm must NOT fire. Together with the
// duplicate-key fire above this shows the memory arm keys on "duplicate key",
// not merely "large mapping". The time arm is excluded (TimeFloor out of reach)
// because yaml.v3's pairwise uniqueness scan makes this decode genuinely
// quadratic in CPU (see the file comment); its reading is logged, not judged.
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
	cfg := calibCfg()
	cfg.TimeFloor = math.MaxInt64 // memory arm only: the time curve is a real (small) quadratic
	v := boundedwork.Analyze("gopkg.in/yaml.v3 uniq", nil, uniqueScale, dupKeyUnmarshalGopkg, cfg)
	t.Logf("unique->map: judged=%v super=%v alloc=%.2fx (time %.2fx on %s clock, not judged: pairwise key scan)",
		v.Judged, v.SuperLinear, v.AllocDoubling, v.TimeDoubling, v.TimeClock)
	if !v.Judged || !v.AllocJudged {
		t.Fatalf("memory arm drew no verdict on the distinct-key control (%s) — fixture too small to calibrate", v.Reason)
	}
	if v.SuperLinear {
		t.Fatalf("oracle FALSE-POSITIVED on distinct keys (linear-allocation control): alloc %.2fx per doubling — %s",
			v.AllocDoubling, v.Reason)
	}
}

// seqScale builds a sequence of factor*512 two-key mappings. Every mapping is
// small, so yaml.v3's per-mapping pairwise key scan is O(1) per item and the
// whole decode is linear in both time and allocation.
func seqScale(_ []byte, factor int) []byte {
	const unit = 512
	var b []byte
	for i := range unit * factor {
		b = append(b, fmt.Sprintf("- a: %d\n  b: x\n", i)...)
	}
	return b
}

func seqUnmarshalGopkg(in []byte) {
	var v any
	_ = gopkgyaml.Unmarshal(in, &v)
}

// plantedSink keeps the planted quadratic pass from being optimised away.
var plantedSink int

// plantedQuadraticCPU is the planted defect: a duplicate-scan style O(n^2) pass
// over the input bytes that allocates nothing, so only the time arm can see it.
func plantedQuadraticCPU(in []byte) {
	acc := 0
	for i := range in {
		for j := 0; j < i; j += 2 {
			if in[i] == in[j] {
				acc++
			}
		}
	}
	plantedSink += acc
}

// TestCalib_YAMLSequence_TimeArmQuietGreen is the time-arm GREEN proof: a
// decode that is linear in CPU and memory must not fire, with both arms judged
// at the production threshold. This is the control that must hold on a loaded
// runner (the time arm measures best-of-N process CPU time, see measure).
func TestCalib_YAMLSequence_TimeArmQuietGreen(t *testing.T) {
	v := boundedwork.Analyze("gopkg.in/yaml.v3 seq", nil, seqScale, seqUnmarshalGopkg, calibCfg())
	t.Logf("seq->any: judged=%v super=%v time=%.2fx (%s) alloc=%.2fx",
		v.Judged, v.SuperLinear, v.TimeDoubling, v.TimeClock, v.AllocDoubling)
	if !v.TimeJudged {
		t.Fatalf("time arm drew no verdict on the linear sequence (%s) — fixture too small to calibrate the time arm", v.Reason)
	}
	if v.SuperLinear {
		t.Fatalf("oracle FALSE-POSITIVED on a linear decode: %s; measurements=%+v", v.Reason, v.Measurements)
	}
}

// TestCalib_PlantedQuadraticTime_FiresRed is the time-arm RED proof on the same
// fixture: the linear sequence decode plus a planted O(n^2) CPU pass with no
// extra allocation. The time arm alone must fire (alloc stays linear), which
// proves the noise-robust time measure still has the power to flag a real
// quadratic, under load as on an idle host.
func TestCalib_PlantedQuadraticTime_FiresRed(t *testing.T) {
	call := func(in []byte) {
		seqUnmarshalGopkg(in)
		plantedQuadraticCPU(in)
	}
	v := boundedwork.Analyze("gopkg.in/yaml.v3 seq+planted", nil, seqScale, call, calibCfg())
	t.Logf("seq+planted: judged=%v super=%v time=%.2fx (%s) alloc=%.2fx",
		v.Judged, v.SuperLinear, v.TimeDoubling, v.TimeClock, v.AllocDoubling)
	if !v.TimeJudged || !v.SuperLinear || v.TimeDoubling <= calibCfg().MaxDoubling {
		t.Fatalf("oracle FAILED to detect the planted O(n^2) CPU pass (time %.2fx, %s) — time arm blinded: %+v",
			v.TimeDoubling, v.Reason, v.Measurements)
	}
	if v.AllocDoubling > calibCfg().MaxDoubling {
		t.Fatalf("planted fixture is not time-only: alloc %.2fx per doubling — it no longer proves the time arm", v.AllocDoubling)
	}
}
