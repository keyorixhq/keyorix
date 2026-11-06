package verifierflip

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

// Planted-defect self-test (PREREG "What counts as negative"): the harness
// must flag every deliberately defective verifier below and must NOT flag the
// correct one. If any plant is missed, a clean result on a real verifier means
// nothing, so this test is the precondition for trusting every other target.

var (
	stKey = []byte("verifierflip-selftest-key-0123456789")
	stMsg = []byte("0123456789abcdef0123456789abcdef") // 32 bytes
)

func stArtifact() []byte {
	m := hmac.New(sha256.New, stKey)
	m.Write(stMsg)
	return append(append([]byte(nil), stMsg...), m.Sum(nil)...)
}

func stMAC(msg []byte) []byte {
	m := hmac.New(sha256.New, stKey)
	m.Write(msg)
	return m.Sum(nil)
}

func stTarget(name string, v func([]byte) bool) Target {
	return Target{
		Name: name, Artifact: stArtifact(), Verify: v,
		// nil Canon: the raw bytes (message AND tag) are the meaning, so
		// any accepted mutation counts as ACCEPT-DIFFERENT.
		MACStart: 32, MACEnd: 64,
	}
}

func good(b []byte) bool {
	return len(b) == 64 && hmac.Equal(stMAC(b[:32]), b[32:])
}

func TestSelfTest_CorrectVerifierIsClean(t *testing.T) {
	r, err := Run(stTarget("good", good), DefaultOptions(1))
	if err != nil {
		t.Fatal(err)
	}
	if r.Different+r.Panics+r.Equivalent != 0 {
		t.Fatalf("false positive on a correct verifier: %+v", r)
	}
	if r.Rejects == 0 || r.Mutations < 64*8 {
		t.Fatalf("harness did not exercise the verifier: mutations=%d rejects=%d", r.Mutations, r.Rejects)
	}
}

func TestSelfTest_PlantedDefectsAreDetected(t *testing.T) {
	plants := []struct {
		name string
		v    func([]byte) bool
		want string
	}{
		{"ignores-last-mac-byte", func(b []byte) bool {
			return len(b) >= 63 && hmac.Equal(stMAC(b[:32])[:31], b[32:63])
		}, AcceptDifferent},
		{"compares-16-byte-prefix", func(b []byte) bool {
			return len(b) >= 48 && hmac.Equal(stMAC(b[:32])[:16], b[32:48])
		}, AcceptDifferent},
		{"accepts-empty", func(b []byte) bool { return len(b) == 0 || good(b) }, AcceptDifferent},
		{"panics-on-truncated", func(b []byte) bool { return hmac.Equal(stMAC(b[:32]), b[32:64]) }, Panic},
		{"ignores-trailing-bytes", func(b []byte) bool {
			return len(b) >= 64 && hmac.Equal(stMAC(b[:32]), b[32:64])
		}, AcceptDifferent},
	}
	for _, p := range plants {
		t.Run(p.name, func(t *testing.T) {
			r, err := Run(stTarget(p.name, p.v), Options{Seed: 1, SkipTiming: true})
			if err != nil {
				t.Fatal(err)
			}
			got := r.Different
			if p.want == Panic {
				got = r.Panics
			}
			if got == 0 {
				t.Fatalf("planted defect %q NOT detected (want %s): %+v", p.name, p.want, r)
			}
		})
	}
}

// earlyExit is a variable-time compare: each matching leading MAC byte costs
// extra time, the classic timing oracle.
func earlyExit(b []byte) bool {
	if len(b) != 64 {
		return false
	}
	want := stMAC(b[:32])
	for i := range want {
		if want[i] != b[32+i] {
			return false
		}
		spin(3 * time.Microsecond)
	}
	return true
}

func spin(d time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); {
	}
}

func TestSelfTest_PlantedTimingSkewIsDetected(t *testing.T) {
	r, err := Run(stTarget("early-exit", earlyExit), DefaultOptions(1))
	if err != nil {
		t.Fatal(err)
	}
	if !r.PosSkew {
		t.Fatalf("planted variable-time compare NOT detected: ratio=%.3f", r.PosRatio)
	}
	rc, err := Run(stTarget("constant", good), DefaultOptions(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("constant-time control ratio=%.3f (skew=%v)", rc.PosRatio, rc.PosSkew)
}
