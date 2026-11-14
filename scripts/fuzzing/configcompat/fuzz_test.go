package configcompat

import (
	"testing"

	"github.com/keyorixhq/keyorix/scripts/fuzzing/configspace"
)

// FuzzConfigCompat drives the three config-compatibility invariants against the
// REAL config.Load/Validate at HEAD, seeded by the shipped example configs
// pulled from the old release tags in Revs. For each input it checks:
//
//	I1  config.Load never panics on arbitrary (old-ish) config bytes, gives a
//	    deterministic verdict, never leaks a canary secret VALUE in an error,
//	    and refuses an unrecognized key with a message that NAMES it.
//	I2  an accepted config never has a security posture holding that is neither
//	    a documented default nor explained by an explicit opt-in / feature key
//	    (a silently weakened default).
//	I3  a config written with a deprecated OLD key loads, warns by name, and has
//	    a security fingerprint identical to the same config written with the new
//	    key name (the deprecated key keeps its old meaning).
//
// The uint8 selector steers which alias pair and value I3 exercises, so the
// native engine explores the whole alias table and both boolean polarities.
func FuzzConfigCompat(f *testing.F) {
	m, err := configspace.LoadModel()
	if err != nil {
		f.Fatal(err)
	}
	pairs := aliasPairs()
	if len(pairs) == 0 {
		f.Fatal("no deprecated-alias pairs from config.DeprecatedSettingAliasPaths()")
	}
	defaults := defaultPostureSet()

	seeds := SeedConfigs()
	if len(seeds) == 0 {
		f.Fatal("no seed configs embedded")
	}
	for _, name := range seedNamesSorted(seeds) {
		for _, sel := range []uint8{0, 1, 7, 128, 200} {
			f.Add(seeds[name], sel)
		}
	}
	// a few non-file seeds that stress the key-naming and canary paths
	f.Add([]byte(Canary+"zz_unknown: 1\n"), uint8(0))
	f.Add([]byte("server:\n  http:\n    token: "+Canary+"\n"), uint8(3))

	dir := f.TempDir()
	env := NewEnv(dir)
	load := env.Load

	f.Fuzz(func(t *testing.T, data []byte, sel uint8) {
		if len(data) > 1<<16 {
			t.Skip()
		}

		// I1 — robustness on the raw bytes.
		for _, fnd := range CheckI1Robust(load, data) {
			t.Errorf("%s", fnd)
		}
		// I1 — named refusal of an unrecognized key derived from the input.
		for _, fnd := range CheckI1Named(m, load, string(data)) {
			t.Errorf("%s", fnd)
		}

		// I2 — no silently weakened posture on an accepted config.
		r := load(data)
		for _, fnd := range CheckI2(m, r, data, defaults, rawHasPath) {
			t.Errorf("%s", fnd)
		}

		// I3 — deprecated alias keeps its old meaning.
		pair := pairs[int(sel)%len(pairs)]
		value := sel&0x80 == 0 // true unless the high bit is set
		for _, fnd := range CheckI3(m, load, pair, value) {
			t.Errorf("%s", fnd)
		}
	})
}
