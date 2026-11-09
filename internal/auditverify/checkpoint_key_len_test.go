package auditverify

import (
	"errors"
	"strings"
	"testing"
)

func forceCheckpointKeyFIPS(t *testing.T, on bool) {
	t.Helper()
	prev := checkpointKeyFIPSEnforced
	checkpointKeyFIPSEnforced = func() bool { return on }
	t.Cleanup(func() { checkpointKeyFIPSEnforced = prev })
}

func TestCheckCheckpointKeyLens_FIPSEnforced(t *testing.T) {
	forceCheckpointKeyFIPS(t, true)
	k := func(n int) []byte { return []byte(strings.Repeat("k", n)) }
	for _, n := range []int{1, 13} {
		err := checkCheckpointKeyLens(Options{CheckpointKey: k(n)})
		if !errors.Is(err, ErrCheckpointKeyTooShort) || !strings.Contains(err.Error(), "MinKEKLen") {
			t.Fatalf("%d-byte key: want ErrCheckpointKeyTooShort naming MinKEKLen, got %v", n, err)
		}
	}
	if err := checkCheckpointKeyLens(Options{CheckpointKey: k(32), PreviousCheckpointKeys: [][]byte{k(32), k(2)}}); !errors.Is(err, ErrCheckpointKeyTooShort) ||
		!strings.Contains(err.Error(), "previous checkpoint key #2") {
		t.Fatalf("short previous key: want a refusal naming #2, got %v", err)
	}
	for name, o := range map[string]Options{
		"no key":   {},
		"14 bytes": {CheckpointKey: k(MinKEKLen)},
		"32 bytes": {CheckpointKey: k(32), PreviousCheckpointKeys: [][]byte{k(32)}},
	} {
		if err := checkCheckpointKeyLens(o); err != nil {
			t.Errorf("%s: unexpected refusal: %v", name, err)
		}
	}
}

// Outside FIPS 140-only mode nothing changes: a short key is not refused (it
// is reported not authenticated by the walk, as before).
func TestCheckCheckpointKeyLens_NotEnforcedUnchanged(t *testing.T) {
	forceCheckpointKeyFIPS(t, false)
	if err := checkCheckpointKeyLens(Options{CheckpointKey: []byte("k"), PreviousCheckpointKeys: [][]byte{[]byte("k")}}); err != nil {
		t.Fatalf("default mode must not refuse: %v", err)
	}
}

// Default mode: every short key is warned about by position and length, never
// by value, and is still accepted.
func TestCheckpointKeyLenWarnings_DefaultModeWarnsAndAccepts(t *testing.T) {
	forceCheckpointKeyFIPS(t, false)
	k := func(n int) []byte { return []byte(strings.Repeat("Z", n)) }
	opts := Options{CheckpointKey: k(13), PreviousCheckpointKeys: [][]byte{k(32), k(2)}}
	got := CheckpointKeyLenWarnings(opts)
	if len(got) != 2 ||
		!strings.Contains(got[0], "the checkpoint key is 13 bytes") ||
		!strings.Contains(got[1], "previous checkpoint key #2 is 2 bytes") {
		t.Fatalf("want warnings for the 13-byte current key and the 2-byte previous key #2, got %q", got)
	}
	for _, w := range got {
		if !strings.HasPrefix(w, "WARNING: ") || !strings.Contains(w, "MinKEKLen (14 bytes") || strings.Contains(w, "ZZ") {
			t.Errorf("want a WARNING naming the minimum and no key bytes, got %q", w)
		}
	}
	if err := checkCheckpointKeyLens(opts); err != nil {
		t.Fatalf("default mode must still accept the keys: %v", err)
	}
	for name, o := range map[string]Options{
		"no key":   {},
		"14 bytes": {CheckpointKey: k(MinKEKLen)},
		"32 bytes": {CheckpointKey: k(32), PreviousCheckpointKeys: [][]byte{k(32)}},
	} {
		if w := CheckpointKeyLenWarnings(o); w != nil {
			t.Errorf("%s: unexpected warning: %q", name, w)
		}
	}
}

// Under enforcement the refusal stands, so there is nothing to warn about.
func TestCheckpointKeyLenWarnings_FIPSEnforcedRefusesInstead(t *testing.T) {
	forceCheckpointKeyFIPS(t, true)
	opts := Options{CheckpointKey: []byte("short")}
	if w := CheckpointKeyLenWarnings(opts); w != nil {
		t.Fatalf("enforced mode must not warn, got %q", w)
	}
	if err := checkCheckpointKeyLens(opts); !errors.Is(err, ErrCheckpointKeyTooShort) {
		t.Fatalf("enforced mode must still refuse, got %v", err)
	}
}
