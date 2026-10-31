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
