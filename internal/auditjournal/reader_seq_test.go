package auditjournal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeSegment writes records encoded with the given seqs, chained from
// prev, as one segment file named for startSeq. Returns the chain head.
func writeSegment(t *testing.T, dir string, startSeq uint64, seqs []uint64, prev [32]byte) [32]byte {
	t.Helper()
	var buf []byte
	for _, s := range seqs {
		enc, next := encodeRecord(s, []byte("payload"), prev)
		buf = append(buf, enc...)
		prev = next
	}
	if err := os.WriteFile(filepath.Join(dir, segmentName(startSeq)), buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return prev
}

// TestValidate_SeqMustMatchPosition: the local hash chain does not cover a
// record's seq, so a record with a valid chain and CRC but a rewritten seq
// is otherwise indistinguishable from a good one. A lowered seq would sit
// below the store's replay cursor and never reach audit_events. Validate
// must refuse it as corruption, whatever its position.
func TestValidate_SeqMustMatchPosition(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"rewritten seq mid-journal": func(t *testing.T, dir string) {
			writeSegment(t, dir, 0, []uint64{0, 0, 2}, genesisLocalHash)
		},
		"rewritten seq at tail": func(t *testing.T, dir string) {
			writeSegment(t, dir, 0, []uint64{0, 1, 7}, genesisLocalHash)
		},
		"first record not seq 0": func(t *testing.T, dir string) {
			writeSegment(t, dir, 3, []uint64{3, 4}, genesisLocalHash)
		},
		"segment name disagrees with its first record": func(t *testing.T, dir string) {
			head := writeSegment(t, dir, 0, []uint64{0, 1}, genesisLocalHash)
			writeSegment(t, dir, 5, []uint64{2, 3}, head)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			build(t, dir)
			_, err := Validate(dir)
			var ce *CorruptionError
			if !errors.As(err, &ce) || !errors.Is(err, ErrSeqMismatch) {
				t.Fatalf("Validate = %v, want *CorruptionError wrapping ErrSeqMismatch", err)
			}
		})
	}

	t.Run("contiguous seqs across segments are accepted", func(t *testing.T) {
		dir := t.TempDir()
		head := writeSegment(t, dir, 0, []uint64{0, 1}, genesisLocalHash)
		writeSegment(t, dir, 2, []uint64{2, 3}, head)
		res, err := Validate(dir)
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if res.NextSeq != 4 || len(res.Records) != 4 {
			t.Fatalf("NextSeq=%d records=%d, want 4/4", res.NextSeq, len(res.Records))
		}
	})
}
