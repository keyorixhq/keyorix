package verifierflip_test

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/verifierflip"
)

// FuzzVerifierMutationChain applies a fuzzer-chosen CHAIN of mutations (bit
// flip, truncate, extend, insert, delete, duplicate, swap, reverse) to a valid
// artifact of a fuzzer-chosen verifier and checks the same oracle as
// TestVerifierBitFlip: no panic, and an accepted artifact must be
// ACCEPT-EQUIVALENT (target Canon equal to the original's). Single mutations
// are covered exhaustively by the unit run; chains reach states those cannot.
func FuzzVerifierMutationChain(f *testing.F) {
	informational := map[string]bool{
		"aead-envelope-metadata-informational":                       true,
		"audit-external-anchor-bundle-unsigned-fields-informational": true,
	}
	var ts []verifierflip.Target
	for _, tg := range allTargets(f) {
		if !informational[tg.Name] {
			ts = append(ts, tg)
		}
	}
	for i := range ts {
		f.Add(uint8(i), []byte{0, 0, 1})
		f.Add(uint8(i), []byte{1, 5, 2, 3, 3, 7})
	}
	f.Fuzz(func(t *testing.T, sel uint8, ops []byte) {
		tg := ts[int(sel)%len(ts)]
		b := append([]byte(nil), tg.Artifact...)
		mutated := false
		for i := 0; i+1 < len(ops) && i < 64; i += 2 {
			op, arg := ops[i]%8, int(ops[i+1])
			if len(b) == 0 {
				break
			}
			pos := (arg*257 + i) % len(b)
			switch op {
			case 0:
				b[pos] ^= 1 << uint(arg%8)
			case 1:
				b = b[:pos]
			case 2:
				b = append(b, byte(arg))
			case 3:
				b = append(b[:pos], b[pos+1:]...)
			case 4:
				b = append(b[:pos], append([]byte{byte(arg)}, b[pos:]...)...)
			case 5:
				end := min(len(b), pos+1+arg%16)
				b = append(b, b[pos:end]...)
			case 6:
				j := (pos + 1 + arg) % len(b)
				b[pos], b[j] = b[j], b[pos]
			case 7:
				for l, r := 0, len(b)-1; l < r; l, r = l+1, r-1 {
					b[l], b[r] = b[r], b[l]
				}
			}
			mutated = true
		}
		if !mutated {
			return
		}
		var ok bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC target=%s: %v input=%x", tg.Name, r, b)
				}
			}()
			ok = tg.Verify(append([]byte(nil), b...))
		}()
		if !ok {
			return
		}
		orig := string(tg.Artifact)
		if tg.Canon == nil {
			if string(b) != orig {
				t.Fatalf("ACCEPT-DIFFERENT target=%s (raw bytes differ) input=%x", tg.Name, b)
			}
			return
		}
		if tg.Canon(b) != tg.Canon(tg.Artifact) {
			t.Fatalf("ACCEPT-DIFFERENT target=%s input=%x", tg.Name, b)
		}
	})
}
