package auditjournal

import "testing"

// FuzzDecodeRecord feeds arbitrary bytes to decodeRecord -- the one
// genuinely new attack surface ADR-115 introduces: Validate/Open treat a
// local journal file (and, in a corrupted/adversarial-disk scenario, every
// byte in it) as data this process itself wrote, but a disk fault, a bug
// elsewhere, or deliberate tampering can hand it anything. decodeRecord
// must never panic and must never allocate more than maxPayloadLen for
// attacker-controlled input -- garbage in, a typed error out, always.
//
// Seeded with a real encoded record (genesis-chained) so the fuzzer starts
// from genuine structure to mutate, plus a handful of adversarial shapes
// (empty input, a too-small header, a payload_len claiming more than
// maxPayloadLen, and a truncated real record) that previously would have
// been the kind of input a hand-rolled parser gets wrong.
func FuzzDecodeRecord(f *testing.F) {
	good, _ := encodeRecord(0, []byte("seed-payload"), genesisLocalHash)
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2})
	f.Add(good[:len(good)-1])
	f.Add(good[:20])

	tooLarge := make([]byte, 16)
	tooLarge[0], tooLarge[1], tooLarge[2], tooLarge[3] = 0x4B, 0x41, 0x4A, 0x31 // recordMagic
	tooLarge[12], tooLarge[13], tooLarge[14], tooLarge[15] = 0xFF, 0xFF, 0xFF, 0xFF
	f.Add(tooLarge)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decodeRecord panicked on input %q: %v", data, r)
			}
		}()
		rec, consumed, err := decodeRecord(data, genesisLocalHash)
		if err == nil {
			if consumed <= 0 || consumed > len(data) {
				t.Fatalf("decodeRecord reported success with invalid consumed=%d (len(data)=%d)", consumed, len(data))
			}
			if len(rec.Payload) > maxPayloadLen {
				t.Fatalf("decodeRecord accepted a payload larger than maxPayloadLen: %d", len(rec.Payload))
			}
		}
		// Also exercise selfConsistent (used by Validate's resync scan) on
		// the same input -- it must never panic either, and must agree
		// with decodeRecord's own success/ErrChainMismatch classification.
		sc := selfConsistent(data)
		if err == nil && !sc {
			t.Fatalf("selfConsistent disagreed with decodeRecord: decode succeeded but selfConsistent=false")
		}
	})
}
