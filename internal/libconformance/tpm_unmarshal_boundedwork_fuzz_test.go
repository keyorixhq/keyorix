package libconformance

import (
	"runtime"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzTPMUnmarshalBoundedWork transfers the digitorus/pkcs7 BER out-of-bounds
// panic AND the length-bomb classes to google/go-tpm's tpm2.Unmarshal — the TPM
// wire decoder Keyorix reaches from internal/crypto/tpm_provider.go:
//
//	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
//	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob.Private)
//
// where blob is json.Unmarshal'ed from the on-disk sealed-KEK blob
// (tpmSealedBlob). The TPM wire format is a sequence of length-prefixed TPM2B
// buffers (a uint16 size then that many bytes) and tagged unions — exactly the
// shape the pkcs7 OOB panic lived in: a declared size larger than the remaining
// buffer, or a union selector that indexes a type the rest of the buffer cannot
// satisfy. The live caller passes bytes that are attacker-controlled the moment
// the sealed-blob file is writable (a compromised/rolled-back KEK file), so a
// panic here is a crash-on-startup DoS, and a length-bomb is a memory DoS, on the
// TPM KEK-unseal path (ADR-038 tier-2).
//
// Targets the TWO live-reachable types (TPM2BPublic, TPM2BPrivate) plus the
// attestation/quote structures named in the task (TPMTPublic, TPMSAttest,
// TPM2BAttest) — those are not on the sealed-blob path but are the canonical
// TPMT_*/TPMS_ATTEST decoders and share the identical Unmarshal machinery, so a
// bounded-work defect in the shared reader surfaces on whichever type trips it.
//
// Oracle (same shape as the pkcs7 bounded-work targets):
//   - fuzzutil.Guard bounds TIME; a panic inside Unmarshal propagates and is
//     recorded natively — so this is ALSO the never-panic / never-OOB oracle.
//   - the allocation check bounds MEMORY: TotalAlloc across ALL five Unmarshal
//     calls must stay within 64 MiB + 4 KiB·N. A TPM2B whose uint16/uint32 length
//     prefix is honored by a make() before the bytes are read would balloon.
//
// EXPECTED today: go-tpm validates length prefixes against the remaining buffer
// (returns an error, never panics or over-allocates), so this passes. It fires
// only if a bump reintroduces an unchecked length read.
//
// What this does NOT verify:
//   - Nothing about unmarshal CORRECTNESS — not that a valid TPM2BPublic
//     round-trips, not any seal/unseal or PCR-policy semantic. Only bounded work.
//   - Only the sealed-blob types are LIVE-reachable in Keyorix today; TPMSAttest /
//     TPM2BAttest / TPMTPublic are decoded here for coverage of the shared reader,
//     NOT because a live Keyorix caller drives them (go-tpm-tools attestation
//     verification is present in the module graph but has no traced live caller).
//     A hit confined to one of those three is an UPSTREAM finding, not a Keyorix
//     reachability claim — triage must say which type tripped.
//   - The 64 MiB floor tolerates constant-factor over-allocation; it catches a
//     length-prefix-driven blow-up, not a 2x inefficiency.
//   - It does not model the stateful tpm2.Unmarshal of nested unions beyond the
//     top-level type dispatch these five exercise.
func FuzzTPMUnmarshalBoundedWork(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})                         // TPM2B with zero length
	f.Add([]byte{0xff, 0xff})                         // TPM2B length 65535, no payload (short)
	f.Add([]byte{0x00, 0x04, 0x00, 0x0b, 0x00, 0x22}) // plausible TPMT_PUBLIC head
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})             // oversized union/length head
	f.Add([]byte{0xff, 0x54, 0x43, 0x47, 0x80, 0x18}) // TPM_GENERATED-ish attest head

	f.Fuzz(func(t *testing.T, data []byte) {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		fuzzutil.Guard(t.Fatalf, "tpm2.Unmarshal(TPM2B*/TPMT*/TPMS*)", func() {
			_, _ = tpm2.Unmarshal[tpm2.TPM2BPublic](data)  // LIVE caller type
			_, _ = tpm2.Unmarshal[tpm2.TPM2BPrivate](data) // LIVE caller type
			_, _ = tpm2.Unmarshal[tpm2.TPMTPublic](data)
			_, _ = tpm2.Unmarshal[tpm2.TPMSAttest](data)
			_, _ = tpm2.Unmarshal[tpm2.TPM2BAttest](data)
		})

		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(64<<20) + uint64(4096)*uint64(len(data))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: tpm2.Unmarshal allocated %d bytes for a %d-byte input (limit %d) — length-prefix amplification regression",
				alloc, len(data), limit)
		}
	})
}
