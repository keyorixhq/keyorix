package libconformance

// FuzzPKCS7DecryptUsingPSK fuzzes (*PKCS7).DecryptUsingPSK — the PSK
// (pre-shared-key) decryption entry point.
//
// # Risk context (from LS1 inventory)
//
// DecryptUsingPSK takes a raw []byte PSK directly and passes it into DES/AES
// cipher construction.  The LS1 inventory flagged this function as "A*"
// (alloc-in-callee): it allocates from the ciphertext inside the private
// decrypt() helper, the same allocation class as the BER memory-exhaustion
// DoS (GHSA-3xqc-rpq8-wgp9) that was in pkcs7.Parse.  The allocation in
// Parse's BER path is bounded by the three existing Parse harnesses; this
// harness verifies the same property for the decrypt path.
//
// # Fuzz strategy
//
// Both envelope bytes AND PSK bytes are fuzzed together.  This is cheaper
// than a split "fixed-envelope, fuzz PSK" approach and covers more surface:
//   - Fuzz envelope → exercises the BER decode and compound-EncryptedContent
//     assembly path inside decrypt().
//   - Fuzz PSK  → exercises DES/AES cipher construction with arbitrary-length
//     keys; wrong key sizes return an error from the cipher constructor (not a
//     panic), which is the expected behavior.
//   - Seed: a valid DES-CBC-encrypted envelope with an 8-byte PSK, so the
//     fuzzer starts with a real decrypt exercising the happy path.
//
// # Oracle
//
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//   - Bounded allocation: TotalAlloc during Parse+DecryptUsingPSK must stay
//     within 64 MiB + 4 KiB·N of the envelope size.  This envelope catches a
//     regression to the GHSA-3xqc-rpq8-wgp9 allocation class if it were ever
//     introduced into the decryption path.
//
// # What this oracle does NOT verify
//
//   - Correctness of the decrypted plaintext
//   - That a wrong PSK returns an error rather than wrong data
//     (authenticated-encryption correctness is out of scope)
//   - Thread safety (each fuzzer iteration is single-threaded by the harness)
//
// # Signature drift check (LS2 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1 inventory:
//
//	func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error)

import (
	"runtime"
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// pskSeedKey is an 8-byte DES key used to build the seed envelope.
// DES-CBC is the default ContentEncryptionAlgorithm in pkcs7.
var pskSeedKey = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// pskSeedContent is the plaintext in the seed envelope.
var pskSeedContent = []byte("ls2-psk-decrypt-fuzz-seed")

// buildPSKSeedEnvelope returns a valid pkcs7 EncryptedData blob encrypted
// with pskSeedKey using the default DES-CBC algorithm.  Called once at
// harness setup; the returned bytes are used as a seed for the fuzzer.
func buildPSKSeedEnvelope(tb testing.TB) []byte {
	tb.Helper()
	env, err := pkcs7.EncryptUsingPSK(pskSeedContent, pskSeedKey)
	if err != nil {
		tb.Fatalf("buildPSKSeedEnvelope: EncryptUsingPSK: %v", err)
	}
	return env
}

// FuzzPKCS7DecryptUsingPSK fuzzes the PSK decrypt path with arbitrary
// envelope bytes and arbitrary PSK bytes.
func FuzzPKCS7DecryptUsingPSK(f *testing.F) {
	seedEnv := buildPSKSeedEnvelope(f)

	// Seed 0: good envelope, correct 8-byte DES key → exercises the happy path.
	f.Add(seedEnv, pskSeedKey)
	// Seed 1: good envelope, wrong key → error from cipher, not panic.
	f.Add(seedEnv, []byte("wrongkey"))
	// Seed 2: good envelope, empty key → error, not panic.
	f.Add(seedEnv, []byte{})
	// Seed 3: minimal DER SEQUENCE, valid key → ErrNotEncryptedContent or parse error.
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, pskSeedKey)
	// Seed 4: BER-ish prefix (matches existing pkcs7 Parse seeds).
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"), pskSeedKey)
	// Seed 5: empty envelope.
	f.Add([]byte{}, pskSeedKey)

	f.Fuzz(func(t *testing.T, envelope []byte, psk []byte) {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		// Parse is a prerequisite: DecryptUsingPSK operates on a *PKCS7.
		// Parse itself is bounded by FuzzDigitorusPKCS7BoundedWork; here we
		// only measure the ADDITIONAL allocation from DecryptUsingPSK.
		p7, err := pkcs7.Parse(envelope)

		runtime.ReadMemStats(&m1)
		allocParse := m1.TotalAlloc - m0.TotalAlloc

		if err != nil {
			return // parse failure expected for most inputs; not our oracle
		}

		runtime.ReadMemStats(&m0)
		fuzzutil.Guard(t.Fatalf, "pkcs7.DecryptUsingPSK", func() {
			_, _ = p7.DecryptUsingPSK(psk)
		})
		runtime.ReadMemStats(&m1)
		allocDecrypt := m1.TotalAlloc - m0.TotalAlloc

		// Total allocation from parse+decrypt must stay within the envelope.
		totalAlloc := allocParse + allocDecrypt
		limit := uint64(64<<20) + uint64(4096)*uint64(len(envelope))
		if totalAlloc > limit {
			t.Fatalf("BOUNDED-WORK: pkcs7.Parse+DecryptUsingPSK allocated %d bytes for a %d-byte envelope (limit %d) — amplification regression",
				totalAlloc, len(envelope), limit)
		}
	})
}
