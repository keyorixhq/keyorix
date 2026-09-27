// aead_context_binding_fuzz_test.go -- FUZZ-MECH M7a: AEAD key-commitment
// (K3), scoped to what's actually tractable and sound.
//
// Raw AES-256-GCM is mathematically NOT key-committing (Len, Grubbs, Ristenpart,
// Sarkar 2021's "partitioning oracle" construction is a known, general property
// of the primitive, not something to rediscover by random fuzzing -- a real
// collision-finding construction requires solving a GHASH polynomial over
// GF(2^128), which random byte mutation cannot stumble into within any
// practical exec budget, and re-implementing that construction from scratch
// here would risk a subtly wrong "success" or "failure" that misleads more
// than it informs). What this codebase actually relies on for the
// multi-tenant-key-separation property K3 names is the APPLICATION-LAYER
// mitigation: ports.SecretAAD(secretID, projectID, versionNumber) binds every
// encrypted secret value to its own identity tuple. FuzzAEADTamperRoundTrip
// (aead_metamorphic_fuzz_test.go) already covers cross-KEK rejection and
// generic AAD-mismatch rejection with an arbitrary byte AAD; this target
// tests the SPECIFIC construction this codebase actually uses for that
// binding, fuzzing two independent (secretID, projectID, versionNumber)
// tuples and asserting: encrypting under tuple A's AAD, then attempting to
// decrypt (under the SAME key) with tuple B's AAD, succeeds if and only if
// A == B. This is the concrete, practical form of "a ciphertext must not
// open under a different [tenant] context" this system is exposed to --
// sound (assert only the non-false-positive direction: AAD mismatch must
// never wrongly succeed) and tractable via ordinary fuzzing (no GHASH
// polynomial construction needed).
package encryption

import (
	"bytes"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func FuzzAEADContextBinding(f *testing.F) {
	f.Add([]byte("k"), []byte("plaintext"),
		uint32(1), uint32(1), int32(1), uint32(1), uint32(1), int32(1))
	f.Add([]byte("z%"), []byte("longer plaintext for coverage"),
		uint32(1), uint32(2), int32(3), uint32(1), uint32(2), int32(3)) // identical tuple -- must succeed
	f.Add([]byte("key"), []byte("p"),
		uint32(1), uint32(2), int32(3), uint32(1), uint32(2), int32(4)) // version differs
	f.Add([]byte("key"), []byte("p"),
		uint32(1), uint32(2), int32(3), uint32(1), uint32(99), int32(3)) // project differs
	f.Add([]byte("key"), []byte("p"),
		uint32(1), uint32(2), int32(3), uint32(99), uint32(2), int32(3)) // secret ID differs

	f.Fuzz(func(t *testing.T, keySeed, plaintext []byte,
		secretIDA, projectIDA uint32, versionA int32,
		secretIDB, projectIDB uint32, versionB int32) {
		fuzzutil.Guard(t.Fatalf, "AEAD context binding", func() {
			checkAEADContextBinding(keySeed, plaintext,
				uint(secretIDA), uint(projectIDA), int(versionA),
				uint(secretIDB), uint(projectIDB), int(versionB))
		})
	})
}

func checkAEADContextBinding(keySeed, plaintext []byte,
	secretIDA, projectIDA uint, versionA int,
	secretIDB, projectIDB uint, versionB int) {
	key := derive32(keySeed)
	svc, err := NewEncryptionService(key)
	if err != nil {
		panic("NewEncryptionService: " + err.Error())
	}

	aadA := ports.SecretAAD(secretIDA, projectIDA, versionA)
	aadB := ports.SecretAAD(secretIDB, projectIDB, versionB)
	sameTuple := secretIDA == secretIDB && projectIDA == projectIDB && versionA == versionB

	enc, err := svc.EncryptWithAAD(plaintext, "v1", aadA)
	if err != nil {
		panic("EncryptWithAAD: " + err.Error())
	}

	gotWithA, err := svc.DecryptWithAAD(enc, aadA)
	if err != nil {
		panic("DecryptWithAAD with the SAME AAD it was encrypted under failed: " + err.Error())
	}
	if !bytes.Equal(gotWithA, plaintext) {
		panic("round-trip under the same AAD returned a different plaintext")
	}

	gotWithB, errB := svc.DecryptWithAAD(enc, aadB)
	if sameTuple {
		if errB != nil {
			panic("two identical (secretID,projectID,version) tuples produced AAD values that did not round-trip: " + errB.Error())
		}
		if !bytes.Equal(gotWithB, plaintext) {
			panic("identical-tuple decrypt returned a different plaintext")
		}
		return
	}
	// CONTEXT-BINDING VIOLATION: any of the three identity components
	// differing must make decryption fail outright -- a ciphertext
	// encrypted for one secret/project/version must never be accepted as
	// belonging to a different one, even under the correct key.
	if errB == nil {
		panic("a ciphertext bound to one (secretID,projectID,version) AAD tuple decrypted successfully under a DIFFERENT tuple")
	}
}
