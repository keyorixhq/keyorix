// Package aead holds internal/encryption's pure AES-256-GCM core: the
// EncryptionService type and the Encrypt/Decrypt/EncryptWithAAD/
// DecryptWithAAD/EncryptChunked/DecryptChunked operations, plus the
// EncryptedData/EncryptionMetadata wire types and their JSON (de)serializers.
// None of it performs I/O, storage, KMS/TPM, or network calls — it operates
// entirely on caller-supplied key and plaintext bytes.
//
// It exists so these operations can be fuzzed cheaply. Go's fuzzer tracks
// coverage over every package the test binary links, and each input costs
// several passes over that coverage map. A fuzz target in package encryption
// links encryption's whole dependency tree (internal/crypto's TPM/KMS/exec
// key-provider machinery, pulled in only for the DefaultKEKIterations
// constant and GenerateKEK — neither used by the AEAD core); the same target
// here links only the standard library, and runs many times more inputs per
// second (see internal/core/rules' doc.go for the measured shape of this
// effect elsewhere in this codebase).
//
// Rules for this package:
//   - It must stay a leaf: it may import only the standard library — nothing
//     else from this module. TestAEADStaysALeaf enforces this.
//   - Package encryption keeps its public API via type aliases and thin
//     wrapper functions (encryption/aead_compat.go), so callers don't change.
//   - WipeDEK exists because internal/encryption/service_rotation.go zeroes
//     an EncryptionService's DEK directly on rotation/shutdown; dek is
//     unexported, so that access can no longer cross the package boundary
//     once EncryptionService lives here — WipeDEK is the same zeroing loop,
//     exported.
package aead
