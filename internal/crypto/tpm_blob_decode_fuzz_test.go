package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
)

// tpmDecodeAllocCap bounds the heap a single sealed-blob decode may allocate. A
// TPM2B carries a uint16 size, so an honest decode of one field never needs more
// than 64 KiB for the buffer plus a constant amount of reflection bookkeeping; the
// cap is generous on purpose (it detects an unbounded allocation, not a slow one).
const tpmDecodeAllocCap = 1 << 20

// decodeSealedPublic and decodeSealedPrivate are the two decode calls
// TPMKeyProvider.unseal makes on the bytes read from the sealed-blob file, before
// it opens the TPM. They are the seam a red-proof swaps.
var (
	decodeSealedPublic = func(b []byte) (*tpm2.TPM2BPublic, error) {
		return tpm2.Unmarshal[tpm2.TPM2BPublic](b)
	}
	decodeSealedPrivate = func(b []byte) (*tpm2.TPM2BPrivate, error) {
		return tpm2.Unmarshal[tpm2.TPM2BPrivate](b)
	}
)

// FuzzTPMSealedBlobDecode fuzzes the decode step of the TPM KEK provider's unseal
// path (internal/crypto/tpm_provider.go, TPMKeyProvider.unseal): the JSON sealed
// blob at wrapped_key_path is read from disk, and its "public" and "private" byte
// fields go to tpm2.Unmarshal[TPM2BPublic] and tpm2.Unmarshal[TPM2BPrivate]
// (google/go-tpm v0.9.8) before anything is sent to the TPM. Whoever can write that
// file (a restore from backup, a corrupted disk, a local attacker with write access
// to the data directory) controls these bytes.
//
//   - B1 PREFIX ROUND-TRIP: when a decode succeeds, re-marshalling the decoded value
//     gives a prefix of the input. The decoder reported exactly the bytes that are in
//     the file, no invented size and no invented contents. (Trailing bytes after the
//     field are accepted by go-tpm; that is pinned separately by
//     TestTPMFindingTrailingBytesAccepted, not judged here.)
//   - B2 INNER ROUND-TRIP: when the public's inner TPMT_PUBLIC decodes (Contents),
//     re-marshalling it gives a prefix of the inner buffer, so the structure go-tpm
//     reports is the one the TPM will hash into the object's Name.
//   - B3 BOUNDED ALLOCATION: one decode of both fields allocates at most
//     tpmDecodeAllocCap bytes.
//
// The fuzz input is the whole file: it goes through the same encoding/json decode
// into tpmSealedBlob the provider uses, so the fuzzer drives the real file format.
//
// What this does NOT verify: anything the TPM does with the decoded blob (Load
// verifies the private's integrity against the parent and the public's Name; a
// forged or corrupted blob is rejected there, and this target never opens a TPM,
// see FuzzTPMUnsealHostileResponse for the TPM side); the private's inner
// encrypted structure (go-tpm treats TPM2B_PRIVATE as opaque bytes); whether a
// decoded public describes a sensible sealed object (attributes, policy); go-tpm's
// command marshalling; the provider's own decode calls (decodeSealedPublic and
// decodeSealedPrivate mirror tpm_provider.go's two tpm2.Unmarshal calls instead of
// calling unseal, so a change there does not reach this target until the mirror
// is updated). Inputs are capped at 8 KiB per field.
func FuzzTPMSealedBlobDecode(f *testing.F) {
	pub := tpm2.Marshal(tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true,
		},
	}))
	priv := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: bytes.Repeat([]byte{0xA5}, 126)})
	eccPub := tpm2.Marshal(tpm2.New2B(tpm2.ECCSRKTemplate))
	for _, s := range [][2][]byte{
		{pub, priv},
		{eccPub, priv},
		{nil, nil},
		{{0x05}, {0x00}},
		{{0x00, 0x10, 0x00, 0x08}, {0xFF, 0xFF}},
		{append(append([]byte{}, pub...), 0xDE, 0xAD), priv},
	} {
		blob, _ := json.Marshal(tpmSealedBlob{Public: s[0], Private: s[1]})
		f.Add(blob)
	}
	f.Fuzz(func(t *testing.T, file []byte) {
		if len(file) > 24<<10 {
			return
		}
		var blob tpmSealedBlob
		if err := json.Unmarshal(file, &blob); err != nil {
			return // the provider fails closed on this: "corrupt sealed blob"
		}
		if len(blob.Public) > 8<<10 || len(blob.Private) > 8<<10 {
			return
		}
		checkSealedBlobDecode(t, blob.Public, blob.Private)
	})
}

func checkSealedBlobDecode(t *testing.T, pubBytes, privBytes []byte) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	pub, perr := decodeSealedPublic(pubBytes)
	priv, verr := decodeSealedPrivate(privBytes)
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > tpmDecodeAllocCap {
		t.Fatalf("B3 BOUNDED ALLOCATION: decoding %d+%d input bytes allocated %d bytes (cap %d)", len(pubBytes), len(privBytes), n, tpmDecodeAllocCap)
	}
	if perr == nil {
		if m := tpm2.Marshal(*pub); !bytes.HasPrefix(pubBytes, m) && !tpmTruncatedSizeTail(pubBytes, m) {
			t.Fatalf("B1 PREFIX ROUND-TRIP (public): input %x decodes to a value that re-marshals as %x", pubBytes, m)
		}
		if inner, err := pub.Contents(); err == nil {
			raw := pub.Bytes()
			if m := tpm2.Marshal(*inner); !bytes.HasPrefix(raw, m) && !tpmTruncatedSizeTail(raw, m) {
				t.Fatalf("B2 INNER ROUND-TRIP: inner buffer %x decodes to a TPMT_PUBLIC that re-marshals as %x", raw, m)
			}
		}
	}
	if verr == nil {
		if m := tpm2.Marshal(*priv); !bytes.HasPrefix(privBytes, m) && !tpmTruncatedSizeTail(privBytes, m) {
			t.Fatalf("B1 PREFIX ROUND-TRIP (private): input %x decodes to a value that re-marshals as %x", privBytes, m)
		}
	}
}

// tpmTruncatedSizeTail is the named exception for finding TP1-TPM-truncated-size
// (pinned by TestTPMFindingTruncatedSizeAccepted): go-tpm v0.9.8's TPM2B.unmarshal
// ignores the error of reading its 2-byte size field, so a TPM2B that starts with
// 0 or 1 bytes left in the input decodes, without error, as empty. That can only
// happen at the very end of the input (the input has run out), so the
// re-marshalled value is the input minus at most one dangling byte, followed by
// one or more zero size fields. Only that exact shape is excused; every other
// round-trip difference still fails. The excuse is broader than the finding in
// one way, stated here: a defect that appended extra zero size fields after a
// fully consumed input would also be excused.
func tpmTruncatedSizeTail(in, m []byte) bool {
	for r := 0; r <= 1 && r <= len(in); r++ {
		base := in[:len(in)-r]
		if !bytes.HasPrefix(m, base) {
			continue
		}
		rest := m[len(base):]
		if len(rest) >= 2 && len(rest)%2 == 0 && !slices.ContainsFunc(rest, func(b byte) bool { return b != 0 }) {
			return true
		}
	}
	return false
}

// decodeTPMTPublicNew is the seam a red-proof swaps for the go-tpm tpm2 decoder.
var decodeTPMTPublicNew = func(b []byte) (*tpm2.TPMTPublic, error) {
	return tpm2.Unmarshal[tpm2.TPMTPublic](b)
}

// FuzzTPMTPublicLegacyDifferential decodes one TPMT_PUBLIC with the two
// independent decoders inside google/go-tpm v0.9.8: the reflection-based
// tpm2.Unmarshal[TPMTPublic] (the one keyorix's unseal path reaches through
// TPM2BPublic.Contents and Load's Name computation) and the hand-written
// legacy/tpm2.DecodePublic. Both claim to implement TPM 2.0 Part 2 §12.2.4.
//
//   - L1 ACCEPTANCE: for the four object types both decoders support (RSA, ECC,
//     KEYEDHASH, SYMCIPHER), they accept and reject the same inputs.
//   - L2 CONTENT: when both accept, both re-encode (tpm2.Marshal, legacy
//     Public.Encode) to the same bytes, and those bytes are a prefix of the input.
//
// What this does NOT verify: types outside the shared four (the decoders' type
// sets differ by design; inputs with another type are skipped); semantic validity
// (an RSA key with a 3-bit modulus decodes fine in both); trailing bytes (both
// decoders stop after the structure); the TPM's own, stricter, unmarshalling.
// Agreement between two decoders in one module is weaker than agreement with the
// TPM reference implementation: a shared misreading of the spec passes. Inputs are
// capped at 4 KiB.
func FuzzTPMTPublicLegacyDifferential(f *testing.F) {
	for _, tmpl := range []tpm2.TPMTPublic{
		tpm2.ECCSRKTemplate,
		tpm2.RSASRKTemplate,
		{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true,
			},
		},
	} {
		f.Add(tpm2.Marshal(tmpl))
	}
	f.Add([]byte{0x00, 0x25, 0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4<<10 || len(b) < 2 {
			return
		}
		switch tpm2.TPMAlgID(uint16(b[0])<<8 | uint16(b[1])) {
		case tpm2.TPMAlgRSA, tpm2.TPMAlgECC, tpm2.TPMAlgKeyedHash, tpm2.TPMAlgSymCipher:
		default:
			return
		}
		checkTPMTPublicDifferential(t, b)
	})
}

// legacyLaxSelector is the named exception for TP1-TPM-legacy-lax-selector
// (EXPECTED-DIFFERENCE, pinned by TestTPMFindingLegacyLaxSelector): the legacy
// decoder reads union selectors (here the symmetric algorithm of a SYMCIPHER or
// a parent's TPMT_SYM_DEF_OBJECT) without checking them against the algorithms
// the union defines, while tpm2 rejects an unknown selector with "no union member
// for tag". Only that direction and that tpm2 error are excused.
func legacyLaxSelector(nerr, lerr error) bool {
	return nerr != nil && lerr == nil && strings.Contains(nerr.Error(), "no union member for tag")
}

// legacySchemeMisread is the named exclusion for TP1-TPM-legacy-rsaes (DEFECT in
// go-tpm v0.9.8 legacy/tpm2, pinned by TestTPMFindingLegacyRSAESMisread): the
// legacy decodeSigScheme reads a hashAlg for every non-NULL RSA scheme, but
// TPMS_ENC_SCHEME_RSAES has no fields, so every RSA public with scheme RSAES is
// misread by the legacy decoder. tpm2 also accepts RSAES as an ECC scheme
// (TPMI_ALG_ECC_SCHEME excludes it; tpm2 shares one asym-scheme union for
// both), found as private fuzz-corpus seed f190c11635016535, and legacy misreads that the same
// way. Such inputs are skipped, whichever decoder
// accepts them: the two cannot be compared there. The scheme is read from the
// raw bytes, after the symmetric definition (2 bytes for NULL, 6 otherwise;
// XOR is excluded separately).
func legacySchemeMisread(b []byte) bool {
	if len(b) < 10 {
		return false
	}
	switch tpm2.TPMAlgID(binary.BigEndian.Uint16(b[0:2])) {
	case tpm2.TPMAlgRSA, tpm2.TPMAlgECC:
	default:
		return false
	}
	off := 10 + int(binary.BigEndian.Uint16(b[8:10]))
	if len(b) < off+2 {
		return false
	}
	if tpm2.TPMAlgID(binary.BigEndian.Uint16(b[off:off+2])) == tpm2.TPMAlgNull {
		off += 2
	} else {
		off += 6
	}
	if len(b) < off+2 {
		return false
	}
	switch tpm2.TPMAlgID(binary.BigEndian.Uint16(b[off : off+2])) {
	case tpm2.TPMAlgRSAES:
		return true
	case tpm2.TPMAlgECDAA:
		// TP1-TPM-legacy-ecdaa-count (pinned by TestTPMFindingLegacyECDAACount):
		// legacy SigScheme.Count is a uint32; TPMS_SCHEME_ECDAA.count is a
		// UINT16 (Part 2 §11.2.1.3), so legacy misreads every ECDAA scheme.
		// Found as private fuzz-corpus seed 441d256acb7fe83f.
		return true
	}
	return false
}

// symDefIsXOR is the named exclusion for TP1-TPM-symdef-xor (pinned by
// TestTPMFindingSymDefObjectXOR): tpm2 accepts TPM_ALG_XOR as the algorithm of a
// TPMT_SYM_DEF_OBJECT, which TPMI_ALG_SYM_OBJECT (Part 2 §9.30) does not allow,
// and decodes XOR's 2-byte hash in the keyBits slot with no mode; the legacy
// decoder always reads algorithm, keyBits and mode. Neither reading is the
// spec's (the TPM rejects the value), so the decoders are not compared there,
// whichever of them accepts. The selector is read from the raw bytes: for
// SYMCIPHER, RSA and ECC the TPMT_SYM_DEF_OBJECT is the first parameter, right
// after type, nameAlg, objectAttributes and the authPolicy TPM2B.
func symDefIsXOR(b []byte) bool {
	switch tpm2.TPMAlgID(binary.BigEndian.Uint16(b[0:2])) {
	case tpm2.TPMAlgSymCipher, tpm2.TPMAlgRSA, tpm2.TPMAlgECC:
	default:
		return false
	}
	if len(b) < 10 {
		return false
	}
	off := 10 + int(binary.BigEndian.Uint16(b[8:10]))
	return len(b) >= off+2 && tpm2.TPMAlgID(binary.BigEndian.Uint16(b[off:off+2])) == tpm2.TPMAlgXOR
}

func checkTPMTPublicDifferential(t *testing.T, b []byte) {
	t.Helper()
	np, nerr := decodeTPMTPublicNew(b)
	lp, lerr := legacy.DecodePublic(b)
	// tpm2 accepting what legacy rejects is excused only when tpm2's reading
	// is the known truncated-size shape (TP1-TPM-truncated-size): the input
	// ran out where a trailing TPM2B's size field should be.
	truncated := nerr == nil && lerr != nil && tpmTruncatedSizeTail(b, tpm2.Marshal(*np))
	if legacySchemeMisread(b) {
		return // TP1-TPM-legacy-rsaes, pinned by TestTPMFindingLegacyRSAESMisread
	}
	if symDefIsXOR(b) {
		return // TP1-TPM-symdef-xor, pinned by TestTPMFindingSymDefObjectXOR
	}
	if (nerr == nil) != (lerr == nil) && !legacyLaxSelector(nerr, lerr) && !truncated {
		t.Fatalf("L1 ACCEPTANCE: tpm2 err=%v, legacy err=%v on %x", nerr, lerr, b)
	}
	if nerr != nil || lerr != nil {
		return // both rejected, or an excused one-sided acceptance above
	}
	nb := tpm2.Marshal(*np)
	lb, err := lp.Encode()
	if err != nil {
		t.Fatalf("L2 CONTENT: legacy accepted %x but cannot re-encode it: %v", b, err)
	}
	if !bytes.Equal(nb, lb) {
		t.Fatalf("L2 CONTENT: input %x\n tpm2   re-encodes as %x\n legacy re-encodes as %x", b, nb, lb)
	}
	if !bytes.HasPrefix(b, nb) {
		t.Fatalf("L2 CONTENT: both decoders re-encode %x as %x, not a prefix of the input", b, nb)
	}
}
