package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// unsealWithRewrittenResponse seals a fixed KEK on a fresh simulator, then
// unseals it with the Unseal response passed through rewrite. It returns what
// TPMKeyProvider.unseal returned and the response the provider saw.
func unsealWithRewrittenResponse(t *testing.T, rewrite func([]byte) []byte) (out, rsp []byte, err error) {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(77)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sim.Close() }()
	ident := &hostileTPM{inner: transport.FromReadWriter(sim), mutate: func(b []byte) []byte { return b }}
	p := &TPMKeyProvider{open: func() (transport.TPMCloser, error) { return ident, nil }}
	blob, err := p.seal(bytes.Repeat([]byte{0x5A}, KEKSize))
	if err != nil {
		t.Fatal(err)
	}
	h := &hostileTPM{inner: transport.FromReadWriter(sim), targetCC: tpmCCUnseal, mutate: rewrite}
	p.open = func() (transport.TPMCloser, error) { return h, nil }
	out, err = p.unseal(blob)
	return out, h.gotRsp, err
}

// TestTPMFindingShortParamsAreSuccess pins finding TP1-TPM-short-params in
// google/go-tpm v0.9.8: rspParameters (tpm2/reflect.go) returns nil without
// decoding when the response parameter area is shorter than 2 bytes, so an
// Unseal response with parameterSize 0 and a valid password-session area is a
// success with an empty outData. TPM 2.0 Part 3 §12.7 makes outData mandatory.
// Keyorix reach: TPMKeyProvider.unseal returns the empty slice without error;
// KEK()'s validateKEK then rejects it (length 0 != 32), so the provider still
// fails closed. This test goes red when go-tpm rejects the short area; then
// delete tpmShortParams with it.
func TestTPMFindingShortParamsAreSuccess(t *testing.T) {
	out, rsp, err := unsealWithRewrittenResponse(t, func(r []byte) []byte {
		// header(10) | parameterSize(4) | params | sessions: drop the params.
		ps := binary.BigEndian.Uint32(r[10:14])
		short := append(append([]byte{}, r[:10]...), 0, 0, 0, 0)
		short = append(short, r[14+ps:]...)
		binary.BigEndian.PutUint32(short[2:6], uint32(len(short)))
		return short
	})
	if err != nil {
		t.Fatalf("go-tpm now rejects an empty Unseal parameter area (%v): finding fixed, remove tpmShortParams\n rsp=%x", err, rsp)
	}
	if len(out) != 0 {
		t.Fatalf("empty parameter area produced outData %x: the model of the finding is wrong", out)
	}
	if _, kerr := validateKEK(out, "tpm"); kerr == nil {
		t.Fatal("validateKEK accepted the empty outData: keyorix no longer fails closed here")
	}
}

// TestTPMFindingResponseHeaderUnchecked pins finding TP1-TPM-rsp-header-unchecked
// in google/go-tpm v0.9.8: rspHeader reads the response tag and responseSize and
// checks neither (only responseCode). A response with tag 0x0000 and
// responseSize 0xFFFFFFFF still unseals the genuine KEK. EXPECTED-DIFFERENCE /
// HARDENING: the body is still parsed strictly (session area, no trailing
// bytes), so no value changes; the TPM is the trusted party. This test goes red
// when go-tpm starts checking the header.
func TestTPMFindingResponseHeaderUnchecked(t *testing.T) {
	out, _, err := unsealWithRewrittenResponse(t, func(r []byte) []byte {
		binary.BigEndian.PutUint16(r[0:2], 0)
		binary.BigEndian.PutUint32(r[2:6], 0xFFFFFFFF)
		return r
	})
	if err != nil {
		t.Fatalf("go-tpm now checks the response header (%v): finding fixed", err)
	}
	if !bytes.Equal(out, bytes.Repeat([]byte{0x5A}, KEKSize)) {
		t.Fatalf("bad header changed the unsealed value to %x", out)
	}
}

// TestTPMFindingTruncatedSizeAccepted pins finding TP1-TPM-truncated-size in
// google/go-tpm v0.9.8: TPM2B.unmarshal (tpm2/tpm2b.go) discards the error from
// binary.Read of its 2-byte size field, so an empty or 1-byte input decodes,
// without error, as an empty TPM2B. The same happens to a TPM2B nested at the end
// of a structure: FuzzTPMSealedBlobDecode found a TPMT_PUBLIC whose trailing
// "unique" TPM2B_DIGEST has a 1-byte size field (testdata 2ebca50f1c116e94).
// B1 and B2 excuse exactly this shape (tpmTruncatedSizeTail). This test goes red
// when go-tpm starts rejecting a truncated size field; then delete
// tpmTruncatedSizeTail with it.
//
// Keyorix reach: the sealed-blob file {} (or "public": "", or a 1-byte field)
// passes the decode step of TPMKeyProvider.unseal and reaches the TPM. The second
// half of this test drives the real KEK() path against the simulator and shows the
// TPM's Load rejects it, so the provider still fails closed; the only effect is
// that the error names Load, not the decode.
//
// What this does NOT verify: other go-tpm types with a size prefix decode the
// same way (only TPM2BPublic and TPM2BPrivate, the two keyorix decodes, are
// checked).
func TestTPMFindingTruncatedSizeAccepted(t *testing.T) {
	for _, in := range [][]byte{nil, {0x05}} {
		pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](in)
		priv, err2 := tpm2.Unmarshal[tpm2.TPM2BPrivate](in)
		if err != nil || err2 != nil {
			t.Fatalf("go-tpm now rejects the truncated size field %x (%v, %v): finding fixed, remove tpmTruncatedSizeField", in, err, err2)
		}
		if len(pub.Bytes()) != 0 || len(priv.Buffer) != 0 {
			t.Fatalf("truncated %x decoded to non-empty contents: the model of the finding is wrong", in)
		}
	}
	// Nested: KEYEDHASH, nameAlg 0x0d34, attributes, empty authPolicy, scheme
	// NULL, then a 1-byte "size" for the unique TPM2B_DIGEST.
	nested := []byte{0x00, 0x08, 0x0d, 0x34, 0xd3, 0x4d, 0x34, 0xd0, 0x00, 0x00, 0x00, 0x10, 0x34}
	inner, err := tpm2.Unmarshal[tpm2.TPMTPublic](nested)
	if err != nil {
		t.Fatalf("go-tpm now rejects the nested truncated size field (%v): finding fixed, remove tpmTruncatedSizeTail", err)
	}
	if m := tpm2.Marshal(*inner); !bytes.Equal(m, append(append([]byte{}, nested[:len(nested)-1]...), 0, 0)) {
		t.Fatalf("nested case re-marshals as %x: the model of the finding is wrong", m)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kek.tpm"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newTPMProvider(t, dir, 7).KEK()
	if err == nil {
		t.Fatal("KEK() unsealed an empty sealed blob: fail-closed property broken")
	}
	if !strings.Contains(err.Error(), "load sealed object") {
		t.Fatalf("empty blob failed at %q, not at the TPM Load: the reach trace above is stale", err)
	}
}

// TestTPMFindingLegacyLaxSelector pins TP1-TPM-legacy-lax-selector
// (EXPECTED-DIFFERENCE, found by FuzzTPMTPublicLegacyDifferential, testdata
// 3ad0110a1f55f254): legacy/tpm2.DecodePublic accepts a SYMCIPHER TPMT_PUBLIC
// whose symmetric algorithm is 0x3030, which no TPM defines; tpm2.Unmarshal
// rejects it. Keyorix uses only the tpm2 decoder, which is the strict one, so
// nothing in keyorix depends on the legacy reading. This test goes red if either
// decoder changes its answer.
func TestTPMFindingLegacyLaxSelector(t *testing.T) {
	in := []byte{0x00, 0x25, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30}
	_, nerr := tpm2.Unmarshal[tpm2.TPMTPublic](in)
	_, lerr := legacy.DecodePublic(in)
	if nerr == nil || lerr != nil || !legacyLaxSelector(nerr, lerr) {
		t.Fatalf("tpm2 err=%v, legacy err=%v: the decoders no longer differ this way, remove legacyLaxSelector", nerr, lerr)
	}
}

// TestTPMFindingLegacyRSAESMisread pins TP1-TPM-legacy-rsaes, an upstream DEFECT
// in google/go-tpm v0.9.8 legacy/tpm2 found by FuzzTPMTPublicLegacyDifferential
// (testdata 1ab57a4c8c393042): decodeSigScheme reads a 2-byte hashAlg after every
// non-NULL scheme, but TPMS_ENC_SCHEME_RSAES (TPM 2.0 Part 2 §11.2.3.2) is empty,
// so a well-formed RSA public with scheme RSAES is misread: the next two bytes
// (keyBits) are taken as the hash and everything after shifts. Keyorix does not
// import legacy/tpm2 (only this test does), so there is no keyorix reach. This
// test goes red when the legacy decoder reads RSAES correctly.
func TestTPMFindingLegacyRSAESMisread(t *testing.T) {
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, Decrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme:  tpm2.TPMAlgRSAES,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAES, &tpm2.TPMSEncSchemeRSAES{}),
			},
			KeyBits: 2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)}),
	}
	in := tpm2.Marshal(pub)
	back, err := tpm2.Unmarshal[tpm2.TPMTPublic](in)
	if err != nil || !bytes.Equal(tpm2.Marshal(*back), in) {
		t.Fatalf("harness: tpm2 does not round-trip its own RSAES public (%v)", err)
	}
	if !legacySchemeMisread(in) {
		t.Fatal("harness: legacySchemeMisread does not recognise a well-formed RSAES public")
	}
	lp, lerr := legacy.DecodePublic(in)
	if lerr == nil && lp.RSAParameters != nil && lp.RSAParameters.KeyBits == 2048 && len(lp.RSAParameters.ModulusRaw) == 256 {
		t.Fatal("legacy now decodes an RSAES public correctly: finding fixed, remove legacySchemeMisread")
	}
	if lerr == nil && lp.RSAParameters != nil {
		t.Logf("legacy.DecodePublic on a valid RSAES public: no error, KeyBits=%d (want 2048), scheme hash=%#x, modulus %d bytes (want 256)",
			lp.RSAParameters.KeyBits, uint16(lp.RSAParameters.Sign.Hash), len(lp.RSAParameters.ModulusRaw))
		return
	}
	t.Logf("legacy.DecodePublic on a valid RSAES public: err=%v", lerr)
}

// TestTPMFindingLegacyECDAACount pins TP1-TPM-legacy-ecdaa-count, an upstream
// DEFECT in google/go-tpm v0.9.8 legacy/tpm2 (found by
// FuzzTPMTPublicLegacyDifferential, testdata 441d256acb7fe83f): legacy SigScheme
// decodes an ECDAA scheme's count as a uint32, TPM 2.0 Part 2 §11.2.1.3 defines
// it as UINT16 (tpm2.TPMSSchemeECDAA has it right). A well-formed ECDAA ECC
// public therefore misdecodes in legacy. No keyorix reach (keyorix does not
// import legacy/tpm2). Goes red when legacy reads it correctly.
func TestTPMFindingLegacyECDAACount(t *testing.T) {
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDAA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDAA, &tpm2.TPMSSchemeECDAA{HashAlg: tpm2.TPMAlgSHA256, Count: 7}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
	in := tpm2.Marshal(pub)
	if !legacySchemeMisread(in) {
		t.Fatal("harness: the scheme exclusion does not recognise a well-formed ECDAA public")
	}
	lp, lerr := legacy.DecodePublic(in)
	if lerr == nil && lp.ECCParameters != nil && lp.ECCParameters.Sign != nil && lp.ECCParameters.Sign.Count == 7 &&
		len(lp.ECCParameters.Point.XRaw) == 32 {
		t.Fatal("legacy now decodes an ECDAA scheme correctly: finding fixed, drop ECDAA from legacySchemeMisread")
	}
	t.Logf("legacy.DecodePublic on a valid ECDAA public: err=%v", lerr)
}

// TestTPMFindingSymDefObjectXOR pins TP1-TPM-symdef-xor (found by
// FuzzTPMTPublicLegacyDifferential, testdata 25c09b19d4927829): tpm2.Unmarshal
// accepts a SYMCIPHER public whose TPMT_SYM_DEF_OBJECT algorithm is TPM_ALG_XOR,
// which TPMI_ALG_SYM_OBJECT excludes; legacy.DecodePublic rejects the same bytes
// (it reads a mode field XOR does not have). HARDENING at most for keyorix: the
// provider only decodes the public of its own sealed object and the TPM rejects
// such a public at Load. This test goes red when tpm2 rejects XOR there.
func TestTPMFindingSymDefObjectXOR(t *testing.T) {
	in := []byte{0x00, 0x25, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x0a, 0x30, 0x30, 0x00, 0x00}
	_, nerr := tpm2.Unmarshal[tpm2.TPMTPublic](in)
	_, lerr := legacy.DecodePublic(in)
	if nerr != nil || !symDefIsXOR(in) {
		t.Fatalf("tpm2 no longer accepts XOR in TPMT_SYM_DEF_OBJECT (%v): finding fixed, remove symDefIsXOR", nerr)
	}
	if lerr == nil {
		t.Fatal("legacy now accepts it too: update the report")
	}
}

// TestTPMFindingTrailingBytesAccepted pins finding TP1-TPM-trailing-bytes:
// tpm2.Unmarshal stops after the structure and ignores what follows, so a sealed
// blob whose "public" or "private" field carries extra bytes after the TPM2B still
// unseals the genuine KEK through the real KEK() path. Classified
// EXPECTED-DIFFERENCE: the extra bytes are never sent to the TPM (Load re-marshals
// the decoded TPM2B) and the TPM's integrity check covers everything that is sent.
// This test goes red if go-tpm or the provider starts rejecting trailing bytes.
//
// What this does NOT verify: that tolerating the bytes is harmless for a future
// consumer of the blob that reads the raw field (none exists today).
func TestTPMFindingTrailingBytesAccepted(t *testing.T) {
	dir := t.TempDir()
	kek, err := newTPMProvider(t, dir, 11).KEK()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kek.tpm")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blob tpmSealedBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		t.Fatal(err)
	}
	blob.Public = append(blob.Public, 0xDE, 0xAD, 0xBE, 0xEF)
	blob.Private = append(blob.Private, 0x00)
	out, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := newTPMProvider(t, dir, 11).KEK()
	if err != nil {
		t.Fatalf("trailing bytes are now rejected (%v): finding changed, update the report", err)
	}
	if string(got) != string(kek) {
		t.Fatal("trailing bytes changed the unsealed KEK")
	}
}
