package webauthnrp

// LIB-FUZZ-2 target 1a: the WebAuthn "tpm" attestation statement, driven through
// keyorix's own relying-party wrapper (relyingParty.FinishRegistration).
//
// Inventory. The statement is attacker-controlled: any logged-in user who passes
// the registration re-authentication posts a navigator.credentials.create()
// response, so attStmt.{ver,alg,sig,x5c,certInfo,pubArea} reach go-webauthn's
// attestationFormatValidationTPM, which hands certInfo and pubArea to go-tpm
// (tpm2.Unmarshal[TPMSAttest] / [TPMTPublic], ObjectName) and x5c to crypto/x509.
// FuzzWebAuthnRegistrationCeremony (webauthnparse) already reaches the format, but
// its "tpm" seed is a placeholder that dies on the first TPM parse, so the checks
// behind it (extraData, Name match, AIK signature, certificate rules) were never
// exercised. These seeds are a complete, valid ceremony, so one mutated field at
// a time lands behind every earlier check.
//
// Two modes, because keyorix and the rejection oracle need different things:
//   - FuzzTPMAttestationRegistration runs the RP exactly as keyorix builds it
//     (webauthnrp.New, no metadata provider). The library then performs no chain
//     validation at all, so the oracle checks the facts the statement itself
//     signs: certInfo.extraData, the pubArea Name, the pubArea key, the AIK
//     signature and the RFC 8.3.1 certificate rules.
//   - FuzzTPMAttestationTrustRoot adds a metadata provider whose only trust
//     anchor is a root the harness owns (webauthnrp.Wrap on a library RP), the
//     one setting in which "a mutated attestation must never verify" is a sound
//     claim about the certificate too.
//
// The oracle (checkTPMAccepted) is independent of go-webauthn and go-tpm for
// every decision it makes: it has its own TPMS_ATTEST reader and does its own
// hashing and signature check. TestTPMOracle_RedProof plants acceptances of
// forged statements and requires the oracle to refuse each one.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // TPM Name hash for nameAlg SHA-1, test oracle only
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

const (
	tpmRPID   = "localhost"
	tpmOrigin = "https://localhost"
)

var (
	tpmChallengeRaw = bytes.Repeat([]byte{0xC7}, 32)
	tpmChallenge    = base64.RawURLEncoding.EncodeToString(tpmChallengeRaw)
	tpmUserID       = []byte("keyorix-tpm-fuzz-user-0001")
	tpmCredID       = bytes.Repeat([]byte{0x5A}, 32)
)

func tpmDetKey(tb testing.TB, label string) *ecdsa.PrivateKey {
	tb.Helper()
	d := sha256.Sum256([]byte("keyorix webauthnrp tpm fuzz " + label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// tpmFixture is one complete, valid TPM-attested registration plus the harness's
// trust root. Every byte is derived from fixed keys and a fixed challenge, so a
// saved crasher (which carries all five statement fields) replays exactly.
type tpmFixture struct {
	credKey                     *ecdsa.PrivateKey
	root                        *x509.Certificate
	authData, clientData        []byte
	certInfo, pubArea, sig, aik []byte
}

func newTPMFixture(tb testing.TB) *tpmFixture {
	tb.Helper()
	return newTPMFixtureWithAIK(tb, tpmDetKey(tb, "aik"))
}

// newTPMFixtureWithAIK is newTPMFixture with the AIK key of the caller's choice
// (an RSA AIK, a P-384 AIK). The AIK signs certInfo with SHA-256: PKCS #1 v1.5
// for RSA, ASN.1 ECDSA for an EC key.
func newTPMFixtureWithAIK(tb testing.TB, aikKey crypto.Signer) *tpmFixture {
	tb.Helper()
	fx := &tpmFixture{credKey: tpmDetKey(tb, "credential"), clientData: tpmClientData(tb)}
	fx.authData = tpmAuthData(tb, fx.credKey)

	// pubArea: the TPMT_PUBLIC the TPM certified, carrying the credential key.
	raw, err := fx.credKey.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		tb.Fatal(err)
	}
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   tpm2.TPMECCNistP256,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: raw[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: raw[33:65]},
		}),
	}
	fx.pubArea = tpm2.Marshal(pub)
	name, err := tpm2.ObjectName(&pub)
	if err != nil {
		tb.Fatal(err)
	}

	// certInfo: TPMS_ATTEST certify whose extraData binds authData || H(clientData).
	cdh := sha256.Sum256(fx.clientData)
	extra := sha256.Sum256(append(append([]byte{}, fx.authData...), cdh[:]...))
	fx.certInfo = tpm2.Marshal(tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestCertify,
		QualifiedSigner: tpm2.TPM2BName{Buffer: bytes.Repeat([]byte{0x11}, 34)},
		ExtraData:       tpm2.TPM2BData{Buffer: extra[:]},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1, ResetCount: 2, RestartCount: 3, Safe: true},
		FirmwareVersion: 1,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          *name,
			QualifiedName: tpm2.TPM2BName{Buffer: bytes.Repeat([]byte{0x22}, 34)},
		}),
	})

	// The AIK certificate chains to a root only the harness holds.
	rootKey := tpmDetKey(tb, "root")
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "keyorix tpm fuzz root"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		tb.Fatal(err)
	}
	if fx.root, err = x509.ParseCertificate(rootDER); err != nil {
		tb.Fatal(err)
	}
	aikTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), // empty subject, as 8.3.1 requires
		NotBefore:    time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0),
		BasicConstraintsValid: true, IsCA: false,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}},
		ExtraExtensions:    []pkix.Extension{tpmSAN(tb)},
	}
	if fx.aik, err = x509.CreateCertificate(rand.Reader, aikTmpl, fx.root, aikKey.Public(), rootKey); err != nil {
		tb.Fatal(err)
	}
	digest := sha256.Sum256(fx.certInfo)
	if fx.sig, err = aikKey.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		tb.Fatal(err)
	}
	return fx
}

// tpmSAN is the critical directoryName SAN carrying the TPM manufacturer, model
// and firmware version (TCG EK Profile 3.2.9).
func tpmSAN(tb testing.TB) pkix.Extension {
	tb.Helper()
	atv := func(oid asn1.ObjectIdentifier, v string) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: oid, Value: v}
	}
	dn, err := asn1.Marshal(pkix.RDNSequence{
		{atv(asn1.ObjectIdentifier{2, 23, 133, 2, 1}, "id:FFFFF1D0")},
		{atv(asn1.ObjectIdentifier{2, 23, 133, 2, 2}, "keyorix-fuzz-tpm")},
		{atv(asn1.ObjectIdentifier{2, 23, 133, 2, 3}, "id:00010001")},
	})
	if err != nil {
		tb.Fatal(err)
	}
	val, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn}})
	if err != nil {
		tb.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: val}
}

func tpmClientData(tb testing.TB) []byte {
	tb.Helper()
	b, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": tpmChallenge, "origin": tpmOrigin, "crossOrigin": false})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func tpmAuthData(tb testing.TB, k *ecdsa.PrivateKey) []byte {
	tb.Helper()
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		tb.Fatal(err)
	}
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		tb.Fatal(err)
	}
	h := sha256.Sum256([]byte(tpmRPID))
	out := append([]byte{}, h[:]...)
	out = append(out, 0x45) // UP | UV | AT
	out = binary.BigEndian.AppendUint32(out, 1)
	out = append(out, make([]byte, 16)...) // AAGUID: zero, the TPM-format default
	out = binary.BigEndian.AppendUint16(out, uint16(len(tpmCredID)))
	out = append(out, tpmCredID...)
	return append(out, cose...)
}

// response assembles the registration JSON the browser would POST.
func (fx *tpmFixture) response(tb testing.TB, ver string, alg int64, certInfo, pubArea, sig, aik []byte) []byte {
	tb.Helper()
	att, err := webauthncbor.Marshal(map[string]any{
		"fmt": "tpm",
		"attStmt": map[string]any{
			"ver": ver, "alg": alg, "sig": sig, "x5c": [][]byte{aik}, "certInfo": certInfo, "pubArea": pubArea,
		},
		"authData": fx.authData,
	})
	if err != nil {
		tb.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	b, err := json.Marshal(map[string]any{
		"id": b64(tpmCredID), "rawId": b64(tpmCredID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(fx.clientData), "attestationObject": b64(att)},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func tpmSession() *webauthn.SessionData {
	return &webauthn.SessionData{
		Challenge:        tpmChallenge,
		RelyingPartyID:   tpmRPID,
		UserID:           tpmUserID,
		Expires:          time.Now().Add(time.Hour),
		UserVerification: protocol.VerificationPreferred,
		CredParams:       webauthn.CredentialParametersDefault(),
	}
}

// rootProvider is a metadata provider with exactly one trust anchor, the
// harness's root, and no other policy.
type rootProvider struct{ entry *metadata.Entry }

func (p rootProvider) GetEntry(context.Context, uuid.UUID) (*metadata.Entry, error) {
	return p.entry, nil
}
func (rootProvider) GetValidateEntry(context.Context) bool                                { return true }
func (rootProvider) GetValidateEntryPermitZeroAAGUID(context.Context) bool                { return false }
func (rootProvider) GetValidateTrustAnchor(context.Context) bool                          { return true }
func (rootProvider) GetValidateStatus(context.Context) bool                               { return false }
func (rootProvider) GetValidateAttestationTypes(context.Context) bool                     { return true }
func (rootProvider) ValidateStatusReports(context.Context, []metadata.StatusReport) error { return nil }

func newRootRP(tb testing.TB, fx *tpmFixture) ports.WebAuthnRelyingParty {
	tb.Helper()
	entry := &metadata.Entry{}
	entry.MetadataStatement.AttestationTypes = metadata.AuthenticatorAttestationTypes{metadata.AttCA}
	entry.MetadataStatement.AttestationRootCertificates = []*x509.Certificate{fx.root}
	rp, err := webauthn.New(&webauthn.Config{
		RPID: tpmRPID, RPDisplayName: "Keyorix", RPOrigins: []string{tpmOrigin},
		MDS: rootProvider{entry: entry},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return Wrap(rp)
}

func newKeyorixRP(tb testing.TB) ports.WebAuthnRelyingParty {
	tb.Helper()
	rp, err := New(Config{RPID: tpmRPID, RPDisplayName: "Keyorix", RPOrigins: []string{tpmOrigin}})
	if err != nil {
		tb.Fatal(err)
	}
	return rp
}

// finish is what FinishWebAuthnRegistration runs: the handler's parse, then the
// keyorix wrapper.
func finish(rp ports.WebAuthnRelyingParty, resp []byte) (ports.WebAuthnVerified, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		return ports.WebAuthnVerified{}, err
	}
	return rp.FinishRegistration(ports.WebAuthnUser{ID: tpmUserID, Name: "fuzz", DisplayName: "fuzz"}, tpmSession(), parsed)
}

// ---- independent oracle ----------------------------------------------------

type tpmStatement struct {
	ver                         string
	alg                         int64
	certInfo, pubArea, sig, aik []byte
}

// checkTPMAccepted is called only when a registration was accepted. It returns
// an error naming the first fact the accepted statement does not satisfy.
func checkTPMAccepted(fx *tpmFixture, st tpmStatement, requireRoot bool) error {
	if st.ver != "2.0" {
		return fmt.Errorf("accepted ver %q", st.ver)
	}
	cert, err := x509.ParseCertificate(st.aik)
	if err != nil {
		return fmt.Errorf("accepted an AIK certificate that does not parse: %w", err)
	}
	// 1. the AIK signed certInfo. The harness AIK is a P-256 key, so only
	// -7 (ES256) and -9 (ESP256), both ECDSA P-256 + SHA-256, are correct.
	// Every other alg is flagged, algES256K (-47) included since #4545.
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("accepted alg %d with a %T AIK key that is not P-256", st.alg, cert.PublicKey)
	}
	if st.alg != -7 && st.alg != -9 {
		return fmt.Errorf("accepted alg %d with a P-256 AIK key", st.alg)
	}
	d := sha256.Sum256(st.certInfo)
	if !ecdsa.VerifyASN1(pub, d[:], st.sig) {
		return errors.New("accepted a certInfo the AIK key did not sign")
	}
	// 2. certInfo binds this ceremony and this pubArea.
	extra, certified, err := readCertify(st.certInfo)
	if err != nil {
		return fmt.Errorf("accepted a certInfo the oracle cannot read: %w", err)
	}
	cdh := sha256.Sum256(fx.clientData)
	want := sha256.Sum256(append(append([]byte{}, fx.authData...), cdh[:]...))
	if !bytes.Equal(extra, want[:]) {
		return errors.New("accepted certInfo.extraData that is not H(authData || H(clientData))")
	}
	canon, err := tpmCanonicalPubArea(st.pubArea)
	if err != nil {
		return fmt.Errorf("accepted a pubArea the oracle cannot parse: %w", err)
	}
	name, err := tpmName(canon)
	if err != nil {
		return fmt.Errorf("accepted a pubArea the oracle cannot name: %w", err)
	}
	if !bytes.Equal(certified, name) {
		return errors.New("accepted certInfo whose certified Name is not the Name of pubArea")
	}
	// 3. pubArea holds the credential key.
	raw, err := fx.credKey.PublicKey.Bytes()
	if err != nil {
		return err
	}
	x, y, err := readECCUnique(canon)
	if err != nil {
		return fmt.Errorf("accepted a pubArea the oracle cannot read: %w", err)
	}
	if !bytes.Equal(x, raw[1:33]) || !bytes.Equal(y, raw[33:65]) {
		return errors.New("accepted a pubArea whose unique.ecc is not the credential public key")
	}
	// 4. TCG AIK certificate rules (WebAuthn 8.3.1).
	if cert.Version != 3 || len(cert.RawSubject) != 2 {
		return errors.New("accepted an AIK certificate that is not v3 with an empty subject")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return errors.New("accepted an AIK certificate without BasicConstraints CA:false")
	}
	eku := false
	for _, o := range cert.UnknownExtKeyUsage {
		eku = eku || o.Equal(asn1.ObjectIdentifier{2, 23, 133, 8, 3})
	}
	if !eku {
		return errors.New("accepted an AIK certificate without the AIK EKU")
	}
	// 5. the one trust claim: only meaningful when the harness owns the root.
	if requireRoot {
		roots := x509.NewCertPool()
		roots.AddCert(fx.root)
		leaf := *cert
		leaf.UnhandledCriticalExtensions = nil // the critical SAN, which crypto/x509 cannot interpret
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return fmt.Errorf("accepted an AIK certificate that does not chain to the harness root: %w", err)
		}
	}
	return nil
}

// readCertify returns extraData and the certified Name of a TPMS_ATTEST of type
// certify: magic(4) type(2) qualifiedSigner(2B) extraData(2B) clockInfo(17)
// firmware(8) name(2B) qualifiedName(2B). It insists on an exact fit.
func readCertify(b []byte) (extra, name []byte, err error) {
	if len(b) < 6 || binary.BigEndian.Uint32(b) != 0xff544347 || binary.BigEndian.Uint16(b[4:]) != 0x8017 {
		return nil, nil, errors.New("not a TPMS_ATTEST certify")
	}
	p := b[6:]
	sized := func() ([]byte, bool) {
		if len(p) < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(p))
		if len(p) < 2+n {
			return nil, false
		}
		v := p[2 : 2+n]
		p = p[2+n:]
		return v, true
	}
	var ok bool
	if _, ok = sized(); !ok {
		return nil, nil, errors.New("short qualifiedSigner")
	}
	if extra, ok = sized(); !ok {
		return nil, nil, errors.New("short extraData")
	}
	if len(p) < 25 {
		return nil, nil, errors.New("short clockInfo/firmwareVersion")
	}
	p = p[25:]
	if name, ok = sized(); !ok {
		return nil, nil, errors.New("short certified name")
	}
	if _, ok = sized(); !ok || len(p) != 0 {
		return nil, nil, errors.New("short or trailing qualifiedName")
	}
	return extra, name, nil
}

// readECCUnique returns unique.ecc.x and .y of an ECC P-256 TPMT_PUBLIC (TPM 2.0
// Part 2, 12.2.4 and 12.2.3.6), refusing any other type, curve or trailing bytes.
func readECCUnique(b []byte) (x, y []byte, err error) {
	p := b
	u16 := func() (uint16, bool) {
		if len(p) < 2 {
			return 0, false
		}
		v := binary.BigEndian.Uint16(p)
		p = p[2:]
		return v, true
	}
	sized := func() ([]byte, bool) {
		n, ok := u16()
		if !ok || len(p) < int(n) {
			return nil, false
		}
		v := p[:n]
		p = p[n:]
		return v, true
	}
	// algOrNull reads an algorithm id and, unless it is TPM_ALG_NULL, the n
	// further u16 fields its union carries.
	algOrNull := func(n int) bool {
		alg, ok := u16()
		for i := 0; ok && alg != 0x0010 && i < n; i++ {
			_, ok = u16()
		}
		return ok
	}
	if typ, ok := u16(); !ok || typ != 0x0023 {
		return nil, nil, errors.New("not an ECC TPMT_PUBLIC")
	}
	if _, ok := u16(); !ok { // nameAlg
		return nil, nil, errors.New("short nameAlg")
	}
	if len(p) < 4 {
		return nil, nil, errors.New("short objectAttributes")
	}
	p = p[4:]
	if _, ok := sized(); !ok {
		return nil, nil, errors.New("short authPolicy")
	}
	// TPMS_ECC_PARMS: symmetric (keyBits, mode), scheme (hashAlg), curveID, kdf (hashAlg).
	if !algOrNull(2) || !algOrNull(1) {
		return nil, nil, errors.New("short symmetric/scheme")
	}
	if curve, ok := u16(); !ok || curve != 0x0003 {
		return nil, nil, errors.New("curve is not NIST P-256")
	}
	if !algOrNull(1) {
		return nil, nil, errors.New("short kdf")
	}
	var ok bool
	if x, ok = sized(); !ok {
		return nil, nil, errors.New("short unique.x")
	}
	if y, ok = sized(); !ok || len(p) != 0 {
		return nil, nil, errors.New("short unique.y or trailing bytes")
	}
	return x, y, nil
}

// tpmName is nameAlg(2) || H_nameAlg(pubArea) for a TPMT_PUBLIC (TPM 2.0 Part 1, 16).
func tpmName(pubArea []byte) ([]byte, error) {
	if len(pubArea) < 4 {
		return nil, errors.New("short pubArea")
	}
	var h hash.Hash
	switch alg := binary.BigEndian.Uint16(pubArea[2:]); alg {
	case 0x0004:
		h = sha1.New() //nolint:gosec // see import // nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1 -- TPM Name for nameAlg SHA-1 (TPM 2.0 Part 1, 16), test oracle only
	case 0x000b:
		h = sha256.New()
	case 0x000c:
		h = sha512.New384()
	case 0x000d:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("nameAlg %#x", alg)
	}
	h.Write(pubArea)
	return append(append([]byte{}, pubArea[2:4]...), h.Sum(nil)...), nil
}

// tpmCanonicalPubArea is the canonical marshalling of the TPMT_PUBLIC that
// pubArea parses to. go-webauthn parses pubArea with tpm2.Unmarshal, which
// ignores bytes after the structure, then computes the Name with tpm2.ObjectName
// and takes the key from the parsed structure. A pubArea with trailing bytes
// therefore names the same object, with the same key, as its canonical form, and
// a certInfo that certifies that Name is a genuine attestation of that key: no
// forgery, the signed Name and the extracted key are unchanged. Hashing and
// reading the raw bytes flagged it as a Name mismatch (KFZ-2026-190). The oracle
// checks the Name and the key against this canonical form.
func tpmCanonicalPubArea(pubArea []byte) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubArea)
	if err != nil {
		return nil, fmt.Errorf("pubArea does not parse: %w", err)
	}
	return tpm2.Marshal(*pub), nil
}

// algES256K is COSE algorithm -47 (ES256K, secp256k1). go-webauthn v0.18.2 maps
// it to x509.ECDSAWithSHA256, so the library alone accepts a TPM statement
// labelled -47 whose P-256 AIK signature over certInfo verifies (#4545,
// KFZ-2026-165/166). That deviates from WebAuthn §8.3 ("using the algorithm
// specified in alg"); checkAttestationKeyAlg refuses it, and
// TestTPMAttestation_AlgMustMatchAIKKey pins the refusal.
const algES256K = int64(-47)

// ---- tests and fuzz targets --------------------------------------------------

func (fx *tpmFixture) seedStatement() tpmStatement {
	return tpmStatement{"2.0", -7, fx.certInfo, fx.pubArea, fx.sig, fx.aik}
}

// TestTPMSeed_AcceptedByBothModes: the seed is a genuine attestation, so the
// fuzzer starts behind every check, in both modes, and the oracle agrees.
func TestTPMSeed_AcceptedByBothModes(t *testing.T) {
	fx := newTPMFixture(t)
	st := fx.seedStatement()
	resp := fx.response(t, st.ver, st.alg, st.certInfo, st.pubArea, st.sig, st.aik)
	for name, rp := range map[string]ports.WebAuthnRelyingParty{"keyorix": newKeyorixRP(t), "root": newRootRP(t, fx)} {
		if _, err := finish(rp, resp); err != nil {
			t.Fatalf("%s: genuine TPM attestation rejected: %v", name, err)
		}
	}
	if err := checkTPMAccepted(fx, st, true); err != nil {
		t.Fatalf("oracle rejects the genuine statement: %v", err)
	}
}

// TestTPMAttestation_TrailingPubAreaBytesTolerated pins the library's
// tolerance of bytes after the TPMT_PUBLIC in pubArea (KFZ-2026-190): the
// certInfo still certifies the canonical Name, the credential key is unchanged,
// and the oracle agrees with the library instead of reporting a Name mismatch.
// It is a tolerance record, not a security claim: if go-webauthn starts refusing
// trailing bytes this test fails and the pin should be flipped to a refusal.
func TestTPMAttestation_TrailingPubAreaBytesTolerated(t *testing.T) {
	fx := newTPMFixture(t)
	st := fx.seedStatement()
	st.pubArea = append(append([]byte{}, st.pubArea...), 0x30)
	resp := fx.response(t, st.ver, st.alg, st.certInfo, st.pubArea, st.sig, st.aik)
	if _, err := finish(newKeyorixRP(t), resp); err != nil {
		t.Fatalf("library no longer tolerates trailing pubArea bytes: %v (flip this pin to a refusal)", err)
	}
	if err := checkTPMAccepted(fx, st, false); err != nil {
		t.Fatalf("oracle contradicts the library on trailing pubArea bytes: %v", err)
	}
}

// TestTPMOracle_AlgVariants verifies the oracle's alg handling: -9 (ESP256,
// legitimate alias for ES256) passes with a genuine signature; -47 (ES256K,
// #4545), -35 (ES384) and -257 (RS256) fail with a P-256 AIK even though the
// signature is genuine.
func TestTPMOracle_AlgVariants(t *testing.T) {
	fx := newTPMFixture(t)
	base := fx.seedStatement() // alg -7, real signature
	st := base
	st.alg = -9
	if err := checkTPMAccepted(fx, st, true); err != nil {
		t.Errorf("oracle rejected alg -9 with a genuine signature, want accepted: %v", err)
	}
	for _, alg := range []int64{algES256K, -35, -257} {
		st := base
		st.alg = alg
		if err := checkTPMAccepted(fx, st, false); err == nil {
			t.Errorf("oracle accepted alg %d, want rejected", alg)
		}
	}
}

// flipLastByte returns a copy of b with one bit of its last byte flipped.
func flipLastByte(b []byte) []byte {
	c := append([]byte{}, b...)
	c[len(c)-1] ^= 0x01
	return c
}

// TestTPMAttestation_AlgMustMatchAIKKey (#4545; it replaces
// TestTPMLibrary_ES256KLeniencyPinned, which pinned the acceptance): in both RP
// modes, a statement whose alg does not name the AIK's key type and curve is
// refused with the library's attestation-format *protocol.Error, even though its
// signature is genuine. -47 (ES256K) with a P-256 AIK is the KFZ-2026-165/166
// reproducer; ES256 with a P-384 AIK is the same gap on the curve alone (x509
// CheckSignature accepts ECDSA-with-SHA256 on any curve). -9 (ESP256) with a
// P-256 AIK stays accepted.
func TestTPMAttestation_AlgMustMatchAIKKey(t *testing.T) {
	fx := newTPMFixture(t)
	st := fx.seedStatement()
	p384, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), bytes.Repeat([]byte{0x3C}, 48))
	if err != nil {
		t.Fatal(err)
	}
	fx384 := newTPMFixtureWithAIK(t, p384)
	st384 := fx384.seedStatement()
	for name, rps := range map[string][2]ports.WebAuthnRelyingParty{
		"keyorix": {newKeyorixRP(t), newKeyorixRP(t)},
		"root":    {newRootRP(t, fx), newRootRP(t, fx384)},
	} {
		if _, err := finish(rps[0], fx.response(t, st.ver, -9, st.certInfo, st.pubArea, st.sig, st.aik)); err != nil {
			t.Errorf("%s: alg -9 (ESP256) with a P-256 AIK rejected: %v", name, err)
		}
		requireAttFormatRefusal(t, name+": alg -47 with a P-256 AIK",
			finishErr(rps[0], fx.response(t, st.ver, algES256K, st.certInfo, st.pubArea, st.sig, st.aik)))
		requireAttFormatRefusal(t, name+": alg -7 (ES256) with a P-384 AIK",
			finishErr(rps[1], fx384.response(t, st384.ver, -7, st384.certInfo, st384.pubArea, st384.sig, st384.aik)))
		if _, err := finish(rps[0], fx.response(t, st.ver, algES256K, st.certInfo, st.pubArea, flipLastByte(st.sig), st.aik)); err == nil {
			t.Errorf("%s: alg -47 with a forged signature accepted", name)
		}
	}
}

// TestTPMAttestation_GenuineES256AndRS256Accepted: the tightening keeps the two
// AIK shapes real TPMs ship. ES256 with a P-256 AIK (the fuzz seed) and RS256
// with an RSA-2048 AIK are accepted in both RP modes.
func TestTPMAttestation_GenuineES256AndRS256Accepted(t *testing.T) {
	rsaAIK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		fx   *tpmFixture
		alg  int64
	}{
		{"ES256/P-256", newTPMFixture(t), -7},
		{"RS256/RSA-2048", newTPMFixtureWithAIK(t, rsaAIK), -257},
	} {
		st := tc.fx.seedStatement()
		resp := tc.fx.response(t, st.ver, tc.alg, st.certInfo, st.pubArea, st.sig, st.aik)
		for name, rp := range map[string]ports.WebAuthnRelyingParty{"keyorix": newKeyorixRP(t), "root": newRootRP(t, tc.fx)} {
			if _, err := finish(rp, resp); err != nil {
				t.Errorf("%s %s: genuine TPM attestation rejected: %v", tc.name, name, err)
			}
		}
	}
}

func finishErr(rp ports.WebAuthnRelyingParty, resp []byte) error {
	_, err := finish(rp, resp)
	return err
}

// requireAttFormatRefusal requires err to be the library's attestation-format
// error (type "invalid_attestation"), the type a signature that fails to verify
// also gets, so a refusal is not mistaken for an unrelated parse failure.
func requireAttFormatRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted, want refused", what)
		return
	}
	perr, ok := errors.AsType[*protocol.Error](err)
	if !ok || perr.Type != protocol.ErrAttestationFormat.Type {
		t.Errorf("%s: refused with %T %v, want a *protocol.Error of type %q", what, err, err, protocol.ErrAttestationFormat.Type)
	}
}

// TestTPMOracle_RedProof plants acceptances of forged statements, as a
// verifier that accepted them would, and requires the oracle to name each one.
func TestTPMOracle_RedProof(t *testing.T) {
	fx := newTPMFixture(t)
	flip := func(b []byte, i int) []byte { c := append([]byte{}, b...); c[i] ^= 0x01; return c }
	otherKey := tpmDetKey(t, "attacker aik")
	otherSig := func(ci []byte) []byte {
		d := sha256.Sum256(ci)
		s, err := ecdsa.SignASN1(rand.Reader, otherKey, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := fx.seedStatement()
	// A pubArea that carries the credential key's X and Y only in its authPolicy,
	// with another key in unique.ecc, certified (Name and AIK signature) for real:
	// a byte search finds the credential key in it, a decode does not.
	smuggled, certSmuggled, sigSmuggled := func() ([]byte, []byte, []byte) {
		raw, err := fx.credKey.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		other, err := tpmDetKey(t, "other credential").PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](fx.pubArea)
		if err != nil {
			t.Fatal(err)
		}
		oldName, err := tpm2.ObjectName(pub)
		if err != nil {
			t.Fatal(err)
		}
		pub.AuthPolicy = tpm2.TPM2BDigest{Buffer: raw[1:65]}
		pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: other[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: other[33:65]},
		})
		newName, err := tpm2.ObjectName(pub)
		if err != nil {
			t.Fatal(err)
		}
		ci := bytes.Replace(fx.certInfo, oldName.Buffer, newName.Buffer, 1)
		d := sha256.Sum256(ci)
		sig, err := ecdsa.SignASN1(rand.Reader, tpmDetKey(t, "aik"), d[:])
		if err != nil {
			t.Fatal(err)
		}
		return tpm2.Marshal(pub), ci, sig
	}()
	// extraData is the 32 bytes after the 6-byte header and the 2B-prefixed qualifiedSigner (2+34).
	extraOff := 6 + 2 + 34 + 2
	tests := []struct {
		name string
		mut  func(*tpmStatement)
		root bool
	}{
		{"extraData of another ceremony", func(s *tpmStatement) { s.certInfo = flip(s.certInfo, extraOff); s.sig = otherSig(s.certInfo) }, false},
		{"certInfo not signed by the AIK", func(s *tpmStatement) { s.certInfo = flip(s.certInfo, 10) }, false},
		{"signature by a different key", func(s *tpmStatement) { s.sig = otherSig(s.certInfo) }, false},
		{"pubArea of a different key", func(s *tpmStatement) { s.pubArea = flip(s.pubArea, len(s.pubArea)-1) }, false},
		{"certified pubArea with the credential key outside unique.ecc", func(s *tpmStatement) {
			s.pubArea, s.certInfo, s.sig = smuggled, certSmuggled, sigSmuggled
		}, false},
		{"wrong alg -35 (ES384)", func(s *tpmStatement) { s.alg = -35 }, false},
		{"wrong alg -257 (RS256)", func(s *tpmStatement) { s.alg = -257 }, false},
		{"wrong version", func(s *tpmStatement) { s.ver = "1.2" }, false},
		{"truncated certInfo", func(s *tpmStatement) { s.certInfo = s.certInfo[:len(s.certInfo)-1] }, false},
		{"AIK certificate corrupted below the TBS", func(s *tpmStatement) { s.aik = flip(s.aik, len(s.aik)-3) }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := base
			tc.mut(&st)
			if err := checkTPMAccepted(fx, st, tc.root); err == nil {
				t.Fatal("oracle accepted a forged statement")
			}
		})
	}
	// Mode honesty: with no harness root, a corrupted certificate signature is
	// legitimately accepted by keyorix's RP and the oracle must not claim otherwise.
	st := base
	st.aik = flip(st.aik, len(st.aik)-3)
	if _, err := finish(newKeyorixRP(t), fx.response(t, st.ver, st.alg, st.certInfo, st.pubArea, st.sig, st.aik)); err == nil {
		if err := checkTPMAccepted(fx, st, false); err != nil {
			t.Fatalf("no-root oracle contradicts the library on a certificate-only change: %v", err)
		}
	}
}

func fuzzTPM(f *testing.F, requireRoot bool) {
	fx := newTPMFixture(f)
	var rp ports.WebAuthnRelyingParty
	if requireRoot {
		rp = newRootRP(f, fx)
	} else {
		rp = newKeyorixRP(f)
	}
	s := fx.seedStatement()
	// -9 and -47 with the genuine signature: the KFZ-2026-165/166 reproducers.
	for _, alg := range []int64{s.alg, -9, algES256K} {
		f.Add(s.ver, alg, s.certInfo, s.pubArea, s.sig, s.aik)
	}
	// One byte after the TPMT_PUBLIC: accepted by the library (KFZ-2026-190).
	f.Add(s.ver, s.alg, s.certInfo, append(append([]byte{}, s.pubArea...), 0x30), s.sig, s.aik)
	f.Fuzz(func(t *testing.T, ver string, alg int64, certInfo, pubArea, sig, aik []byte) {
		st := tpmStatement{ver, alg, certInfo, pubArea, sig, aik}
		resp := fx.response(t, ver, alg, certInfo, pubArea, sig, aik)
		var err error
		fuzzutil.Guard(t.Fatalf, "FinishRegistration(tpm)", func() { _, err = finish(rp, resp) })
		if err != nil {
			return
		}
		if oerr := checkTPMAccepted(fx, st, requireRoot); oerr != nil {
			t.Fatal(oerr)
		}
	})
}

// FuzzTPMAttestationRegistration: the RP exactly as keyorix builds it.
func FuzzTPMAttestationRegistration(f *testing.F) { fuzzTPM(f, false) }

// FuzzTPMAttestationTrustRoot: the same statement, with a harness-owned root.
func FuzzTPMAttestationTrustRoot(f *testing.F) { fuzzTPM(f, true) }
