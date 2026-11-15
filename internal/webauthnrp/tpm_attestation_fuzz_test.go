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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	rootKey, aikKey := tpmDetKey(tb, "root"), tpmDetKey(tb, "aik")
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
	if fx.aik, err = x509.CreateCertificate(rand.Reader, aikTmpl, fx.root, &aikKey.PublicKey, rootKey); err != nil {
		tb.Fatal(err)
	}
	digest := sha256.Sum256(fx.certInfo)
	if fx.sig, err = ecdsa.SignASN1(rand.Reader, aikKey, digest[:]); err != nil {
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
	// 1. the AIK signed certInfo (ES256 only: the harness AIK is a P-256 key).
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || st.alg != -7 {
		return fmt.Errorf("accepted alg %d with a %T AIK key", st.alg, cert.PublicKey)
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
	name, err := tpmName(st.pubArea)
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
	if !bytes.Contains(st.pubArea, raw[1:33]) || !bytes.Contains(st.pubArea, raw[33:65]) {
		return errors.New("accepted a pubArea that does not carry the credential public key")
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

// tpmName is nameAlg(2) || H_nameAlg(pubArea) for a TPMT_PUBLIC (TPM 2.0 Part 1, 16).
func tpmName(pubArea []byte) ([]byte, error) {
	if len(pubArea) < 4 {
		return nil, errors.New("short pubArea")
	}
	var h hash.Hash
	switch alg := binary.BigEndian.Uint16(pubArea[2:]); alg {
	case 0x0004:
		h = sha1.New() //nolint:gosec // see import
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
		{"wrong alg", func(s *tpmStatement) { s.alg = -35 }, false},
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
	f.Add(s.ver, s.alg, s.certInfo, s.pubArea, s.sig, s.aik)
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
