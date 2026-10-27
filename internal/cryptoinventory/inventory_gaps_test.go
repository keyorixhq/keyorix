package cryptoinventory

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genKey is one real key pair of each supported algorithm.
type genKey struct {
	name, wantAlg string
	wantBits      int
	pub, priv     any
}

func genKeys(t *testing.T) []genKey {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return []genKey{
		{"ecdsa-p256", "ECDSA-P256", 256, &ec.PublicKey, ec},
		{"rsa-2048", "RSA-2048", 2048, &rsaKey.PublicKey, rsaKey},
		{"ed25519", "Ed25519", 256, edPub, edPriv},
	}
}

// samlMetadata is IdP metadata with an encryption key (must be ignored) and a
// signing key, both real certificates.
func samlMetadata(t *testing.T, dir string, signing, encryption genKey, nb, na time.Time) []byte {
	t.Helper()
	b64 := func(g genKey) string {
		p := writeCertPEM(t, dir, "m-"+g.name+".pem", g.pub, g.priv, nb, na, false)
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		blk, _ := pem.Decode(raw)
		return base64.StdEncoding.EncodeToString(blk.Bytes)
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
      %s
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>`, b64(encryption), b64(signing)))
}

// gapWarnings drops the encryption-disabled warning every EncryptionEnabled=false
// fixture raises, leaving the warnings these tests are about.
func gapWarnings(inv Inventory) []string {
	var out []string
	for _, w := range inv.Warnings {
		if !strings.HasPrefix(w, "encryption is disabled: secrets are stored") {
			out = append(out, w)
		}
	}
	return out
}

func assetByID(t *testing.T, inv Inventory, id string) Asset {
	t.Helper()
	for _, a := range inv.Assets {
		if a.ID == id {
			return a
		}
	}
	require.Failf(t, "asset missing", "no asset %q in %d assets", id, len(inv.Assets))
	return Asset{}
}

func TestBuild_SAMLSigningCertificates(t *testing.T) {
	dir := t.TempDir()
	nb, na := riskNow.Add(-time.Hour), riskNow.Add(365*24*time.Hour)
	keys := genKeys(t)
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			// the encryption certificate is always the "other" algorithm
			enc := keys[(indexOf(keys, k)+1)%len(keys)]
			in := Inputs{SAML: []SAMLInput{{Name: "okta", Metadata: samlMetadata(t, dir, k, enc, nb, na)}}}
			inv := Build(in, DefaultPolicy(), riskNow)

			require.Len(t, inv.Assets, 1, "only the signing KeyDescriptor is inventoried")
			a := assetByID(t, inv, "saml.okta.0")
			assert.Equal(t, ClassSAMLCertificate, a.Class)
			assert.Equal(t, k.wantAlg, a.Algorithm)
			assert.Equal(t, k.wantBits, a.KeySizeBits)
			require.NotNil(t, a.CreatedAt)
			require.NotNil(t, a.ExpiresAt)
			assert.WithinDuration(t, na, *a.ExpiresAt, time.Second)
			assert.True(t, a.Risk.QuantumVulnerable)
			assert.Equal(t, DefaultPolicy().Assess(a, riskNow), a.Risk, "score comes from the existing scorer")
			assert.Empty(t, gapWarnings(inv))
		})
	}
}

func indexOf(keys []genKey, k genKey) int {
	for i := range keys {
		if keys[i].name == k.name {
			return i
		}
	}
	return -1
}

func TestBuild_SAMLMetadataProblemsAreVisible(t *testing.T) {
	for name, in := range map[string]SAMLInput{
		"unreadable": {Name: "a", MetadataErr: "read idp_metadata_file: no such file"},
		"malformed":  {Name: "a", Metadata: []byte("<EntityDescriptor")},
		"no-cert":    {Name: "a", Metadata: []byte(`<EntityDescriptor><IDPSSODescriptor/></EntityDescriptor>`)},
		"bad-cert": {Name: "a", Metadata: []byte(`<EntityDescriptor><IDPSSODescriptor><KeyDescriptor use="signing">` +
			`<X509Certificate>AAAA</X509Certificate></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>`)},
	} {
		t.Run(name, func(t *testing.T) {
			inv := Build(Inputs{SAML: []SAMLInput{in}}, DefaultPolicy(), riskNow)
			require.Len(t, inv.Assets, 1)
			assert.Equal(t, "unknown", inv.Assets[0].Algorithm)
			assert.GreaterOrEqual(t, inv.Assets[0].Risk.Score, 40, "an uninspectable certificate fails closed")
			require.Len(t, gapWarnings(inv), 1)
			assert.Contains(t, gapWarnings(inv)[0], `"a"`)
		})
	}
}

func TestBuild_DatabaseTLS(t *testing.T) {
	dir := t.TempDir()
	nb, na := riskNow.Add(-time.Hour), riskNow.Add(180*24*time.Hour)
	keys := genKeys(t)
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			client := writeCertPEM(t, dir, "client-"+k.name+".pem", k.pub, k.priv, nb, na, true)
			ca := writeCertPEM(t, dir, "ca-"+k.name+".pem", k.pub, k.priv, nb, na.Add(5*365*24*time.Hour), false)
			in := Inputs{Database: &DatabaseTLSInput{SSLMode: "verify-full", RootCertFile: ca,
				ClientCertFile: client, ClientKeyFile: "/etc/pg/client.key"}}
			inv := Build(in, DefaultPolicy(), riskNow)

			require.Len(t, inv.Assets, 2)
			c := assetByID(t, inv, "database-tls.client")
			assert.Equal(t, k.wantAlg, c.Algorithm)
			assert.Equal(t, k.wantBits, c.KeySizeBits)
			assert.Contains(t, c.Storage, "/etc/pg/client.key", "key recorded as a location")
			require.NotNil(t, c.ExpiresAt)
			assert.WithinDuration(t, na, *c.ExpiresAt, time.Second)
			ca0 := assetByID(t, inv, "database-tls.ca.0")
			assert.Equal(t, k.wantAlg, ca0.Algorithm)
			assert.True(t, ca0.Risk.QuantumVulnerable)
			assert.Greater(t, ca0.Risk.Score, c.Risk.Score, "the longer-lived CA scores higher than the 180-day client cert")
			assert.Empty(t, gapWarnings(inv))
		})
	}
}

func TestBuild_DatabaseCABundleAndSystemRoots(t *testing.T) {
	dir := t.TempDir()
	nb, na := riskNow.Add(-time.Hour), riskNow.Add(365*24*time.Hour)
	keys := genKeys(t)
	var bundle []byte
	for _, k := range keys {
		raw, err := os.ReadFile(writeCertPEM(t, dir, k.name+".pem", k.pub, k.priv, nb, na, true))
		require.NoError(t, err)
		bundle = append(bundle, raw...)
	}
	path := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(path, bundle, 0o600))

	inv := Build(Inputs{Database: &DatabaseTLSInput{RootCertFile: path}}, DefaultPolicy(), riskNow)
	require.Len(t, inv.Assets, 3, "every CERTIFICATE in the bundle, private keys skipped")

	sys := Build(Inputs{Database: &DatabaseTLSInput{RootCertSystem: true}}, DefaultPolicy(), riskNow)
	assert.Empty(t, sys.Assets, "the OS trust store has no file to inventory")
	assert.Empty(t, gapWarnings(sys))

	bad := Build(Inputs{Database: &DatabaseTLSInput{RootCertFile: filepath.Join(dir, "nope.pem"),
		ClientCertFile: filepath.Join(dir, "nope2.pem")}}, DefaultPolicy(), riskNow)
	require.Len(t, bad.Assets, 2)
	assert.Len(t, gapWarnings(bad), 2)
}

func TestBuild_BackupEncryption(t *testing.T) {
	on := Build(Inputs{Backup: &BackupInput{EncryptionEnabled: true}}, DefaultPolicy(), riskNow)
	a := assetByID(t, on, "backup-archive")
	assert.Equal(t, ClassBackupEncryption, a.Class)
	assert.Equal(t, "AES-256-GCM", a.Algorithm)
	assert.Equal(t, 256, a.KeySizeBits)
	assert.Equal(t, LevelLow, a.Risk.Level)
	assert.False(t, a.Risk.QuantumVulnerable)
	assert.Contains(t, a.Storage, "no archive-level encryption", "the gap is stated, not hidden")
	assert.Empty(t, gapWarnings(on))

	off := Build(Inputs{Backup: &BackupInput{EncryptionEnabled: false}}, DefaultPolicy(), riskNow)
	b := assetByID(t, off, "backup-archive")
	assert.Equal(t, "none", b.Algorithm)
	assert.Equal(t, LevelMedium, b.Risk.Level, "plaintext secrets in a backup fail closed to medium")
	require.Len(t, gapWarnings(off), 1)
	assert.Contains(t, gapWarnings(off)[0], "backup archives carry secret values as plaintext")
}

// Review finding (#3754): plaintext Shamir share files in the archive mean its
// encryption cannot be credited; the asset fails closed and the inventory warns.
func TestBuild_BackupWithShamirShareFilesFailsClosed(t *testing.T) {
	sch := compileCycloneDX16(t)
	inv := Build(Inputs{Backup: &BackupInput{EncryptionEnabled: true, ShamirShareFiles: 3}}, DefaultPolicy(), riskNow)
	a := assetByID(t, inv, "backup-archive")
	assert.Equal(t, "unknown", a.Algorithm)
	assert.Zero(t, a.KeySizeBits)
	assert.Equal(t, LevelMedium, a.Risk.Level, "fail closed: the archive may hold threshold-many shares")
	assert.Contains(t, a.Notes, "3 plaintext Shamir KEK share file(s)")
	require.Len(t, gapWarnings(inv), 1)
	assert.Contains(t, gapWarnings(inv)[0], "Shamir KEK share file(s) as plaintext")
	assert.Contains(t, gapWarnings(inv)[0], "shamir_share_env", "the warning says what to do")
	doc, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc))

	// encryption disabled is the stronger statement and wins
	off := Build(Inputs{Backup: &BackupInput{ShamirShareFiles: 3}}, DefaultPolicy(), riskNow)
	assert.Equal(t, "none", assetByID(t, off, "backup-archive").Algorithm)
	require.Len(t, gapWarnings(off), 1)
	assert.Contains(t, gapWarnings(off)[0], "encryption is disabled")
}

func TestCBOM_GapAssetsValidateAndCarryNoKeyMaterial(t *testing.T) {
	sch := compileCycloneDX16(t)
	dir := t.TempDir()
	nb, na := riskNow.Add(-time.Hour), riskNow.Add(365*24*time.Hour)
	keys := genKeys(t)

	var in Inputs
	in.EncryptionEnabled = true
	for _, k := range keys {
		enc := keys[(indexOf(keys, k)+1)%len(keys)]
		in.SAML = append(in.SAML, SAMLInput{Name: k.name, Metadata: samlMetadata(t, dir, k, enc, nb, na)})
	}
	in.SAML = append(in.SAML, SAMLInput{Name: "broken", MetadataErr: "unreadable"})
	client := writeCertPEM(t, dir, "client.pem", keys[0].pub, keys[0].priv, nb, na, true)
	ca := writeCertPEM(t, dir, "ca.pem", keys[1].pub, keys[1].priv, nb, na, true)
	in.Database = &DatabaseTLSInput{RootCertFile: ca, ClientCertFile: client, ClientKeyFile: "/k.key"}
	in.Backup = &BackupInput{EncryptionEnabled: true}

	inv := Build(in, DefaultPolicy(), riskNow)
	doc, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc), "CBOM with the gap assets must validate against CycloneDX 1.6")
	for _, id := range []string{"saml.ecdsa-p256.0", "saml.rsa-2048.0", "saml.ed25519.0", "saml.broken", "database-tls.client", "database-tls.ca.0", "backup-archive"} {
		assert.Contains(t, string(doc), "keyorix:asset:"+id)
	}
	assert.NotContains(t, string(doc), "PRIVATE KEY")

	off := Build(Inputs{Backup: &BackupInput{}}, DefaultPolicy(), riskNow)
	doc, err = off.CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc), "a plaintext-backup asset ('none' / unknown primitive) must validate too")
}

func TestBuild_DEKCreatedAtEstimatedIsMarked(t *testing.T) {
	sch := compileCycloneDX16(t)
	at := riskNow.Add(-90 * 24 * time.Hour)
	for _, tc := range []struct {
		name      string
		estimated bool
	}{{"recorded", false}, {"estimated", true}} {
		t.Run(tc.name, func(t *testing.T) {
			inv := Build(Inputs{EncryptionEnabled: true, DEKCreatedAt: &at, DEKCreatedAtEstimated: tc.estimated}, DefaultPolicy(), riskNow)
			dek := assetByID(t, inv, "dek")
			assert.Equal(t, tc.estimated, dek.CreatedAtEstimated)
			assert.Equal(t, tc.estimated, strings.Contains(dek.Notes, "estimated"))

			doc, err := inv.CBOM(CBOMOptions{})
			require.NoError(t, err)
			require.NoError(t, validate(t, sch, doc))
			assert.Equal(t, tc.estimated, strings.Contains(string(doc), "keyorix:created-at-estimated"))
		})
	}
	// no DEK time at all: nothing is marked
	inv := Build(Inputs{EncryptionEnabled: true, DEKCreatedAtEstimated: true}, DefaultPolicy(), riskNow)
	assert.False(t, assetByID(t, inv, "dek").CreatedAtEstimated)
}

// coseKeys are real COSE_Key encodings of freshly generated keys, the shape a
// passkey's public key has in the credential store.
func coseKeys(t *testing.T) map[string][]byte {
	t.Helper()
	marshal := func(v any) []byte {
		b, err := webauthncbor.Marshal(v)
		require.NoError(t, err)
		return b
	}
	pad := func(b []byte, n int) []byte { return append(make([]byte, n-len(b)), b...) }

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return map[string][]byte{
		"es256": marshal(webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
			Curve:         int64(webauthncose.P256), XCoord: pad(ec.X.Bytes(), 32), YCoord: pad(ec.Y.Bytes(), 32)}),
		"rs256": marshal(webauthncose.RSAPublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.RSAKey), Algorithm: int64(webauthncose.AlgRS256)},
			Modulus:       rk.N.Bytes(), Exponent: big.NewInt(int64(rk.E)).Bytes()}),
		"eddsa": marshal(webauthncose.OKPPublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.OctetKey), Algorithm: int64(webauthncose.AlgEdDSA)},
			Curve:         int64(webauthncose.Ed25519), XCoord: edPub}),
	}
}

func TestClassifyWebAuthnKey(t *testing.T) {
	keys := coseKeys(t)
	for name, want := range map[string]WebAuthnKey{
		"es256": {Algorithm: "ECDSA-P256 (COSE ES256)", KeySizeBits: 256},
		"rs256": {Algorithm: "RSA-2048 (COSE RS256)", KeySizeBits: 2048},
		"eddsa": {Algorithm: "Ed25519 (COSE EdDSA)", KeySizeBits: 256},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ClassifyWebAuthnKey(keys[name])
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
	for name, junk := range map[string][]byte{"empty": nil, "garbage": []byte("not cbor at all"), "truncated": keys["es256"][:10]} {
		_, err := ClassifyWebAuthnKey(junk)
		assert.Error(t, err, name)
	}
}

func TestBuild_WebAuthnCredentialsPerAlgorithm(t *testing.T) {
	sch := compileCycloneDX16(t)
	keys := coseKeys(t)
	d1, d2 := riskNow.Add(-300*24*time.Hour), riskNow.Add(-10*24*time.Hour)
	in := Inputs{WebAuthnEnabled: true, WebAuthnRPID: "keyorix.example", WebAuthnEnumerated: true,
		WebAuthnCredentials: []WebAuthnCredentialInput{
			{PublicKey: keys["es256"], CreatedAt: d2},
			{PublicKey: keys["es256"], CreatedAt: d1},
			{PublicKey: keys["rs256"], CreatedAt: d2},
			{PublicKey: keys["eddsa"], CreatedAt: d2},
			{PublicKey: []byte("junk"), CreatedAt: d2},
		}}
	inv := Build(in, DefaultPolicy(), riskNow)

	es := assetByID(t, inv, "webauthn-passkeys.ecdsa-p256-cose-es256")
	assert.Equal(t, "ECDSA-P256 (COSE ES256)", es.Algorithm)
	assert.Contains(t, es.Notes, "2 credential(s)")
	require.NotNil(t, es.CreatedAt)
	assert.WithinDuration(t, d1, *es.CreatedAt, time.Second, "oldest registration")
	assert.True(t, es.Risk.QuantumVulnerable)
	assert.Equal(t, 2048, assetByID(t, inv, "webauthn-passkeys.rsa-2048-cose-rs256").KeySizeBits)
	assert.True(t, assetByID(t, inv, "webauthn-passkeys.ed25519-cose-eddsa").Risk.QuantumVulnerable)
	unk := assetByID(t, inv, "webauthn-passkeys.unknown")
	assert.GreaterOrEqual(t, unk.Risk.Score, 40, "an unclassifiable key fails closed")
	assert.Contains(t, gapWarnings(inv)[0], "1 WebAuthn credential(s)")
	for _, a := range inv.Assets {
		assert.NotEqual(t, "webauthn-passkeys", a.ID, "the generic asset is replaced by the enumerated ones")
	}

	doc, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc))
}

func TestBuild_WebAuthnNotEnumeratedKeepsGenericAsset(t *testing.T) {
	inv := Build(Inputs{WebAuthnEnabled: true, WebAuthnRPID: "x"}, DefaultPolicy(), riskNow)
	assetByID(t, inv, "webauthn-passkeys")

	none := Build(Inputs{WebAuthnEnabled: true, WebAuthnRPID: "x", WebAuthnEnumerated: true}, DefaultPolicy(), riskNow)
	for _, a := range none.Assets {
		assert.NotEqual(t, ClassWebAuthn, a.Class, "enumerated and empty: nothing to list")
	}
	assert.Contains(t, strings.Join(none.Notes, " "), "no passkey is registered")
}

// An AKP (ML-DSA) credential is post-quantum: only its header is read, so this
// does not depend on the Go version's ML-DSA support.
func TestClassifyWebAuthnKey_MLDSAIsPostQuantum(t *testing.T) {
	b, err := webauthncbor.Marshal(webauthncose.PublicKeyData{KeyType: int64(webauthncose.AKP), Algorithm: -48})
	require.NoError(t, err)
	k, err := ClassifyWebAuthnKey(b)
	require.NoError(t, err)
	assert.True(t, k.PostQuantum)
	assert.Contains(t, k.Algorithm, "ML-DSA-44")

	inv := Build(Inputs{WebAuthnEnabled: true, WebAuthnEnumerated: true,
		WebAuthnCredentials: []WebAuthnCredentialInput{{PublicKey: b, CreatedAt: riskNow}}}, DefaultPolicy(), riskNow)
	require.Len(t, inv.Assets, 1)
	assert.False(t, inv.Assets[0].Risk.QuantumVulnerable)
	assert.Equal(t, LevelLow, inv.Assets[0].Risk.Level)
}

// Review findings (#3754): an AKP key whose algorithm is not ML-DSA is
// unclassifiable, not post-quantum. An EC2 key on a curve outside P-256/384/521
// (e.g. secp256k1) is unclassifiable, not "ECDSA-P0": go-webauthn v0.18.2's
// ParsePublicKey already rejects it, so that half passes without
// ClassifyWebAuthnKey's own curve check, which is kept in case a later
// go-webauthn accepts more curves.
func TestClassifyWebAuthnKey_UnmodelledAKPAlgAndEC2CurveAreUnclassifiable(t *testing.T) {
	akp, err := webauthncbor.Marshal(webauthncose.PublicKeyData{KeyType: int64(webauthncose.AKP), Algorithm: -7})
	require.NoError(t, err)
	_, err = ClassifyWebAuthnKey(akp)
	assert.Error(t, err, "AKP with a non-ML-DSA alg must not be classified post-quantum")

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k1, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         8, // secp256k1, under an alg go-webauthn parses
		XCoord:        ec.X.FillBytes(make([]byte, 32)),
		YCoord:        ec.Y.FillBytes(make([]byte, 32)),
	})
	require.NoError(t, err)
	_, err = ClassifyWebAuthnKey(k1)
	assert.Error(t, err, "an unmodelled curve must not be labelled ECDSA-P0")
}
