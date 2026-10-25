package cryptoinventory

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeCertPEM writes a self-signed certificate for priv to dir. When combined is
// true the PRIVATE KEY block is appended to the same file (a common deployment
// shape) so tests can prove the inventory never reads or emits it.
func writeCertPEM(t *testing.T, dir, name string, pub, priv any, notBefore, notAfter time.Time, combined bool) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "keyorix.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if combined {
		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	}
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, out, 0o600))
	return p
}

func TestLoadLeafCertificate_AlgorithmsAndSizes(t *testing.T) {
	dir := t.TempDir()
	nb, na := riskNow.Add(-time.Hour), riskNow.Add(90*24*time.Hour)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		path      string
		wantAlg   string
		wantBits  int
		wantCurve string
	}{
		{"ecdsa", writeCertPEM(t, dir, "ec.pem", &ec.PublicKey, ec, nb, na, false), "ECDSA-P256", 256, "P-256"},
		{"ed25519", writeCertPEM(t, dir, "ed.pem", edPub, edPriv, nb, na, false), "Ed25519", 256, "Ed25519"},
		{"rsa", writeCertPEM(t, dir, "rsa.pem", &rsaKey.PublicKey, rsaKey, nb, na, false), "RSA-2048", 2048, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := LoadCertificateInfo(tc.path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAlg, info.KeyAlgorithm)
			assert.Equal(t, tc.wantBits, info.KeySizeBits)
			assert.Equal(t, tc.wantCurve, info.Curve)
			assert.WithinDuration(t, nb, info.NotBefore, time.Second)
			assert.WithinDuration(t, na, info.NotAfter, time.Second)
			assert.NotEmpty(t, info.SignatureAlgorithm)
		})
	}
}

func TestLoadCertificateInfo_Errors(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCertificateInfo(filepath.Join(dir, "missing.pem"))
	assert.Error(t, err)

	junk := filepath.Join(dir, "junk.pem")
	require.NoError(t, os.WriteFile(junk, []byte("not a pem"), 0o600))
	_, err = LoadCertificateInfo(junk)
	assert.Error(t, err)

	keyOnly := filepath.Join(dir, "key.pem")
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	require.NoError(t, os.WriteFile(keyOnly, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	_, err = LoadCertificateInfo(keyOnly)
	assert.Error(t, err, "a file holding only a private key is not a certificate and must be refused")
	assert.NotContains(t, err.Error(), "PRIVATE", "errors must not echo file content")
}

func fullInputs(t *testing.T) (Inputs, []byte) {
	t.Helper()
	dir := t.TempDir()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certPath := writeCertPEM(t, dir, "tls.pem", &ec.PublicKey, ec, riskNow.Add(-time.Hour), riskNow.Add(60*24*time.Hour), true)
	keyDER, err := x509.MarshalPKCS8PrivateKey(ec)
	require.NoError(t, err)

	created := riskNow.Add(-400 * 24 * time.Hour)
	rot := riskNow.Add(-30 * 24 * time.Hour)
	return Inputs{
		EncryptionEnabled: true,
		KeyProvider:       "password",
		DEKPath:           "keys/dek.key",
		DEKCreatedAt:      &created,
		TLS: []TLSInput{
			{Name: "http", CertFile: certPath, KeyFile: "/etc/keyorix/tls.key"},
		},
		Recovery:        &RecoveryInput{KeyVersion: 2, CreatedAt: created, RotatedAt: &rot},
		WebAuthnEnabled: true,
		WebAuthnRPID:    "keyorix.example.com",
		OIDCIssuers:     []string{"https://idp.example.com"},
	}, keyDER
}

func TestBuild_CoversEveryKeyClass(t *testing.T) {
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)

	byClass := map[Class]int{}
	for _, a := range inv.Assets {
		byClass[a.Class]++
	}
	for _, c := range []Class{ClassKEK, ClassDEK, ClassRecoveryKey, ClassTLSCertificate, ClassSigningKey, ClassAuditHMACKey, ClassWebAuthn, ClassJWTKey} {
		assert.Positive(t, byClass[c], "class %s missing from inventory", c)
	}
	ids := map[string]bool{}
	for _, a := range inv.Assets {
		assert.False(t, ids[a.ID], "duplicate asset id %s", a.ID)
		ids[a.ID] = true
		assert.NotEmpty(t, a.Name)
		assert.NotEmpty(t, a.Storage, "asset %s must say where it is stored", a.ID)
		assert.NotEmpty(t, a.Algorithm)
		assert.NotEmpty(t, a.Risk.Level)
	}
}

func TestBuild_FlagsClassicalKeysAndNotAES(t *testing.T) {
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)
	get := func(id string) Asset {
		for _, a := range inv.Assets {
			if a.ID == id {
				return a
			}
		}
		t.Fatalf("asset %q not in inventory", id)
		return Asset{}
	}
	assert.True(t, get("tls.http").Risk.QuantumVulnerable)
	assert.True(t, get("webauthn-passkeys").Risk.QuantumVulnerable)
	assert.True(t, get("oidc-jwks.0").Risk.QuantumVulnerable)
	assert.False(t, get("dek").Risk.QuantumVulnerable)
	assert.Equal(t, LevelLow, get("dek").Risk.Level)
	assert.False(t, get("audit-checkpoint-hmac").Risk.QuantumVulnerable)

	assert.GreaterOrEqual(t, inv.Summary.QuantumVulnerable, 3)
	assert.Equal(t, len(inv.Assets), inv.Summary.Total)
	assert.Equal(t, inv.Summary.High+inv.Summary.Medium+inv.Summary.Low, inv.Summary.Total)
}

func TestBuild_SortedByRiskThenID(t *testing.T) {
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)
	for i := 1; i < len(inv.Assets); i++ {
		p, c := inv.Assets[i-1], inv.Assets[i]
		if p.Risk.Score == c.Risk.Score {
			assert.Less(t, p.ID, c.ID)
		} else {
			assert.Greater(t, p.Risk.Score, c.Risk.Score)
		}
	}
}

func TestBuild_KEKByProvider(t *testing.T) {
	kek := func(in Inputs) Asset {
		in.EncryptionEnabled = true
		for _, a := range Build(in, DefaultPolicy(), riskNow).Assets {
			if a.ID == "kek" {
				return a
			}
		}
		t.Fatal("kek missing")
		return Asset{}
	}
	pw := kek(Inputs{KeyProvider: "password"})
	assert.Equal(t, "kdf", pw.Primitive)
	assert.Contains(t, pw.Algorithm, "PBKDF2")
	assert.False(t, pw.Risk.QuantumVulnerable)

	tpm := kek(Inputs{KeyProvider: "tpm", KeyProviderRef: "/dev/tpmrm0"})
	assert.Contains(t, tpm.Storage, "TPM")

	aws := kek(Inputs{KeyProvider: "aws-kms", KeyProviderRef: "alias/keyorix"})
	assert.False(t, aws.Risk.QuantumVulnerable, "AES-256 symmetric KMS wrap")

	az := kek(Inputs{KeyProvider: "azure-kms", KeyProviderRef: "https://v.vault.azure.net/keys/k"})
	assert.True(t, az.Risk.QuantumVulnerable, "azure-kms wraps the KEK with RSA-OAEP: harvest-now-decrypt-later exposure")
	assert.Contains(t, az.Algorithm, "RSA")
}

func TestBuild_EncryptionDisabledSaysSo(t *testing.T) {
	inv := Build(Inputs{EncryptionEnabled: false}, DefaultPolicy(), riskNow)
	for _, a := range inv.Assets {
		assert.NotContains(t, []string{"kek", "dek", "audit-checkpoint-hmac", "evidence-hmac", "backup-manifest-hmac"}, a.ID,
			"no KEK/DEK-derived key exists when encryption is disabled")
	}
	require.NotEmpty(t, inv.Warnings, "plaintext-at-rest must surface as a warning, not silence")
	assert.Contains(t, strings.ToLower(strings.Join(inv.Warnings, " ")), "encryption is disabled")
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestBuild_UnreadableCertIsReportedNotDropped(t *testing.T) {
	inv := Build(Inputs{
		EncryptionEnabled: true,
		TLS:               []TLSInput{{Name: "grpc", CertFile: filepath.Join(t.TempDir(), "nope.pem")}},
	}, DefaultPolicy(), riskNow)
	var found bool
	for _, a := range inv.Assets {
		if a.ID == "tls.grpc" {
			found = true
			assert.NotEqual(t, LevelLow, a.Risk.Level, "an unreadable certificate cannot be assumed safe")
		}
	}
	assert.True(t, found, "unreadable certificate must stay in the inventory")
	require.NotEmpty(t, inv.Warnings)
	assert.Contains(t, strings.Join(inv.Warnings, " "), "grpc")
}

func TestBuild_AutoCertListedWithoutFile(t *testing.T) {
	inv := Build(Inputs{EncryptionEnabled: true, TLS: []TLSInput{{Name: "http", AutoCert: true}}}, DefaultPolicy(), riskNow)
	var found bool
	for _, a := range inv.Assets {
		if a.ID == "tls.http" {
			found = true
			assert.Contains(t, strings.ToLower(a.Storage), "acme")
		}
	}
	assert.True(t, found)
}

// The central safety property of this feature: the inventory is metadata only.
func TestBuild_NeverEmitsKeyMaterial(t *testing.T) {
	in, keyDER := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)

	j, err := json.Marshal(inv)
	require.NoError(t, err)
	cbom, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)

	for name, doc := range map[string][]byte{"json": j, "cbom": cbom} {
		s := string(doc)
		assert.NotContains(t, s, "PRIVATE KEY", name)
		assert.NotContains(t, s, "BEGIN CERTIFICATE", name, "the PEM body is not needed; only parsed metadata")
		assert.NotContains(t, s, base64Std(keyDER), name)
		assert.NotContains(t, s, base64Std(keyDER[len(keyDER)-24:]), name, "even a fragment of the key")
	}
}

func TestAssetJSONHasNoSecretFields(t *testing.T) {
	b, err := json.Marshal(Asset{})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	for k := range m {
		lk := strings.ToLower(k)
		for _, bad := range []string{"value", "secret", "private", "material", "pem", "password", "passphrase"} {
			assert.NotContains(t, lk, bad, "Asset JSON field %q looks like it carries secret material", k)
		}
	}
}
