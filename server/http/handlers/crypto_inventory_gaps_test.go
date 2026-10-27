package handlers

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
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
)

// selfSignedDER returns a real self-signed certificate for pub/priv.
func selfSignedDER(t *testing.T, pub, priv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "gap.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(120 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	return der
}

func TestCryptoInventoryHandler_GapAssets(t *testing.T) {
	f := newCryptoInvFixture(t)
	dir := t.TempDir()

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	meta := func(der []byte) string {
		return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor>`+
			`<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>`+
			`</IDPSSODescriptor></EntityDescriptor>`, base64.StdEncoding.EncodeToString(der))
	}
	// the second provider reads its metadata from a file, the third from a missing one
	rsaMetaPath := filepath.Join(dir, "rsa-meta.xml")
	require.NoError(t, os.WriteFile(rsaMetaPath, []byte(meta(selfSignedDER(t, &rk.PublicKey, rk))), 0o600))
	f.cfg.SSO = config.SSOConfig{Enabled: true, Providers: []config.SSOProviderConfig{
		{Name: "okta", Type: "saml", SAML: &config.SAMLProviderConfig{IDPMetadataXML: meta(selfSignedDER(t, &ec.PublicKey, ec))}},
		{Name: "adfs", Type: "saml", SAML: &config.SAMLProviderConfig{IDPMetadataFile: rsaMetaPath}},
		{Name: "gone", Type: "saml", SAML: &config.SAMLProviderConfig{IDPMetadataFile: filepath.Join(dir, "missing.xml")}},
	}}

	clientPath := filepath.Join(dir, "client.crt")
	require.NoError(t, os.WriteFile(clientPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedDER(t, edPub, edPriv)}), 0o600))
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedDER(t, &ec.PublicKey, ec)}), 0o600))
	f.cfg.Storage.Type = "postgres"
	f.cfg.Storage.Database.DSN = "host=db user=k password=hunter2 sslmode=verify-full sslrootcert=" + caPath +
		" sslcert=" + clientPath + " sslkey=/pg/client.key"

	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data cryptoinventory.Inventory `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	byID := map[string]cryptoinventory.Asset{}
	for _, a := range env.Data.Assets {
		byID[a.ID] = a
	}
	assert.Equal(t, "ECDSA-P256", byID["saml.okta.0"].Algorithm)
	assert.Equal(t, "RSA-2048", byID["saml.adfs.0"].Algorithm)
	assert.Equal(t, "unknown", byID["saml.gone"].Algorithm)
	assert.Equal(t, "Ed25519", byID["database-tls.client"].Algorithm)
	assert.Equal(t, "ECDSA-P256", byID["database-tls.ca.0"].Algorithm)
	assert.Equal(t, "AES-256-GCM", byID["backup-archive"].Algorithm)
	assert.Contains(t, w.Body.String(), `\"gone\" signing certificates could not be inspected`)
	assert.NotContains(t, w.Body.String(), "hunter2", "the dsn password is never echoed")
	assert.NotContains(t, w.Body.String(), "BEGIN CERTIFICATE")

	cbom := f.get(t, "?format=cbom", true)
	require.Equal(t, http.StatusOK, cbom.Code)
	assert.Contains(t, cbom.Body.String(), "keyorix:asset:database-tls.client")
}

func TestCryptoInventoryHandler_BadDatabaseTLSIsAWarning(t *testing.T) {
	f := newCryptoInvFixture(t)
	f.cfg.Storage.Type = "postgres"
	f.cfg.Storage.Database.DSN = "host=db sslmode=bogus"
	w := f.get(t, "", true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "database TLS settings could not be read")
}
