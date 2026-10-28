package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTestClientPair writes a matching client certificate and PKCS#8 key into
// dir and returns their paths and the certificate's DER.
func writeTestClientPair(t *testing.T, dir, prefix string) (certPath, keyPath string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: prefix},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPath, keyPath = filepath.Join(dir, prefix+".crt"), filepath.Join(dir, prefix+".key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath, der
}

// TestDSNClientCert_AgreesWithPgx is the drift guard for parseDSNTLS's sslcert
// and sslkey (DatabaseTLSFilesOf's ClientCert/ClientKey, which the crypto
// inventory lists): for each connection string, the client certificate pgx
// loads into TLSConfig.Certificates is the file parseDSNTLS names, and pgx loads
// none when parseDSNTLS names none. It covers quoting and escapes, percent-
// encoded URL values, "+" in URL values and repeated keys (last wins). It does
// not cover PGSSLCERT/PGSSLKEY or libpq's ~/.postgresql defaults, which
// DatabaseTLSFilesOf does not report (cleared here).
func TestDSNClientCert_AgreesWithPgx(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PGSSLCERT", "")
	t.Setenv("PGSSLKEY", "")
	t.Setenv("PGSERVICE", "")

	dir := filepath.Join(t.TempDir(), "pg dir+x")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	cert, key, der := writeTestClientPair(t, dir, "client'a")
	decoyCert, decoyKey, _ := writeTestClientPair(t, dir, "decoy")

	dsns := []string{
		"host=db sslmode=require sslcert=" + quoteDSNValue(cert) + " sslkey=" + quoteDSNValue(key),
		"host=db sslmode=verify-ca sslcert = " + quoteDSNValue(cert) + "   sslkey =" + quoteDSNValue(key) + " sslrootcert=system",
		"host=db sslmode=require sslcert=" + quoteDSNValue(decoyCert) + " sslkey=" + quoteDSNValue(decoyKey) +
			" sslcert=" + quoteDSNValue(cert) + " sslkey=" + quoteDSNValue(key),
		"postgres://u@db/k?sslmode=require&sslcert=" + url.PathEscape(cert) + "&sslkey=" + url.PathEscape(key),
		"postgres://u@db/k?sslmode=require&sslcert=" + url.PathEscape(decoyCert) + "&sslkey=" + url.PathEscape(decoyKey) +
			"&sslcert=" + url.PathEscape(cert) + "&sslkey=" + url.PathEscape(key),
		"host=db sslmode=require",
		"postgres://u@db/k?sslmode=require",
	}
	for _, dsn := range dsns {
		t.Run(dsn, func(t *testing.T) {
			pc, perr := pgconn.ParseConfig(dsn)
			s, err := parseDSNTLS(dsn)
			require.NoError(t, err)
			if s.sslcert == "" {
				require.NoError(t, perr)
				require.NotNil(t, pc.TLSConfig)
				assert.Empty(t, pc.TLSConfig.Certificates, "pgx loads a client certificate parseDSNTLS does not report")
				assert.Empty(t, s.sslkey)
				return
			}
			require.NoError(t, perr, "the corpus must be DSNs pgx accepts")
			assert.Equal(t, cert, s.sslcert)
			assert.Equal(t, key, s.sslkey)
			require.NotNil(t, pc.TLSConfig)
			require.Len(t, pc.TLSConfig.Certificates, 1)
			require.NotEmpty(t, pc.TLSConfig.Certificates[0].Certificate)
			assert.Equal(t, der, pc.TLSConfig.Certificates[0].Certificate[0], "pgx loaded a different client certificate")
		})
	}
}
