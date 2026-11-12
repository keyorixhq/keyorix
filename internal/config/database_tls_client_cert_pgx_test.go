package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
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

// clientCertsPgxSends connects pc to a loopback server that speaks just enough
// of the PostgreSQL SSLRequest exchange to run a TLS handshake which requests
// (without verifying) a client certificate, and returns the DER of the chain pgx
// presented. Since pgx v5.13.0 ParseConfig no longer fills TLSConfig.Certificates:
// sslcert/sslkey are loaded lazily when a connection attempt is made, so the
// handshake is the only public place the loaded certificate can be observed.
func clientCertsPgxSends(t *testing.T, pc *pgconn.Config) [][]byte {
	t.Helper()
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "db"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, srvTmpl, &srvKey.PublicKey, srvKey)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	got := make(chan [][]byte, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			got <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		var req [8]byte // SSLRequest: int32 length (8), int32 code (80877103)
		if _, rerr := io.ReadFull(conn, req[:]); rerr != nil {
			got <- nil
			return
		}
		if _, werr := conn.Write([]byte{'S'}); werr != nil {
			got <- nil
			return
		}
		tc := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
			ClientAuth:   tls.RequestClientCert,
			MinVersion:   tls.VersionTLS12,
		})
		if herr := tc.Handshake(); herr != nil {
			got <- nil
			return
		}
		var chain [][]byte
		for _, c := range tc.ConnectionState().PeerCertificates {
			chain = append(chain, c.Raw)
		}
		got <- chain
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := pc.Copy() // keeps the lazy sslcert/sslkey loader that Copy documents
	cfg.Host, cfg.Port = "127.0.0.1", uint16(addr.Port)
	cfg.Fallbacks = nil
	cfg.ConnectTimeout = 5 * time.Second
	// The test server's certificate is throwaway; this is a handshake probe, not a
	// connection, and only the client side of the exchange is under test.
	cfg.TLSConfig.InsecureSkipVerify = true // #nosec G402 -- loopback probe
	cfg.TLSConfig.VerifyPeerCertificate = nil
	cfg.TLSConfig.VerifyConnection = nil

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, cerr := pgconn.ConnectConfig(ctx, cfg); cerr == nil {
		_ = c.Close(ctx)
	}
	select {
	case chain := <-got:
		return chain
	case <-time.After(10 * time.Second):
		t.Fatal("loopback TLS server never saw a handshake")
		return nil
	}
}

// TestDSNClientCert_AgreesWithPgx is the drift guard for parseDSNTLS's sslcert
// and sslkey (DatabaseTLSFilesOf's ClientCert/ClientKey, which the crypto
// inventory lists): for each connection string, the client certificate pgx
// presents in a TLS handshake is the file parseDSNTLS names, and pgx loads
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
				assert.Empty(t, clientCertsPgxSends(t, pc), "pgx loads a client certificate parseDSNTLS does not report")
				assert.Empty(t, s.sslkey)
				return
			}
			require.NoError(t, perr, "the corpus must be DSNs pgx accepts")
			assert.Equal(t, cert, s.sslcert)
			assert.Equal(t, key, s.sslkey)
			require.NotNil(t, pc.TLSConfig)
			sent := clientCertsPgxSends(t, pc)
			require.Len(t, sent, 1, "pgx presented no client certificate")
			assert.Equal(t, der, sent[0], "pgx loaded a different client certificate")
		})
	}
}
