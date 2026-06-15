package notary

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTSA stands up an in-process RFC 3161 Time-Stamp Authority backed by a
// self-signed timestamping cert. It parses each request and returns a real signed
// TimeStampToken stamped at fixedTime, so the client path is exercised end to end.
func newTestTSA(t *testing.T, fixedTime time.Time) (*httptest.Server, crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},
		NotBefore:             fixedTime.Add(-time.Hour),
		NotAfter:              fixedTime.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, "parse", http.StatusBadRequest)
			return
		}
		ts := &timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              fixedTime,
			Nonce:             req.Nonce,
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
			SerialNumber:      big.NewInt(42),
			AddTSACertificate: true, // embed the signing cert so the token is self-contained
		}
		resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			http.Error(w, "create: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, key, cert
}

func TestRFC3161_AnchorAndVerifyRoundTrip(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	srv, _, cert := newTestTSA(t, fixedTime)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	msg := []byte("v1\x00128\x0099\x00deadbeef\x00v1")
	rec, err := NewRFC3161(srv.URL, 5*time.Second).Anchor(context.Background(), msg)
	require.NoError(t, err)
	require.NotEmpty(t, rec.Token)
	assert.WithinDuration(t, fixedTime, rec.Time, time.Second)
	assert.Equal(t, "rfc3161:"+srv.URL, rec.Provider)

	// The receipt verifies against the original message + trusted root, yielding the TSA time.
	at, err := VerifyReceipt(roots, msg, rec.Token)
	require.NoError(t, err)
	assert.WithinDuration(t, fixedTime, at, time.Second)

	// A different message must NOT verify against the same token.
	_, err = VerifyReceipt(roots, []byte("v1\x00129\x0099\x00deadbeef\x00v1"), rec.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not bind")

	// A token from an UNTRUSTED issuer (empty/other root pool) must be rejected —
	// this is the trust-anchor check that stops a DB+DEK attacker forging a token.
	_, err = VerifyReceipt(x509.NewCertPool(), msg, rec.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not trusted")

	// A nil trust anchor fails closed rather than asserting an unverifiable proof.
	_, err = VerifyReceipt(nil, msg, rec.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust anchor")
}

func TestVerifyReceipt_Errors(t *testing.T) {
	roots := x509.NewCertPool()
	t.Run("empty token", func(t *testing.T) {
		_, err := VerifyReceipt(roots, []byte("m"), nil)
		require.Error(t, err)
	})
	t.Run("garbage token", func(t *testing.T) {
		_, err := VerifyReceipt(roots, []byte("m"), []byte("not-a-token"))
		require.Error(t, err)
	})
}

func TestRFC3161_Anchor_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	_, err := NewRFC3161(srv.URL, 5*time.Second).Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 503")
}

func TestRFC3161_Anchor_GarbageResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-a-timestamp-response"))
	}))
	t.Cleanup(srv.Close)
	_, err := NewRFC3161(srv.URL, 5*time.Second).Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
}
