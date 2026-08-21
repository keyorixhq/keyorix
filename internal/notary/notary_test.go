package notary

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test TSA"},
		// Wide validity so the test is never time-bombed: the in-process TSA signs at
		// real wall-clock time (the embedded CMS signingTime is "now"), so the cert
		// must cover real now, not just the fixed genTime.
		NotBefore:             fixedTime.Add(-365 * 24 * time.Hour),
		NotAfter:              fixedTime.Add(3650 * 24 * time.Hour),
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
	tsa, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)
	rec, err := tsa.Anchor(context.Background(), msg)
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
	tsa, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)
	_, err = tsa.Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 503")
}

func TestRFC3161_Anchor_GarbageResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-a-timestamp-response"))
	}))
	t.Cleanup(srv.Close)
	tsa, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)
	_, err = tsa.Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
}

// buildTestCert issues a certificate for tmpl, signed by (parentTmpl, parentKey),
// or self-signed when parentTmpl/parentKey are nil.
func buildTestCert(t *testing.T, tmpl *x509.Certificate, parentTmpl *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signParentTmpl, signKey := tmpl, crypto.Signer(key)
	if parentTmpl != nil {
		signParentTmpl, signKey = parentTmpl, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signParentTmpl, &key.PublicKey, signKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// TestVerifyReceipt_TrustsChainThroughIntermediateCA exercises the intermediates
// pool notary.go's VerifyReceipt builds from p7.Certificates (the
// `for _, c := range p7.Certificates { intermediates.AddCert(c) }` loop): a token
// whose embedded chain is leaf -> intermediate -> root, where only the ROOT sits
// in the configured trust anchor, must still verify. TestRFC3161_AnchorAndVerifyRoundTrip
// only ever exercises a leaf that IS the root (self-signed, directly trusted), so
// it never actually requires that intermediates pool to do anything; this pins
// the genuine multi-hop chain-building behavior.
func TestVerifyReceipt_TrustsChainThroughIntermediateCA(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	validity := func(tmpl *x509.Certificate) {
		tmpl.NotBefore = fixedTime.Add(-365 * 24 * time.Hour)
		tmpl.NotAfter = fixedTime.Add(3650 * 24 * time.Hour)
		tmpl.BasicConstraintsValid = true
	}

	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root CA"}, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true}
	validity(rootTmpl)
	rootCert, rootKey := buildTestCert(t, rootTmpl, nil, nil)

	intTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate CA"}, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true}
	validity(intTmpl)
	intCert, intKey := buildTestCert(t, intTmpl, rootTmpl, rootKey)

	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Test TSA Leaf"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	validity(leafTmpl)
	leafCert, leafKey := buildTestCert(t, leafTmpl, intTmpl, intKey)

	msg := []byte("chain verification message")
	want := sha256.Sum256(msg)

	// The token embeds the leaf AND the intermediate (Certificates: parents),
	// mirroring what a real TSA operating behind an intermediate CA would send.
	ts := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     want[:],
		Time:              fixedTime,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      big.NewInt(42),
		Certificates:      []*x509.Certificate{intCert},
		AddTSACertificate: true,
	}
	resp, err := ts.CreateResponseWithOpts(leafCert, leafKey, crypto.SHA256)
	require.NoError(t, err)
	parsed, err := timestamp.ParseResponse(resp)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert) // only the ROOT is trusted — leaf+intermediate arrive via the token

	at, err := VerifyReceipt(roots, msg, parsed.RawToken)
	require.NoError(t, err)
	assert.WithinDuration(t, fixedTime, at, time.Second)

	// Sanity: a token from the SAME leaf but with the intermediate withheld (so no
	// path from leaf to the trusted root can be built) must fail — confirming the
	// pass above genuinely depended on the intermediate being embedded, not on
	// some unrelated path.
	tsNoChain := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     want[:],
		Time:              fixedTime,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      big.NewInt(43),
		AddTSACertificate: true, // embeds ONLY the leaf, no parents
	}
	respNoChain, err := tsNoChain.CreateResponseWithOpts(leafCert, leafKey, crypto.SHA256)
	require.NoError(t, err)
	parsedNoChain, err := timestamp.ParseResponse(respNoChain)
	require.NoError(t, err)

	_, err = VerifyReceipt(roots, msg, parsedNoChain.RawToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not trusted")
}
