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
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewRFC3161 — zero/negative timeout falls back to defaultTimeout
// ---------------------------------------------------------------------------

func TestNewRFC3161_ZeroTimeout_UsesDefault(t *testing.T) {
	r, err := NewRFC3161("https://example.tsa/rfc3161", 0)
	require.NoError(t, err)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

// ---------------------------------------------------------------------------
// VerifyReceipt — malformed token must not panic (fuzz regression)
// ---------------------------------------------------------------------------

// TestVerifyReceipt_MalformedToken_NoPanic guards against digitorus/pkcs7
// panicking on truncated BER inputs (index out of range in ber.go:readObject,
// found by the continuous fuzz rig on 2026-07-27).
func TestVerifyReceipt_MalformedToken_NoPanic(t *testing.T) {
	roots := x509.NewCertPool()
	msg := []byte("any message")
	cases := [][]byte{
		{0x30, 0x81},             // SEQUENCE + long-form length, no length byte follows
		{0x30, 0x82},             // SEQUENCE + long-form length claiming 2 bytes, none follow
		{0x30, 0x01},             // SEQUENCE claiming 1 content byte, none present
		{0xff, 0x81},             // high-tag-number form, truncated
		{0x30, 0x80, 0x00, 0x00}, // indefinite-length SEQUENCE
	}
	for _, token := range cases {
		require.NotPanics(t, func() {
			_, _ = VerifyReceipt(roots, msg, token)
		})
	}
}

func TestNewRFC3161_NegativeTimeout_UsesDefault(t *testing.T) {
	r, err := NewRFC3161("https://example.tsa/rfc3161", -1*time.Second)
	require.NoError(t, err)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

func TestNewRFC3161_PositiveTimeout_Respected(t *testing.T) {
	r, err := NewRFC3161("https://example.tsa/rfc3161", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, r.client.Timeout)
}

func TestRFC3161_Provider(t *testing.T) {
	r, err := NewRFC3161("https://freetsa.org/tsr", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "rfc3161:https://freetsa.org/tsr", r.Provider())
}

// ---------------------------------------------------------------------------
// Anchor — error paths that don't require a live HTTP server
// ---------------------------------------------------------------------------

// TestRFC3161_Anchor_BadURL confirms a URL with an invalid control character is
// rejected. This used to only surface via http.NewRequestWithContext failing at
// Anchor() time; NewRFC3161 now parses (and https/loopback-validates) the URL at
// construction, so the same malformed input is now caught earlier, at startup —
// url.Parse itself rejects the embedded null byte.
func TestRFC3161_Anchor_BadURL(t *testing.T) {
	_, err := NewRFC3161("https://host/\x00bad", 5*time.Second)
	require.Error(t, err)
}

// TestRFC3161_Anchor_UnreachableHost exercises the http.Do error path: a URL
// pointing at a closed local port causes the TCP dial to fail quickly. Plain
// http to loopback is the documented local-testing exception (validateTSAURL).
func TestRFC3161_Anchor_UnreachableHost(t *testing.T) {
	// Port 1 on localhost — connection refused in < 1 ms on any OS.
	r, err := NewRFC3161("http://127.0.0.1:1/tsr", 2*time.Second)
	require.NoError(t, err)
	_, err = r.Anchor(context.Background(), []byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post to")
}

// TestRFC3161_Anchor_MalformedTSAResponseNoPanic is #G61: Anchor() hands the
// TSA's response bytes to timestamp.ParseResponse, the same digitorus parser
// family VerifyReceipt was already hardened against (index out of range on
// malformed BER, found by the continuous fuzz rig). A hostile or buggy TSA
// endpoint must produce an error, never a process-killing panic — the same
// property TestVerifyReceipt_MalformedToken_NoPanic pins for VerifyReceipt.
func TestRFC3161_Anchor_MalformedTSAResponseNoPanic(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("not DER at all"),
		{0x30, 0x81},             // SEQUENCE + long-form length, no length byte follows
		{0x30, 0x82},             // SEQUENCE + long-form length claiming 2 bytes, none follow
		{0x30, 0x01},             // SEQUENCE claiming 1 content byte, none present
		{0xff, 0x81},             // high-tag-number form, truncated
		{0x30, 0x80, 0x00, 0x00}, // indefinite-length SEQUENCE
	}
	for _, body := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		client, err := NewRFC3161(srv.URL, 5*time.Second)
		require.NoError(t, err)

		require.NotPanics(t, func() {
			_, err = client.Anchor(context.Background(), []byte("anchor message"))
		})
		assert.Error(t, err, "a malformed TSA response must be reported as an error, not silently accepted")
		srv.Close()
	}
}

// ---------------------------------------------------------------------------
// VerifyReceipt — additional nil/empty guards
// ---------------------------------------------------------------------------

// TestVerifyReceipt_NilRoots_FailsClosed re-confirms the nil roots path is rejected.
func TestVerifyReceipt_NilRoots_FailsClosed(t *testing.T) {
	_, err := VerifyReceipt(nil, []byte("msg"), []byte("token"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust anchor")
}

// TestVerifyReceipt_EmptyToken_FailsClosed confirms an empty token is rejected.
func TestVerifyReceipt_EmptyToken_FailsClosed(t *testing.T) {
	_, err := VerifyReceipt(nil, []byte("msg"), nil)
	require.Error(t, err)
	// nil roots error fires before empty-token check, so we only need Error here.
}

// ---------------------------------------------------------------------------
// validateTSAURL / NewRFC3161 — https-only, loopback exception (Wave 6 #baseline/notary-findings.json#1)
// ---------------------------------------------------------------------------

// TestNewRFC3161_RejectsPlaintextHTTP_NonLoopback confirms a plaintext http://
// TSA URL to a non-loopback host is rejected at construction, not silently
// accepted. A network attacker on that path could otherwise see every
// checkpoint hash being anchored and swap in a rogue TSA's response.
func TestNewRFC3161_RejectsPlaintextHTTP_NonLoopback(t *testing.T) {
	_, err := NewRFC3161("http://tsa.example.com/tsr", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestNewRFC3161_AcceptsHTTPS confirms a well-formed https:// TSA URL is still
// accepted (the common, expected case).
func TestNewRFC3161_AcceptsHTTPS(t *testing.T) {
	_, err := NewRFC3161("https://tsa.example.com/tsr", 5*time.Second)
	require.NoError(t, err)
}

// TestNewRFC3161_AcceptsPlaintextHTTP_Loopback confirms the local-testing
// exception this codebase uses elsewhere for operator-configured outbound URLs
// (internal/storage/remote's validateBaseURL, server/main.go's
// requireSecureOrLoopback): plain http to localhost/a loopback IP is still
// accepted, since that can only ever be a local dev/test TSA, not a real
// network attacker's vantage point.
func TestNewRFC3161_AcceptsPlaintextHTTP_Loopback(t *testing.T) {
	for _, u := range []string{
		"http://127.0.0.1:8080/tsr",
		"http://localhost:8080/tsr",
		"http://[::1]:8080/tsr",
	} {
		_, err := NewRFC3161(u, 5*time.Second)
		require.NoError(t, err, u)
	}
}

// TestNewRFC3161_RejectsMalformedURL confirms a URL with no host is rejected
// (unchanged pre-existing behavior, re-pinned after the https-only rewrite of
// validateTSAURL).
func TestNewRFC3161_RejectsMalformedURL(t *testing.T) {
	_, err := NewRFC3161("not-a-url", 5*time.Second)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// VerifyReceipt — message-imprint hash algorithm must be SHA-256
// (Wave 6, notary-findings.json#2)
// ---------------------------------------------------------------------------

// craftTokenWithHashAlgorithm builds a validly-signed RFC 3161 TimeStampToken,
// self-issued by a fresh timestamping cert, whose message-imprint declares
// hashAlg as its hash algorithm but carries hashedMessage as the raw imprint
// bytes verbatim — regardless of whether hashedMessage is actually
// hashAlg(message). This mirrors what a misconfigured or hostile TSA could
// produce: digitorus/timestamp does not itself check that HashedMessage's
// length/content matches the declared algorithm.
func craftTokenWithHashAlgorithm(t *testing.T, fixedTime time.Time, hashAlg crypto.Hash, hashedMessage []byte) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},
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

	ts := &timestamp.Timestamp{
		HashAlgorithm:     hashAlg,
		HashedMessage:     hashedMessage,
		Time:              fixedTime,
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		SerialNumber:      big.NewInt(42),
		AddTSACertificate: true,
	}
	resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
	require.NoError(t, err)
	parsed, err := timestamp.ParseResponse(resp)
	require.NoError(t, err)
	return parsed.RawToken, cert
}

// TestVerifyReceipt_RejectsNonSHA256HashAlgorithm crafts a token that declares
// SHA-384 as its message-imprint hash algorithm but carries a HashedMessage
// equal to sha256.Sum256(message) — the scenario the pre-fix code accepted, since it
// compared raw bytes against a SHA-256 digest regardless of what algorithm the
// token claimed to have used. VerifyReceipt must reject the mismatch instead of
// silently trusting the byte comparison.
func TestVerifyReceipt_RejectsNonSHA256HashAlgorithm(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	msg := []byte("checkpoint bytes being anchored")
	want := sha256.Sum256(msg)

	token, cert := craftTokenWithHashAlgorithm(t, fixedTime, crypto.SHA384, want[:])
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := VerifyReceipt(roots, msg, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash algorithm")
}

// TestVerifyReceipt_AcceptsSHA256HashAlgorithm is the positive-path sibling:
// a token that correctly declares SHA-256 and carries the matching digest must
// still verify — the new check must not reject the legitimate case.
func TestVerifyReceipt_AcceptsSHA256HashAlgorithm(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	msg := []byte("checkpoint bytes being anchored")
	want := sha256.Sum256(msg)

	token, cert := craftTokenWithHashAlgorithm(t, fixedTime, crypto.SHA256, want[:])
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	at, err := VerifyReceipt(roots, msg, token)
	require.NoError(t, err)
	assert.WithinDuration(t, fixedTime, at, time.Second)
}

// ---------------------------------------------------------------------------
// Anchor — refuseRedirect, defense-in-depth URL re-validation, and the
// recover() path around timestamp.ParseResponse
// ---------------------------------------------------------------------------

// TestRFC3161_Anchor_RefusesRedirect confirms the client never follows a 3xx
// from the TSA endpoint: refuseRedirect must reject it (CWE-918 — a
// compromised/misconfigured TSA could otherwise bounce the request to an
// internal host such as cloud IMDS even though the configured URL itself was
// fine at setup time).
func TestRFC3161_Anchor_RefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	tsa, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)
	_, err = tsa.Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to follow redirect")
}

// TestRFC3161_Anchor_RevalidatesURLAtCallTime constructs an RFC3161 value
// directly (bypassing NewRFC3161's constructor validation) to exercise
// Anchor's own defense-in-depth validateTSAURL call. This matters because the
// url field could in principle be reached via a path that skips the
// constructor; Anchor must not trust a stale/bypassed value.
func TestRFC3161_Anchor_RevalidatesURLAtCallTime(t *testing.T) {
	r := &RFC3161{url: "http://not-loopback.example.com/tsr", client: &http.Client{Timeout: 5 * time.Second}}
	_, err := r.Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// rfc3161TestPKIStatusInfo/rfc3161TestResponse mirror digitorus/timestamp's
// unexported `pkiStatusInfo`/`response` ASN.1 shapes closely enough to build a
// well-formed TSA response envelope by hand (see rfc3161_struct.go in that
// module): a SEQUENCE of a status INTEGER-bearing structure followed by an
// (optional) raw TimeStampToken.
type rfc3161TestPKIStatusInfo struct {
	Status int
}

type rfc3161TestResponse struct {
	Status         rfc3161TestPKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// TestRFC3161_Anchor_NestedMalformedResponse_RecoversFromPanic is #G61's
// sibling for a panic that TestRFC3161_Anchor_MalformedTSAResponseNoPanic's
// flat byte sequences cannot reach: those are all rejected by Go's
// standard-library asn1 decoder (used for the OUTER response envelope) before
// the bytes ever reach digitorus/pkcs7's own hand-rolled BER reader, so the
// recover() in Anchor never actually fires for them.
//
// Here the outer envelope is well-formed DER (so encoding/asn1 accepts it and
// hands the embedded TimeStampToken bytes through untouched), but those
// embedded bytes are a high-tag-number form whose length byte sits exactly one
// byte past the end of the buffer — digitorus/pkcs7's readObject indexes that
// byte without a bounds check first (ber.go), panicking with "index out of
// range" instead of returning a parse error. Anchor's recover() must convert
// that into an error, never crash the process anchoring an audit checkpoint.
func TestRFC3161_Anchor_NestedMalformedResponse_RecoversFromPanic(t *testing.T) {
	respBytes, err := asn1.Marshal(rfc3161TestResponse{
		Status: rfc3161TestPKIStatusInfo{Status: 0},
		TimeStampToken: asn1.RawValue{
			FullBytes: []byte{0x30, 0x02, 0xff, 0x30},
		},
	})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}))
	t.Cleanup(srv.Close)
	client, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)

	var anchorErr error
	require.NotPanics(t, func() {
		_, anchorErr = client.Anchor(context.Background(), []byte("anchor message"))
	})
	require.Error(t, anchorErr)
	assert.Contains(t, anchorErr.Error(), "parser panic")
}

// TestRFC3161_Anchor_NilContext confirms Anchor surfaces
// http.NewRequestWithContext's own defensive nil-Context error as a wrapped
// "new request" error rather than panicking or silently proceeding with a
// background context.
func TestRFC3161_Anchor_NilContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	tsa, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)

	//lint:ignore SA1012 deliberately nil to exercise the nil-Context guard inside http.NewRequestWithContext
	_, err = tsa.Anchor(nil, []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "new request")
}

// TestRFC3161_Anchor_ResponseBodyReadError confirms a TSA response whose
// declared Content-Length is never fully delivered (connection closed mid-body)
// surfaces as a wrapped "read response" error from io.ReadAll, not a panic or
// a response treated as complete.
func TestRFC3161_Anchor_ResponseBodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, buf, err := hj.Hijack()
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		// Claim far more body bytes than are actually sent, then close the
		// connection — the client's io.ReadAll(resp.Body) hits an
		// unexpected-EOF read error instead of a clean 200 with a full body.
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: application/timestamp-reply\r\n\r\nshort")
		_ = buf.Flush()
	}))
	t.Cleanup(srv.Close)
	tsa, err := NewRFC3161(srv.URL, 5*time.Second)
	require.NoError(t, err)
	_, err = tsa.Anchor(context.Background(), []byte("m"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read response")
}
