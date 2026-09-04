// certificate_rune_test.go — exercises certCmd.RunE directly (the only existing
// test, TestFetchCertificate, calls rc.Get on the fixture but never invokes the
// command closure that formats and prints it).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func certStub(t *testing.T, path, body string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func TestCertCmd_Success_NotExpired_SelfSigned_WithSANs(t *testing.T) {
	done := certStub(t, "/api/v1/secrets/7/certificate", `{"data":{"secret_id":7,"secret_name":"tls-cert","subject":"CN=example.com","issuer":"CN=example.com","serial_number":"4242","not_before":"2025-06-23T00:00:00Z","not_after":"2026-09-21T00:00:00Z","days_until_expiry":90,"is_expired":false,"is_ca":false,"self_signed":true,"dns_names":["example.com","www.example.com"],"signature_algorithm":"ECDSA-SHA256","public_key_algorithm":"ECDSA"}}`)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := certCmd.RunE(certCmd, []string{"7"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "90 days left")
	assert.Contains(t, out, "self-signed")
	assert.Contains(t, out, "example.com")
	assert.Contains(t, out, "SANs:")
}

func TestCertCmd_Success_Expired_NotSelfSigned_NoSANs(t *testing.T) {
	done := certStub(t, "/api/v1/secrets/8/certificate", `{"data":{"secret_id":8,"secret_name":"old-cert","subject":"CN=old.example.com","issuer":"CN=CA","serial_number":"1","not_before":"2020-01-01T00:00:00Z","not_after":"2021-01-01T00:00:00Z","days_until_expiry":0,"is_expired":true,"is_ca":true,"self_signed":false,"dns_names":[],"signature_algorithm":"SHA256-RSA","public_key_algorithm":"RSA"}}`)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := certCmd.RunE(certCmd, []string{"8"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "EXPIRED")
	assert.NotContains(t, out, "self-signed")
	assert.NotContains(t, out, "SANs:")
	assert.Contains(t, out, "CA:         true")
}

func TestCertCmd_InvalidSecretArg(t *testing.T) {
	err := certCmd.RunE(certCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret id")
}

func TestCertCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := certCmd.RunE(certCmd, []string{"7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestCertCmd_APIError(t *testing.T) {
	done := certStub(t, "/api/v1/secrets/7/certificate", `{}`)
	defer done()
	err := certCmd.RunE(certCmd, []string{"999"})
	require.Error(t, err)
}
