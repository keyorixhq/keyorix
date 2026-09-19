package connect

// response_size_cap_test.go — regression tests for the shared post-decompression
// response-size cap (hardened_client.go's sizeCappedRoundTripper,
// connectMaxResponseBytes) on AWS Secrets Manager and Azure Key Vault, the two
// backends that had NO cap at all before this fix (§3 of
// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md measured ~4 GiB
// peak heap / ~6s elapsed decompressing a gzip-bombed response against the
// pre-fix client). Vault already had its own io.LimitReader (vault.go) and needs
// no separate regression test here — it's covered by its own existing
// fail-closed oracles in vault_response_fuzz_test.go.
//
// Unlike the original investigation (which used a ~1 GiB decompressed payload to
// MEASURE the unbounded amplification), these tests use a payload just over
// connectMaxResponseBytes — large enough to prove the cap actually truncates the
// read and the connector fails closed on the resulting invalid JSON, small
// enough to run in milliseconds. The measurement question (how bad was it) is
// already answered in the findings doc; these tests answer a different question
// (does the fix hold), and don't need the original scale to do it.
import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildOversizedGzipJSON builds a gzip-compressed JSON body shaped
// prefix+filler+suffix, where the DECOMPRESSED total exceeds
// connectMaxResponseBytes — so a correctly-capped read truncates inside the
// filler, leaving invalid (unterminated) JSON no decoder can parse
// successfully. The filler is a single repeated byte — gzip compresses it to a
// tiny fraction of its decompressed size, so this stays fast regardless of how
// large decompressedTotal is.
func buildOversizedGzipJSON(t *testing.T, prefix, suffix string, decompressedTotal int) []byte {
	t.Helper()
	fillerLen := decompressedTotal - len(prefix) - len(suffix)
	if fillerLen <= 0 {
		t.Fatalf("decompressedTotal %d too small for prefix+suffix", decompressedTotal)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(prefix)); err != nil {
		t.Fatalf("gzip write prefix: %v", err)
	}
	if _, err := gz.Write(bytes.Repeat([]byte{'a'}, fillerLen)); err != nil {
		t.Fatalf("gzip write filler: %v", err)
	}
	if _, err := gz.Write([]byte(suffix)); err != nil {
		t.Fatalf("gzip write suffix: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestAWSSMConnector_ResponseSizeCap_FailsClosed uses the REAL production
// newConnectHardenedTransport (hardened_client.go), not a reimplementation, so a
// regression in the cap itself is what this test would catch.
func TestAWSSMConnector_ResponseSizeCap_FailsClosed(t *testing.T) {
	body := buildOversizedGzipJSON(t, `{"SecretString":"`, `"}`, int(connectMaxResponseBytes)*2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	cl := secretsmanager.New(secretsmanager.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(awsFuzzAccessKeyID, awsFuzzSecretKey, ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient: &http.Client{
			Transport:     newConnectHardenedTransport(awsBaseTransport()),
			CheckRedirect: refuseRedirect,
		},
		Retryer: retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 1 }),
	})

	c := NewAWSSecretsManagerConnector("cap-test", "us-east-1", "", nil)
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

	val, err := c.GetSecret(context.Background(), "cap-test-ref")
	require.Error(t, err, "a response whose decompressed size exceeds the cap must fail closed, not return a (truncated) value")
	assert.Empty(t, val)
	assert.ErrorIs(t, err, errResponseTooLarge, "must be the explicit cap-overflow error (MaxBytesReader-style), not a generic truncated-body decode failure")
}

// TestAzureKVConnector_ResponseSizeCap_FailsClosed reuses sizeCappedRoundTripper
// directly (the real production type) rather than newConnectHardenedTransport,
// which builds its own base *http.Transport that wouldn't trust srv's
// self-signed TLS cert — the cap logic under test is identical either way.
//
// Deliberately does NOT override azcore's default Retry policy (unlike the
// fuzz harness, which sets a fast one for unrelated reasons) — that default
// is exactly what this test's own wall-clock assertion below is checking
// against: azcore's retry classifier, by default, treats an unrecognized I/O
// error surfacing during body-read as possibly transient and retries with
// real exponential backoff. Confirmed empirically: before responseTooLargeError
// implemented the NonRetriable() marker, this exact test took ~8s (3 extra
// attempts against the same still-oversized response). An explicit fast-retry
// override here would have hidden that regression rather than catching it.
func TestAzureKVConnector_ResponseSizeCap_FailsClosed(t *testing.T) {
	body := buildOversizedGzipJSON(t, `{"value":"`, `"}`, int(connectMaxResponseBytes)*2)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://fake.local/tenant" resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	cl, err := azsecrets.NewClient(srv.URL, fuzzAzureCred{}, &azsecrets.ClientOptions{
		DisableChallengeResourceVerification: true,
		ClientOptions: azcore.ClientOptions{
			Transport: &http.Client{
				Transport:     sizeCappedRoundTripper{Transport: srv.Client().Transport, MaxBytes: connectMaxResponseBytes},
				CheckRedirect: refuseRedirect,
			},
		},
	})
	require.NoError(t, err)

	c := NewAzureKeyVaultConnector("cap-test", srv.URL, nil)
	c.newClient = func(_ context.Context) (azSecretGetter, error) { return cl, nil }

	start := time.Now()
	val, err := c.GetSecret(context.Background(), "cap-test-ref")
	elapsed := time.Since(start)
	require.Error(t, err, "a response whose decompressed size exceeds the cap must fail closed, not return a (truncated) value")
	assert.Empty(t, val)
	assert.ErrorIs(t, err, errResponseTooLarge, "must be the explicit cap-overflow error (MaxBytesReader-style), not a generic truncated-body decode failure")
	assert.Less(t, elapsed, 2*time.Second, "must fail on the FIRST attempt under azcore's default retry policy -- a cap overflow is a permanent, not transient, condition; if this is slow, responseTooLargeError's NonRetriable() marker regressed")
}
