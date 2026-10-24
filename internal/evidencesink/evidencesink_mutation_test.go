//go:build !lean && !noaws

package evidencesink

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hermeticAWSEnv keeps LoadDefaultConfig from picking a region, endpoint or
// profile out of the developer's or CI runner's environment, so the assertions
// below see only what NewObjectStore itself configured.
func hermeticAWSEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3",
		"AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent/keyorix-aws-config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/keyorix-aws-credentials")
}

func s3ClientOf(t *testing.T, o *ObjectStore) *s3.Client {
	t.Helper()
	c, ok := o.api.(*s3.Client)
	require.True(t, ok, "NewObjectStore must build a real *s3.Client, got %T", o.api)
	return c
}

// NewObjectStore must hand its Region and Endpoint to the S3 client and install
// the DNS-pinned HTTP client only when an endpoint is configured. Kills the
// CONDITIONALS_NEGATION mutants at objectstore.go:170, :178 and :181
// (gremlins, MUTANT-SEC-1): without the pinned client the SSRF/DNS-rebinding
// guard on a custom endpoint silently disappears.
func TestNewObjectStore_ClientOptions(t *testing.T) {
	hermeticAWSEnv(t)

	t.Run("region endpoint and pinned http client are applied", func(t *testing.T) {
		o, err := NewObjectStore(context.Background(), ObjectStoreConfig{
			Bucket:       "b",
			Region:       "eu-central-1",
			Endpoint:     "http://127.0.0.1:9000",
			UsePathStyle: true,
		})
		require.NoError(t, err)
		opts := s3ClientOf(t, o).Options()
		assert.Equal(t, "eu-central-1", opts.Region)
		require.NotNil(t, opts.BaseEndpoint)
		assert.Equal(t, "http://127.0.0.1:9000", *opts.BaseEndpoint)
		hc, ok := opts.HTTPClient.(*http.Client)
		require.True(t, ok, "a custom endpoint must install the pinned *http.Client, got %T", opts.HTTPClient)
		require.NotNil(t, hc)
		tr, ok := hc.Transport.(*http.Transport)
		require.True(t, ok)
		assert.NotNil(t, tr.DialContext, "the pinned dialer must be set")
		assert.True(t, opts.UsePathStyle)
	})

	t.Run("no endpoint leaves the SDK defaults alone", func(t *testing.T) {
		o, err := NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b"})
		require.NoError(t, err)
		opts := s3ClientOf(t, o).Options()
		assert.Empty(t, opts.Region)
		assert.Nil(t, opts.BaseEndpoint)
		_, isPinned := opts.HTTPClient.(*http.Client)
		assert.False(t, isPinned, "without an endpoint no pinned *http.Client should be installed, got %T", opts.HTTPClient)
		assert.False(t, opts.UsePathStyle)
	})
}

// The retention window is days * 24h. Kills the ARITHMETIC_BASE mutants at
// objectstore.go:191 (gremlins, MUTANT-SEC-1): a wrong factor would make WORM
// objects expire early or never.
func TestNewObjectStore_RetentionIsDaysTimes24Hours(t *testing.T) {
	hermeticAWSEnv(t)
	o, err := NewObjectStore(context.Background(), ObjectStoreConfig{
		Bucket: "b", LockMode: "compliance", LockRetainDays: 7,
	})
	require.NoError(t, err)
	assert.Equal(t, 7*24*time.Hour, o.retain)
}

// The webhook constants are pinned here because gremlins cannot run mutants in
// a const expression (no coverage block exists for one): webhook.go:23 and :27.
func TestWebhookConstants(t *testing.T) {
	assert.Equal(t, 30*time.Second, webhookTimeout)
	assert.Equal(t, time.Second, defaultBaseBackoff)
	assert.Equal(t, 4, maxAttempts)
}

// Only 2xx is success. A 300 (which Go's client returns as-is when there is no
// Location header) must be a permanent failure, not accepted and not retried.
// Kills the CONDITIONALS_BOUNDARY mutant at webhook.go:255 (gremlins,
// MUTANT-SEC-1): a receiver answering 300 has not recorded the evidence pack.
func TestWebhook_Status300_IsPermanentFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusMultipleChoices)
	}))
	t.Cleanup(srv.Close)

	wh, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)

	err = wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err, "300 is not a delivery")
	assert.Contains(t, err.Error(), "300")
	assert.EqualValues(t, 1, calls.Load(), "a 3xx is permanent and must not be retried")
}
