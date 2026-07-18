// evidencesink_s25_test.go — additional coverage: refuseRedirect, newWebhook
// InsecureSkipVerify, validateEndpoint http+allowPrivateNetwork, post via
// roundTripper mock (no network listener needed), and NewObjectStore success path.
package evidencesink

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// roundTripper mock — intercepts HTTP requests without a real listener.
// ---------------------------------------------------------------------------

type mockRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func respWithStatus(code int) (*http.Response, error) {
	status := fmt.Sprintf("%d %s", code, http.StatusText(code))
	return &http.Response{
		StatusCode: code,
		Status:     status,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}, nil
}

// ---------------------------------------------------------------------------
// refuseRedirect — direct unit tests.
// ---------------------------------------------------------------------------

// TestRefuseRedirect_NoVia covers the len(via)==0 early return (currently 0%).
func TestRefuseRedirect_NoVia(t *testing.T) {
	req := &http.Request{URL: mustURL("https://example.com/evidence")}
	err := refuseRedirect(req, nil) // via is nil → len == 0
	assert.NoError(t, err, "len(via)==0 must return nil")
}

// TestRefuseRedirect_SameHostHTTPS verifies a same-host https redirect is allowed.
func TestRefuseRedirect_SameHostHTTPS(t *testing.T) {
	prev := &http.Request{URL: mustURL("https://example.com/old")}
	req := &http.Request{URL: mustURL("https://example.com/new")}
	err := refuseRedirect(req, []*http.Request{prev})
	assert.NoError(t, err, "same-host https→https redirect must be allowed")
}

// TestRefuseRedirect_SameHostHTTPSToHTTP verifies the https→http downgrade path
// that is NOT hit by the existing TLS-server-based test when the sandbox blocks listeners.
func TestRefuseRedirect_SameHostHTTPSToHTTP(t *testing.T) {
	prev := &http.Request{URL: mustURL("https://example.com/old")}
	req := &http.Request{URL: mustURL("http://example.com/new")}
	err := refuseRedirect(req, []*http.Request{prev})
	require.Error(t, err, "same-host https→http redirect must be refused")
	assert.Contains(t, err.Error(), "https->http")
}

// TestRefuseRedirect_CrossHost verifies the cross-host path directly.
func TestRefuseRedirect_CrossHost(t *testing.T) {
	prev := &http.Request{URL: mustURL("https://example.com/evidence")}
	req := &http.Request{URL: mustURL("https://evil.example.com/steal")}
	err := refuseRedirect(req, []*http.Request{prev})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-host redirect")
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// ---------------------------------------------------------------------------
// newWebhook — InsecureSkipVerify path.
// ---------------------------------------------------------------------------

// TestNewWebhook_InsecureSkipVerify exercises the TLS-disabled transport branch
// (line 67-69 of webhook.go) which was not reached by existing tests.
func TestNewWebhook_InsecureSkipVerify(t *testing.T) {
	// Stub the DNS resolver so validateEndpoint's refuseDisallowedHost call
	// succeeds without a real DNS query (blocked in some sandboxed environments).
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.5")}}, nil // public TEST-NET-3
	}

	wh, err := newWebhook(WebhookConfig{
		Endpoint:           "https://collector.example.com/evidence",
		InsecureSkipVerify: true,
	}, time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, wh)
	// Target must still be "webhook".
	assert.Equal(t, "webhook", wh.Target())
}

// ---------------------------------------------------------------------------
// validateEndpoint — http + AllowPrivateNetworkTarget with non-loopback host.
// ---------------------------------------------------------------------------

// TestValidateEndpoint_HTTPAllowPrivateNetworkNonLoopback covers the branch where
// scheme=="http", allowPrivateNetwork==true but host is not loopback — previously
// the AllowPrivateNetworkTarget test only used a non-loopback domain with http.
// Here we verify the SSRF check is truly bypassed (no refuseDisallowedHost call).
func TestValidateEndpoint_HTTPAllowPrivateNetworkNonLoopback(t *testing.T) {
	// A private RFC-1918 address; without AllowPrivateNetworkTarget this would be
	// refused — with it the check is skipped.
	err := validateEndpoint("http://10.0.0.50/evidence", true)
	assert.NoError(t, err, "http to private IP must be allowed when AllowPrivateNetworkTarget is true")
}

// TestValidateEndpoint_HTTPSAllowPrivateNetworkSkipsHostCheck verifies that
// AllowPrivateNetworkTarget also skips the refuseDisallowedHost call for https.
func TestValidateEndpoint_HTTPSAllowPrivateNetworkSkipsHostCheck(t *testing.T) {
	// 169.254.169.254 is the AWS metadata link-local address that is normally
	// refused by refuseDisallowedHost even for https.
	err := validateEndpoint("https://169.254.169.254/latest/meta-data", true)
	assert.NoError(t, err, "AllowPrivateNetworkTarget must bypass the host check even for https")
}

// ---------------------------------------------------------------------------
// post — via mockRoundTripper (no network listener).
// ---------------------------------------------------------------------------

func webhookWithTransport(endpoint string, rt http.RoundTripper) *Webhook {
	return &Webhook{
		cfg:         WebhookConfig{Endpoint: endpoint},
		client:      &http.Client{Transport: rt, CheckRedirect: refuseRedirect},
		baseBackoff: time.Millisecond,
	}
}

// TestPost_SuccessNoNameNoSig covers the name=="" and signature=="" branches of post.
func TestPost_SuccessNoNameNoSig(t *testing.T) {
	rt := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		// Verify no optional headers set.
		assert.Empty(t, req.Header.Get("X-Keyorix-Evidence-Filename"))
		assert.Empty(t, req.Header.Get("X-Keyorix-Evidence-Signature"))
		assert.Empty(t, req.Header.Get("Authorization"))
		return respWithStatus(http.StatusOK)
	}}
	wh := webhookWithTransport("https://example.com/evidence", rt)
	err := wh.ForwardEvidence(context.Background(), "", []byte(`{}`), "")
	require.NoError(t, err)
}

// TestPost_SuccessWithNameAndSig covers the name!="" and signature!="" headers.
func TestPost_SuccessWithNameAndSig(t *testing.T) {
	rt := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "pack.json", req.Header.Get("X-Keyorix-Evidence-Filename"))
		assert.Equal(t, "v1:abc", req.Header.Get("X-Keyorix-Evidence-Signature"))
		assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
		return respWithStatus(http.StatusCreated)
	}}
	wh := &Webhook{
		cfg:         WebhookConfig{Endpoint: "https://example.com/evidence", Token: "tok"},
		client:      &http.Client{Transport: rt, CheckRedirect: refuseRedirect},
		baseBackoff: time.Millisecond,
	}
	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "v1:abc")
	require.NoError(t, err)
}

// TestPost_429IsRetryable verifies that HTTP 429 is treated as retryable.
func TestPost_429IsRetryable(t *testing.T) {
	var calls int
	rt := &mockRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		calls++
		if calls < maxAttempts {
			return respWithStatus(http.StatusTooManyRequests)
		}
		return respWithStatus(http.StatusOK)
	}}
	wh := webhookWithTransport("https://example.com/evidence", rt)
	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.NoError(t, err, "429 must be retried and succeed on final attempt")
	assert.Equal(t, maxAttempts, calls)
}

// TestPost_TransportError verifies a transport/dial error is retryable.
func TestPost_TransportError(t *testing.T) {
	var calls int
	rt := &mockRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("dial: connection refused")
	}}
	wh := webhookWithTransport("https://example.com/evidence", rt)
	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
	assert.Equal(t, maxAttempts, calls, "transport errors must be retried up to maxAttempts")
}

// TestPost_5xxIsRetryable verifies that HTTP 500 exhausts maxAttempts.
func TestPost_5xxIsRetryable(t *testing.T) {
	var calls int
	rt := &mockRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		calls++
		return respWithStatus(http.StatusInternalServerError)
	}}
	wh := webhookWithTransport("https://example.com/evidence", rt)
	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
	assert.Equal(t, maxAttempts, calls)
}

// TestPost_4xxIsNotRetryable verifies that a 4xx returns immediately.
func TestPost_4xxIsNotRetryable(t *testing.T) {
	var calls int
	rt := &mockRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		calls++
		return respWithStatus(http.StatusForbidden)
	}}
	wh := webhookWithTransport("https://example.com/evidence", rt)
	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
	assert.Equal(t, 1, calls, "4xx must not be retried")
}

// TestPost_ContextCancelledDuringRetryBackoff verifies context cancellation
// during the backoff select is surfaced correctly.
func TestPost_ContextCancelledDuringRetryBackoff(t *testing.T) {
	rt := &mockRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		return respWithStatus(http.StatusServiceUnavailable)
	}}
	wh := &Webhook{
		cfg:         WebhookConfig{Endpoint: "https://example.com/evidence"},
		client:      &http.Client{Transport: rt, CheckRedirect: refuseRedirect},
		baseBackoff: 500 * time.Millisecond, // long enough for ctx to cancel first
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := wh.ForwardEvidence(ctx, "pack.json", []byte(`{}`), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}

// TestPost_InvalidEndpointError verifies that an invalid URL in Endpoint causes
// the http.NewRequestWithContext to error (permanent, not retried).
func TestPost_InvalidEndpointError(t *testing.T) {
	wh := &Webhook{
		cfg:         WebhookConfig{Endpoint: "://invalid"},
		client:      &http.Client{CheckRedirect: refuseRedirect},
		baseBackoff: time.Millisecond,
	}
	// Only one call is expected since NewRequestWithContext errors on invalid URL —
	// that is a permanent (non-retryable) error in post.
	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// NewObjectStore — test the valid construction branches.
// ---------------------------------------------------------------------------

// TestNewObjectStore_ValidMinimalConfig tests a minimal valid config (bucket only).
// AWS credential loading still succeeds even without real credentials because the
// SDK only resolves them lazily on the first actual API call, not at LoadDefaultConfig.
func TestNewObjectStore_ValidMinimalConfig(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{Bucket: "my-bucket"})
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Equal(t, "objectstore:my-bucket/", o.Target())
}

// TestNewObjectStore_WithRegionAndEndpoint exercises the loadOpts path and the
// custom-endpoint / path-style option branches.
func TestNewObjectStore_WithRegionAndEndpoint(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{
		Bucket:       "minio-bucket",
		Prefix:       "evidence",
		Region:       "us-east-1",
		Endpoint:     "http://localhost:9000",
		UsePathStyle: true,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Equal(t, "objectstore:minio-bucket/evidence/", o.Target())
}

// TestNewObjectStore_WithLockGovernanceAndLegalHold exercises object-lock and
// legal-hold construction including the Region branch.
func TestNewObjectStore_WithLockGovernanceAndLegalHold(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{
		Bucket:         "bkt",
		LockMode:       "governance",
		LockRetainDays: 30,
		LegalHold:      true,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
	target := o.Target()
	assert.Contains(t, target, "lock:governance")
	assert.Contains(t, target, "legal-hold")
}

// TestNewObjectStore_WithComplianceLock exercises the compliance lock mode path.
func TestNewObjectStore_WithComplianceLock(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{
		Bucket:         "bkt",
		LockMode:       "compliance",
		LockRetainDays: 90,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Contains(t, o.Target(), "lock:compliance")
}
