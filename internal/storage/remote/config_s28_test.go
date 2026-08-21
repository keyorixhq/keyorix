// config_s28_test.go — s28 coverage sweep for internal/storage/remote.
//
// Targets remaining gaps left after the s24/s27 sweeps:
//
//	config.go Validate
//	  — empty APIKey is rejected before BaseURL is even inspected
//	config.go validateBaseURL
//	  — a genuinely unparseable base_url (url.Parse itself errors) is rejected
//	    with the parse error, distinct from the "wrong scheme" rejection
//
//	client.go APIError.Error
//	  — Details-populated branch renders "code: message (details)"
//	client.go HTTPError.Error
//	  — Message-only branch (no ErrorType) renders "HTTP <code>: <message>"
//	client.go rawJSONToString
//	  — a RawMessage that isn't a JSON string literal falls back to the raw text
//	client.go circuitBreakerOpen
//	  — the 30s-cooldown-elapsed branch actually closes the breaker and resets
//	    the failure count, not just reports "not open"
//	client.go Request
//	  — a context that's canceled/expires during the inter-attempt backoff sleep
//	    returns ctx.Err() instead of continuing to retry
//	client.go makeRequest
//	  — a request body that can't be JSON-marshaled surfaces a wrapped error
//	  — an invalid HTTP method passed to Request surfaces the NewRequestWithContext
//	    construction error
//	  — a response body that is shorter than its own Content-Length header
//	    surfaces a body-read error rather than silently returning a partial body
package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Config.Validate
// ---------------------------------------------------------------------------

// TestValidate_S28_EmptyAPIKeyRejected verifies that a missing API key is
// rejected with a clear message, independent of BaseURL validity.
func TestValidate_S28_EmptyAPIKeyRejected(t *testing.T) {
	c := &Config{BaseURL: "https://api.example.com", APIKey: ""}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key is required")
}

// ---------------------------------------------------------------------------
// validateBaseURL
// ---------------------------------------------------------------------------

// TestValidateBaseURL_S28_UnparseableURLRejected verifies that a base_url
// which url.Parse itself rejects (not merely "wrong scheme") is surfaced as
// an "invalid base_url" error carrying the underlying parse failure, distinct
// from the https-scheme rejection message.
func TestValidateBaseURL_S28_UnparseableURLRejected(t *testing.T) {
	c := &Config{BaseURL: "http://exa mple.com", APIKey: "k"}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base_url")
}

// ---------------------------------------------------------------------------
// APIError.Error
// ---------------------------------------------------------------------------

// TestAPIError_S28_ErrorWithDetails verifies the Details-populated rendering
// branch of APIError.Error, distinct from the nil-receiver and no-details cases
// already pinned elsewhere.
func TestAPIError_S28_ErrorWithDetails(t *testing.T) {
	e := &APIError{Code: "VALIDATION", Message: "bad input", Details: "field 'name' is required"}
	got := e.Error()
	assert.Equal(t, "VALIDATION: bad input (field 'name' is required)", got)
}

// ---------------------------------------------------------------------------
// HTTPError.Error
// ---------------------------------------------------------------------------

// TestHTTPError_S28_MessageOnlyNoErrorType verifies the branch where a
// Message is present but ErrorType is empty (e.g. a body that only had a
// "message" field, no "error" type string) — falls back to "HTTP <code>: <message>"
// rather than the ErrorType-driven format.
func TestHTTPError_S28_MessageOnlyNoErrorType(t *testing.T) {
	e := &HTTPError{StatusCode: http.StatusInternalServerError, Status: "500 Internal Server Error", Message: "database unavailable"}
	got := e.Error()
	assert.Equal(t, "HTTP 500: database unavailable", got)
}

// ---------------------------------------------------------------------------
// rawJSONToString
// ---------------------------------------------------------------------------

// TestRawJSONToString_S28_NonStringFallsBackToRawText verifies that a
// RawMessage which is valid JSON but not a JSON string literal (e.g. an
// object, as a "details" field might legitimately carry) falls back to
// returning the raw JSON text verbatim rather than an empty/failed unmarshal.
func TestRawJSONToString_S28_NonStringFallsBackToRawText(t *testing.T) {
	raw := json.RawMessage(`{"field":"name","reason":"required"}`)
	got := rawJSONToString(raw)
	assert.Equal(t, `{"field":"name","reason":"required"}`, got)
}

// TestRawJSONToString_S28_EmptyReturnsEmpty pins the len(raw)==0 short-circuit.
func TestRawJSONToString_S28_EmptyReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", rawJSONToString(nil))
	assert.Equal(t, "", rawJSONToString(json.RawMessage{}))
}

// ---------------------------------------------------------------------------
// circuitBreakerOpen
// ---------------------------------------------------------------------------

// TestCircuitBreakerOpen_S28_ClosesAfterCooldown verifies that once the 30s
// cooldown has elapsed since the last recorded failure, circuitBreakerOpen
// both reports the breaker as closed AND actually resets circuitOpen/
// failureCount as a side effect (not just a read-only "would be closed"
// check) — a stuck-open breaker would permanently reject all requests.
func TestCircuitBreakerOpen_S28_ClosesAfterCooldown(t *testing.T) {
	client, err := NewHTTPClient(&Config{
		BaseURL: "https://api.example.com", APIKey: "k", TimeoutSeconds: 5, RetryAttempts: 1, TLSVerify: true,
	})
	require.NoError(t, err)

	// Force the breaker into an open state as if 5 failures had just
	// accumulated, but backdate lastFailureTime past the 30s cooldown.
	client.cbMux.Lock()
	client.circuitOpen = true
	client.failureCount = 5
	client.lastFailureTime = time.Now().Add(-31 * time.Second)
	client.cbMux.Unlock()

	open := client.circuitBreakerOpen()
	assert.False(t, open, "cooldown elapsed: breaker must report closed")

	client.cbMux.Lock()
	stillOpen := client.circuitOpen
	failures := client.failureCount
	client.cbMux.Unlock()
	assert.False(t, stillOpen, "cooldown elapsed: circuitOpen must be reset to false")
	assert.Equal(t, 0, failures, "cooldown elapsed: failureCount must be reset to 0")
}

// ---------------------------------------------------------------------------
// Request — context canceled during inter-attempt backoff
// ---------------------------------------------------------------------------

// TestRequest_S28_ContextExpiresDuringBackoff verifies that when the caller's
// context is canceled/expires while Request is sleeping between retry
// attempts, it returns ctx.Err() immediately instead of continuing to sleep
// out the full exponential backoff and retry budget.
func TestRequest_S28_ContextExpiresDuringBackoff(t *testing.T) {
	// A server that always resets the connection: a retryable network error on
	// every attempt, so Request always reaches the backoff-sleep between
	// attempts (attempt=1 backs off for 1*1=1s).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	}))
	defer server.Close()

	client, err := NewHTTPClient(&Config{
		BaseURL: server.URL, APIKey: "k", TimeoutSeconds: 5, RetryAttempts: 3, TLSVerify: false,
	})
	require.NoError(t, err)

	// Deadline shorter than the 1s backoff before the second attempt, but long
	// enough for the first (immediately-failing) attempt to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.Request(ctx, http.MethodGet, "/test", nil)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 900*time.Millisecond, "must return as soon as the context expires, not after the full 1s backoff")
}

// ---------------------------------------------------------------------------
// makeRequest — construction/marshal/body-read failure branches
// ---------------------------------------------------------------------------

// TestMakeRequest_S28_UnmarshalableBodyErrors verifies that a request body
// which json.Marshal cannot encode (a channel) surfaces a wrapped
// "failed to marshal request body" error rather than panicking or silently
// dropping the body.
func TestMakeRequest_S28_UnmarshalableBodyErrors(t *testing.T) {
	client, err := NewHTTPClient(&Config{
		BaseURL: "https://api.example.com", APIKey: "k", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	_, err = client.Post(context.Background(), "/test", make(chan int))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal request body")
}

// TestMakeRequest_S28_InvalidMethodErrors verifies that an invalid HTTP
// method (rejected by http.NewRequestWithContext itself) surfaces a wrapped
// "failed to create request" error. isRetryableError treats this message as
// non-retryable, so this also exercises the single-attempt, no-retry path.
func TestMakeRequest_S28_InvalidMethodErrors(t *testing.T) {
	client, err := NewHTTPClient(&Config{
		BaseURL: "https://api.example.com", APIKey: "k", TimeoutSeconds: 5, RetryAttempts: 3, TLSVerify: true,
	})
	require.NoError(t, err)

	_, err = client.Request(context.Background(), "BAD METHOD", "/test", nil)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "failed to create request") || strings.Contains(err.Error(), "invalid method"),
		"expected a request-construction error, got: %v", err)
}

// TestMakeRequest_S28_TruncatedBodyBelowContentLength verifies that a
// response whose actual body is shorter than its own Content-Length header
// (connection dropped mid-body) surfaces a body-read error from makeRequest
// rather than silently returning a truncated/corrupt APIResponse.
func TestMakeRequest_S28_TruncatedBodyBelowContentLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, bufrw, err := hj.Hijack()
		require.NoError(t, err)
		// Promise 100 bytes of body but only send 5, then close the connection.
		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
		_ = bufrw.Flush()
		_ = conn.Close()
	}))
	defer server.Close()

	// RetryAttempts:0 would be defaulted up to 3 by Config.Validate (any
	// value <=0 defaults to 3), turning this into a ~14s exponential-backoff
	// run (1s+4s+9s across 3 retries) — use 1 explicitly so this stays fast
	// (the read failure is retryable, so one retry attempt still happens).
	client, err := NewHTTPClient(&Config{
		BaseURL: server.URL, APIKey: "k", TimeoutSeconds: 5, RetryAttempts: 1, TLSVerify: false,
	})
	require.NoError(t, err)

	_, err = client.Get(context.Background(), "/test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read response body")
}
