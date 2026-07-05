package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient(t *testing.T) {
	config := &Config{
		BaseURL:        "https://api.example.com",
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      true,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "https://api.example.com", client.baseURL)
	assert.Equal(t, "test-key", client.apiKey)
	assert.Equal(t, 3, client.retryAttempts)
}

func TestNewHTTPClient_InvalidConfig(t *testing.T) {
	config := &Config{
		// Missing required fields
	}

	_, err := NewHTTPClient(config)
	assert.Error(t, err)
}

func TestHTTPClient_Get(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/test", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"message": "success"}`),
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	resp, err := client.Get(context.Background(), "/test")
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Contains(t, string(resp.Data), "success")
}

func TestHTTPClient_Get_WithCaching(t *testing.T) {
	requestCount := 0

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"message": "success", "count": ` + string(rune(requestCount+'0')) + `}`), // #nosec G115
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	// First request
	resp1, err := client.Get(context.Background(), "/test")
	require.NoError(t, err)
	assert.True(t, resp1.Success)
	assert.Equal(t, 1, requestCount)

	// Second request should be cached
	resp2, err := client.Get(context.Background(), "/test")
	require.NoError(t, err)
	assert.True(t, resp2.Success)
	assert.Equal(t, 1, requestCount) // Should still be 1 due to caching
}

// A successful mutating request (PUT here, standing in for an UpdateSecret/
// rotate/revoke call) invalidates the GET cache, so a subsequent read through the
// SAME client instance is not served the pre-write cached value for up to the
// full 5-minute TTL — closing the "revoked/rotated secret served stale from
// cache" gap for the read-your-own-write case.
func TestHTTPClient_Get_CacheInvalidatedOnWrite(t *testing.T) {
	var getCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getCount++
		}
		response := APIResponse{Success: true, Data: json.RawMessage(`{"ok":true}`)}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}
	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	// Prime the cache for /secrets/1.
	_, err = client.Get(context.Background(), "/secrets/1")
	require.NoError(t, err)
	assert.Equal(t, 1, getCount)

	// Cached: no new GET.
	_, err = client.Get(context.Background(), "/secrets/1")
	require.NoError(t, err)
	assert.Equal(t, 1, getCount, "second GET should be served from cache")

	// A write — even to a DIFFERENT path, mirroring UpdateSecret's PUT
	// /secrets/{id} vs GetSecretByName's /secrets/by-name/... cache key mismatch —
	// must invalidate the whole cache, not just a matching key.
	_, err = client.Put(context.Background(), "/secrets/1", map[string]string{"value": "new"})
	require.NoError(t, err)

	// Next GET must hit the server again, not the stale cached value.
	_, err = client.Get(context.Background(), "/secrets/1")
	require.NoError(t, err)
	assert.Equal(t, 2, getCount, "GET after a write must not be served from the pre-write cache")
}

func TestHTTPClient_Post(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/test", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"message": "created"}`),
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	body := map[string]string{"name": "test"}
	resp, err := client.Post(context.Background(), "/test", body)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Contains(t, string(resp.Data), "created")
}

func TestHTTPClient_RetryLogic(t *testing.T) {
	attemptCount := 0

	// Create a test server that fails first few times
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			// Simulate network error by closing connection
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
			}
			return
		}

		// Success on third attempt
		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"message": "success"}`),
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  3,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	resp, err := client.Get(context.Background(), "/test")
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, 3, attemptCount) // Should have retried 3 times
}

// TestHTTPClient_CircuitBreaker was previously skipped as flaky/"needs
// debugging". Root cause (#501): a real 5xx from an httptest server with an
// empty body never unmarshaled into APIResponse, so makeRequest returned
// (resp, nil) — a nil error — and Request() treated that as a SUCCESSFUL
// round trip, calling c.resetFailureCount() instead of c.recordFailure(). The
// circuit breaker's failureCount could never accumulate against a real
// server, so it never opened. Fixed by unconditionally treating every 4xx/5xx
// status as an error (see makeRequest), which is now enabled.
func TestHTTPClient_CircuitBreaker(t *testing.T) {
	// Create a test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 1,
		RetryAttempts:  1,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	// Make several failing requests to trigger circuit breaker
	for i := 0; i < 6; i++ {
		_, err := client.Get(context.Background(), "/test")
		assert.Error(t, err)
	}

	// Circuit should now be open (we can't directly check the private field,
	// but the next request should fail with circuit breaker error)

	// Next request should fail immediately due to circuit breaker
	_, err = client.Get(context.Background(), "/test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")
}

// TestHTTPClient_MalformedSuccessResponse_NoPanic pins #314: an upstream that
// returns a 2xx status with a technically-valid-but-incomplete JSON body (no
// "error" field set, e.g. a proxy/WAF/CDN interstitial returning `{}`) must not
// crash makeRequest's caller. Before the fix, this produced Success:false with
// Error:nil, and every remote_*.go call site's resp.Error.Error() pattern
// panicked on the nil *APIError receiver — reproduced and confirmed via an
// earlier version of this test before the fix landed.
func TestHTTPClient_MalformedSuccessResponse_NoPanic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  0,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	resp, err := client.Get(context.Background(), "/test")
	require.NoError(t, err)
	require.False(t, resp.Success)
	require.NotNil(t, resp.Error, "makeRequest must synthesize a non-nil Error when Success is false")
	assert.NotPanics(t, func() {
		_ = resp.Error.Error() // the exact pattern every remote_*.go call site uses
	})
}

// TestHTTPClient_204NoContent_Success pins #498: a 204 No Content response (the
// real shape DeleteUser/DeleteSecret's handlers return — an empty body, no JSON
// at all) must be treated as an unambiguous success, not a parse failure. Before
// the fix, json.Unmarshal on the zero-byte body errored with "unexpected end of
// JSON input", and makeRequest's parse-error branch synthesized Success:false —
// silently misreporting every genuinely successful delete as a failure.
func TestHTTPClient_204NoContent_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  0,
		TLSVerify:      false,
	}
	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	resp, err := client.Delete(context.Background(), "/users/1")
	require.NoError(t, err, "a 204 No Content must not be misreported as a request failure")
	require.NotNil(t, resp)
	assert.True(t, resp.Success, "a 204 No Content must be treated as success, not the zero-value Success:false")
	assert.Nil(t, resp.Error)
}

// TestHTTPClient_2xxEmptyBody_Success generalizes the #498 fix beyond a literal
// 204: any 2xx status with a genuinely empty body (not just 204) must also be
// treated as success, since the mechanism (an empty body can't be unmarshaled)
// is identical regardless of the exact 2xx code used.
func TestHTTPClient_2xxEmptyBody_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// deliberately write nothing
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  0,
		TLSVerify:      false,
	}
	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	resp, err := client.Get(context.Background(), "/whatever")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestHTTPClient_MalformedNonEmptyBody_StillReportsFailure is the non-regression
// half of the #498 fix: the empty-body special case must NOT be broadened into
// "any unparseable body is success". A 200 that was supposed to carry a JSON
// body but instead sends truncated/malformed (non-empty) bytes must still
// surface as a genuine parse failure (Success:false with the raw body captured
// in Error.Details), exactly as before this fix.
func TestHTTPClient_MalformedNonEmptyBody_StillReportsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success": tru`)) // truncated, non-empty, malformed JSON
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  0,
		TLSVerify:      false,
	}
	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	resp, err := client.Get(context.Background(), "/whatever")
	require.NoError(t, err, "a parse failure is reported via Success:false/Error, not a Go error")
	require.NotNil(t, resp)
	assert.False(t, resp.Success, "a genuinely malformed non-empty body must still be reported as a failure")
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Details, `{"success": tru`)
}

// TestAPIError_ErrorMethod_NilSafe pins the nil-receiver guard directly: any
// existing or future caller doing (*APIError)(nil).Error() must not panic.
func TestAPIError_ErrorMethod_NilSafe(t *testing.T) {
	var e *APIError
	assert.NotPanics(t, func() {
		assert.Equal(t, "unknown error", e.Error())
	})
}

// TestHTTPClient_4xx_ParsesFlatSendErrorEnvelope pins #501: a 4xx/5xx response
// whose body matches the ACTUAL shape server/http/handlers/helpers.go's
// sendError writes — a flat object with a bare "error" type string, not the
// nested {"error":{"code":...}} shape APIResponse.Error models — must surface
// the real ErrorType/Message/Details via *HTTPError, not a generic
// "HTTP 404: 404 Not Found" string. Before the fix, json.Unmarshal into
// APIResponse failed on this exact shape (string into a struct field) and the
// real detail was discarded.
func TestHTTPClient_4xx_ParsesFlatSendErrorEnvelope(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		wantType   string
		wantMsg    string
	}{
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			body:       `{"success":false,"error":"NotFound","message":"User not found","code":404}`,
			wantType:   "NotFound",
			wantMsg:    "User not found",
		},
		{
			name:       "validation failure",
			statusCode: http.StatusBadRequest,
			body:       `{"success":false,"error":"ValidationError","message":"Invalid request data","code":400,"details":"name is required"}`,
			wantType:   "ValidationError",
			wantMsg:    "Invalid request data",
		},
		{
			name:       "conflict",
			statusCode: http.StatusConflict,
			body:       `{"success":false,"error":"ConflictError","message":"Group name already exists","code":409}`,
			wantType:   "ConflictError",
			wantMsg:    "Group name already exists",
		},
		{
			name:       "permission denied",
			statusCode: http.StatusForbidden,
			body:       `{"success":false,"error":"Forbidden","message":"insufficient permissions","code":403}`,
			wantType:   "Forbidden",
			wantMsg:    "insufficient permissions",
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			body:       `{"success":false,"error":"RateLimited","message":"too many requests","code":429}`,
			wantType:   "RateLimited",
			wantMsg:    "too many requests",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.statusCode)
				_, _ = w.Write([]byte(c.body))
			}))
			defer server.Close()

			client, err := NewHTTPClient(&Config{
				BaseURL: server.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 1, TLSVerify: false,
			})
			require.NoError(t, err)

			_, err = client.Get(context.Background(), "/test")
			require.Error(t, err)

			var httpErr *HTTPError
			require.True(t, errors.As(err, &httpErr), "error must unwrap to *HTTPError")
			assert.Equal(t, c.statusCode, httpErr.StatusCode)
			assert.Equal(t, c.wantType, httpErr.ErrorType)
			assert.Equal(t, c.wantMsg, httpErr.Message)
			assert.NotEqual(t, fmt.Sprintf("HTTP %d: %d %s", c.statusCode, c.statusCode, http.StatusText(c.statusCode)), err.Error())
		})
	}
}

// TestHTTPClient_4xx_NestedErrorShape_StillParses is the defensive-fallback
// half of #501: if some OTHER upstream (not this codebase's own sendError)
// emits the nested {"error":{"code","message","details"}} shape that
// APIResponse.Error/APIError already models, that structured detail must
// still be extracted rather than only supporting the flat shape.
func TestHTTPClient_4xx_NestedErrorShape_StillParses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": "SERVICE_UNAVAILABLE", "message": "unavailable", "details": "db down"},
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&Config{
		BaseURL: server.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 1, TLSVerify: false,
	})
	require.NoError(t, err)

	_, err = client.Get(context.Background(), "/test")
	require.Error(t, err)

	var httpErr *HTTPError
	require.True(t, errors.As(err, &httpErr))
	assert.Equal(t, http.StatusServiceUnavailable, httpErr.StatusCode)
	assert.Equal(t, "SERVICE_UNAVAILABLE", httpErr.ErrorType)
	assert.Equal(t, "unavailable", httpErr.Message)
	assert.Equal(t, "db down", httpErr.Details)
}

// TestHTTPClient_4xx_MalformedNonJSONBody_DegradesGracefully pins requirement
// (b): a 4xx/5xx response with a body that ISN'T JSON at all (e.g. a
// proxy/WAF interstitial, an nginx default error page, a plain-text upstream
// error) must not panic and must still produce a usable, non-empty error —
// falling back to the raw status/body instead of silently dropping it.
func TestHTTPClient_4xx_MalformedNonJSONBody_DegradesGracefully(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	}))
	defer server.Close()

	client, err := NewHTTPClient(&Config{
		BaseURL: server.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 1, TLSVerify: false,
	})
	require.NoError(t, err)

	var got error
	assert.NotPanics(t, func() {
		_, got = client.Get(context.Background(), "/test")
	})
	require.Error(t, got)

	var httpErr *HTTPError
	require.True(t, errors.As(got, &httpErr))
	assert.Equal(t, http.StatusBadGateway, httpErr.StatusCode)
	assert.Empty(t, httpErr.ErrorType, "a non-JSON body has no structured error type to extract")
	assert.Contains(t, httpErr.Details, "502 Bad Gateway", "the raw body must be preserved, not silently dropped")
	assert.NotPanics(t, func() { _ = got.Error() })
}

// TestHTTPClient_4xx_EmptyBody_DegradesGracefully covers a 4xx/5xx status with
// a genuinely empty body (no JSON, no text at all) — must not panic and must
// still carry the HTTP status in the resulting error.
func TestHTTPClient_4xx_EmptyBody_DegradesGracefully(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewHTTPClient(&Config{
		BaseURL: server.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 1, TLSVerify: false,
	})
	require.NoError(t, err)

	var got error
	assert.NotPanics(t, func() {
		_, got = client.Get(context.Background(), "/test")
	})
	require.Error(t, got)

	var httpErr *HTTPError
	require.True(t, errors.As(got, &httpErr))
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
	assert.NotPanics(t, func() { _ = got.Error() })
}

// TestHTTPClient_NetworkUnreachable_DegradesGracefully pins the other half of
// requirement (b): a genuine network-level failure (the server is
// unreachable entirely, not merely returning an error status) must not panic
// and must still surface a sensible, non-empty error.
func TestHTTPClient_NetworkUnreachable_DegradesGracefully(t *testing.T) {
	// Bind and immediately close a listener so the port is refusing
	// connections deterministically (no real service behind it).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachableURL := server.URL
	server.Close()

	client, err := NewHTTPClient(&Config{
		BaseURL: unreachableURL, APIKey: "test-key", TimeoutSeconds: 2, RetryAttempts: 1, TLSVerify: false,
	})
	require.NoError(t, err)

	var got error
	assert.NotPanics(t, func() {
		_, got = client.Get(context.Background(), "/test")
	})
	require.Error(t, got)
	assert.NotPanics(t, func() { _ = got.Error() })

	// A pure network failure is NOT a structured HTTPError (there is no HTTP
	// response at all to parse a status/body from).
	var httpErr *HTTPError
	assert.False(t, errors.As(got, &httpErr), "a connection-refused failure has no HTTP response to build an HTTPError from")
}

func TestHTTPClient_Timeout(t *testing.T) {
	// Create a test server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Delay longer than client timeout
		response := APIResponse{
			Success: true,
			Data:    json.RawMessage(`{"message": "success"}`),
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := &Config{
		BaseURL:        server.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 1, // Short timeout
		RetryAttempts:  1,
		TLSVerify:      false,
	}

	client, err := NewHTTPClient(config)
	require.NoError(t, err)

	_, err = client.Get(context.Background(), "/test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestIsRetryableError pins #317: a non-retryable failure (marshal error, or a
// 4xx client error other than 429) must not be retried — the old
// implementation always returned true, burning the full retry budget with
// quadratic backoff for failures that could never succeed on retry.
func TestIsRetryableError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"5xx is retryable", &HTTPError{StatusCode: http.StatusInternalServerError}, true},
		{"429 is retryable", &HTTPError{StatusCode: http.StatusTooManyRequests}, true},
		{"401 is not retryable", &HTTPError{StatusCode: http.StatusUnauthorized}, false},
		{"403 is not retryable", &HTTPError{StatusCode: http.StatusForbidden}, false},
		{"404 is not retryable", &HTTPError{StatusCode: http.StatusNotFound}, false},
		{"marshal error is not retryable", fmt.Errorf("failed to marshal request body: boom"), false},
		{"request-construction error is not retryable", fmt.Errorf("failed to create request: boom"), false},
		{"generic network error is retryable", fmt.Errorf("request failed: connection refused"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isRetryableError(c.err))
		})
	}
}

// TestHTTPClient_CircuitBreakerFields_ConcurrentAccess pins #316: the circuit
// breaker fields must be race-free under concurrent use, since *HTTPClient is
// a long-lived singleton shared by every concurrent request-handling goroutine
// when storage.type: remote. Run with -race.
func TestHTTPClient_CircuitBreakerFields_ConcurrentAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewHTTPClient(&Config{
		BaseURL: server.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.Get(context.Background(), "/test")
		}()
	}
	wg.Wait()
}
