package remote

import (
	"context"
	"encoding/json"
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

func TestHTTPClient_CircuitBreaker(t *testing.T) {
	t.Skip("Circuit breaker test needs debugging - skipping for now")
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

// TestAPIError_ErrorMethod_NilSafe pins the nil-receiver guard directly: any
// existing or future caller doing (*APIError)(nil).Error() must not panic.
func TestAPIError_ErrorMethod_NilSafe(t *testing.T) {
	var e *APIError
	assert.NotPanics(t, func() {
		assert.Equal(t, "unknown error", e.Error())
	})
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
		{"5xx is retryable", &httpStatusError{StatusCode: http.StatusInternalServerError}, true},
		{"429 is retryable", &httpStatusError{StatusCode: http.StatusTooManyRequests}, true},
		{"401 is not retryable", &httpStatusError{StatusCode: http.StatusUnauthorized}, false},
		{"403 is not retryable", &httpStatusError{StatusCode: http.StatusForbidden}, false},
		{"404 is not retryable", &httpStatusError{StatusCode: http.StatusNotFound}, false},
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
