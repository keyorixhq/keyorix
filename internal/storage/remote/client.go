package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxResponseBytes caps a single API response body to bound client memory use.
const maxResponseBytes = 64 << 20 // 64 MiB

// cacheEntry represents a cached response
type cacheEntry struct {
	response  *APIResponse
	timestamp time.Time
	ttl       time.Duration
}

// HTTPClient wraps http.Client with retry logic and authentication
type HTTPClient struct {
	client        *http.Client
	baseURL       string
	apiKey        string
	retryAttempts int
	userAgent     string

	// Circuit breaker state. cbMux guards all three fields (#316): HTTPClient is a
	// long-lived singleton shared by every concurrent request-handling goroutine
	// when storage.type: remote, and these were read/written with no
	// synchronization at all — a genuine data race under concurrent use.
	cbMux           sync.Mutex
	failureCount    int
	lastFailureTime time.Time
	circuitOpen     bool

	// Response cache
	cache    map[string]*cacheEntry
	cacheMux sync.RWMutex
}

// NewHTTPClient creates a new HTTP client for remote API calls
func NewHTTPClient(config *Config) (*HTTPClient, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create HTTP client with timeout. Refuse a redirect to a different host so a
	// compromised/misbehaving server can't bounce the token-bearing request elsewhere
	// (Go already strips the Authorization header cross-host, but don't follow at all).
	httpClient := &http.Client{
		Timeout: config.GetTimeout(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("remote: refusing redirect to a different host %q", req.URL.Host)
			}
			return nil
		},
	}

	// Configure TLS if needed
	if !config.TLSVerify {
		// #nosec G402 -- InsecureSkipVerify is explicitly user-controlled via
		// tls_verify: false in config. Intended for dev/air-gapped environments only.
		// Production deployments must use tls_verify: true.
		log.Println("WARNING: TLS verification disabled. Do not use in production.")
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- NOSONAR go:S4830 go:S5527: InsecureSkipVerify is user-controlled via tls_verify config
		}
	}

	hc := &HTTPClient{
		client:        httpClient,
		baseURL:       config.BaseURL,
		apiKey:        config.GetAPIKeyFromEnv(),
		retryAttempts: config.RetryAttempts,
		userAgent:     "keyorix-cli/1.0",
		cache:         make(map[string]*cacheEntry),
		cacheMux:      sync.RWMutex{},
	}
	// hc.baseURL is a distinct field declaration from config.BaseURL (which
	// config.Validate already checked above) -- this direct read of hc.baseURL is
	// what lets a static analyzer recognize the SAME validation as covering the
	// field makeRequest below actually reads.
	if err := validateBaseURL(hc.baseURL); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return hc, nil
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError represents an API error response
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error implements the error interface. Nil-safe (#314): every remote_*.go call
// site does resp.Error.Error() as soon as resp.Success is false, and makeRequest
// can return Success:false with a nil Error (an upstream 2xx whose JSON body
// simply omits "error") — without this guard, that call site pattern panics.
func (e *APIError) Error() string {
	if e == nil {
		return "unknown error"
	}
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// circuitBreakerOpen reports whether the circuit breaker currently refuses
// requests, closing it first if the 30s cooldown has elapsed (#316: guarded by
// cbMux instead of being read/written unsynchronized).
func (c *HTTPClient) circuitBreakerOpen() bool {
	c.cbMux.Lock()
	defer c.cbMux.Unlock()
	if !c.circuitOpen {
		return false
	}
	if time.Since(c.lastFailureTime) > 30*time.Second {
		c.circuitOpen = false
		c.failureCount = 0
		return false
	}
	return true
}

func (c *HTTPClient) resetFailureCount() {
	c.cbMux.Lock()
	c.failureCount = 0
	c.cbMux.Unlock()
}

// Request makes an HTTP request with retry logic and circuit breaker
func (c *HTTPClient) Request(ctx context.Context, method, path string, body interface{}) (*APIResponse, error) {
	if c.circuitBreakerOpen() {
		return nil, fmt.Errorf("circuit breaker is open, service unavailable")
	}

	var lastErr error

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.makeRequest(ctx, method, path, body)
		if err != nil {
			lastErr = err
			c.recordFailure()

			// Retry on network errors
			if isRetryableError(err) {
				continue
			}
			return nil, err
		}

		// Reset failure count on success
		c.resetFailureCount()
		// A successful mutation (anything but GET) invalidates the WHOLE GET cache,
		// not just the entry for this path. Without this, a revoked/rotated secret
		// (or any other resource) written through THIS client instance — e.g. a
		// server running with storage.type: remote, proxying to another Keyorix
		// server — could still be served stale from the 5-minute GET cache for up to
		// 5 minutes after its own write, since GetSecret/UpdateSecret/DeleteSecret
		// use different cache keys (id-based vs by-name) that a targeted single-key
		// invalidation would miss. This does not help a write made through a
		// DIFFERENT client/instance (out-of-band revoke) — only shortening the TTL
		// or adding a push-invalidation channel would close that window, which is a
		// larger change than this fixes; this closes the read-your-own-write case.
		if method != http.MethodGet && resp.Success {
			c.cacheMux.Lock()
			c.cache = make(map[string]*cacheEntry)
			c.cacheMux.Unlock()
		}
		return resp, nil
	}

	c.recordFailure()
	return nil, fmt.Errorf("request failed after %d attempts: %w", c.retryAttempts, lastErr)
}

// recordFailure records a failure and potentially opens the circuit breaker
func (c *HTTPClient) recordFailure() {
	c.cbMux.Lock()
	defer c.cbMux.Unlock()
	c.failureCount++
	c.lastFailureTime = time.Now()

	// Open circuit breaker after 5 consecutive failures
	if c.failureCount >= 5 {
		c.circuitOpen = true
	}
}

// makeRequest makes a single HTTP request
func (c *HTTPClient) makeRequest(ctx context.Context, method, path string, body interface{}) (*APIResponse, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	// c.client (built in NewHTTPClient above) already sets CheckRedirect to reject
	// a cross-host redirect, and config.BaseURL is scheme/host validated by
	// Config.Validate's validateBaseURL(c.BaseURL) call (a direct field read,
	// rejecting non-https except for a loopback host) before this client is
	// ever constructed.
	// codeql[go/keyorix-ssrf-unvalidated-outbound-request]: the query traces this
	// sink's taint back to callers that build `path` from an incoming HTTP request's
	// r.URL.Query() values (e.g. server/http/handlers/audit.go's filter params) --
	// an incoming-request field that happens to match the query's url/host/dsn/
	// webhook/callback field-name heuristic. Those values only ever contribute a
	// query-string suffix appended to the already-validated c.baseURL above, never
	// the request's own host/scheme. Not a real unvalidated destination -- a
	// coincidental name match on net/http.Request.URL.
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Bound the response so a malicious/MITM server can't OOM the client.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// A 2xx response with a genuinely empty body (the canonical shape of a 204
	// No Content, e.g. DeleteUser/DeleteSecret) is an unambiguous success, not
	// a parse failure (#498). json.Unmarshal on zero bytes errors with
	// "unexpected end of JSON input", which — before this check — fell into
	// the generic parse-error branch below and synthesized Success:false,
	// silently misreporting every genuinely successful delete as failed. Only
	// short-circuit for a truly empty body on a 2xx status; a malformed/
	// truncated JSON body (non-empty) still falls through to the real parse
	// error below, so a corrupted response on a 200 that was SUPPOSED to
	// carry content is still correctly surfaced as an error.
	if len(respBody) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &APIResponse{Success: true}, nil
	}

	// Any 4xx/5xx status is unconditionally a failure (#501): parse the body
	// for the server's actual structured error detail and return it as an
	// error, rather than sometimes returning a "successful round trip with
	// Success:false" *APIResponse (the old behavior when the body didn't
	// unmarshal into APIResponse — which is the common case for THIS server,
	// since sendError's "error" field is a bare type string, not the nested
	// object APIResponse.Error expects, so json.Unmarshal always failed and
	// the real code/message were discarded into an opaque "HTTP 404: 404 Not
	// Found" string). Every remote_*.go call site checks `err != nil` before
	// ever touching the response (verified across all ~60 call sites), so
	// collapsing onto the error return is safe and gives every caller ONE
	// consistent failure signal for what is really the same class of failure.
	//
	// This also fixes a latent circuit-breaker bug: previously, a real 4xx/5xx
	// response (which never unmarshaled into APIResponse) came back as
	// (resp, nil) from makeRequest, and Request() treated a nil error as a
	// SUCCESSFUL round trip — calling c.resetFailureCount() instead of
	// c.recordFailure(). The circuit breaker could never open against a real
	// server returning persistent 5xx errors.
	if resp.StatusCode >= 400 {
		return nil, newHTTPError(resp.StatusCode, resp.Status, respBody)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		// If we can't parse as API response, create a generic error
		return &APIResponse{
			Success: false,
			Error: &APIError{
				Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
				Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status),
				Details: string(respBody),
			},
		}, nil
	}

	// #314: a 2xx/3xx upstream response can still carry Success:false with no
	// "error" field populated (e.g. a proxy/WAF/CDN interstitial, or a degraded
	// upstream returning "{}") — every remote_*.go call site immediately does
	// resp.Error.Error() as soon as !resp.Success, which would otherwise panic
	// on this nil field. Synthesize a generic error so callers always have
	// something safe to report.
	if !apiResp.Success && apiResp.Error == nil {
		apiResp.Error = &APIError{
			Code:    "UPSTREAM_UNSUCCESSFUL",
			Message: "upstream returned an unsuccessful response with no error detail",
		}
	}

	return &apiResp, nil
}

// serverErrorBody mirrors the JSON shape sendError actually writes
// (server/http/handlers/helpers.go): a flat object with a short
// machine-readable "error" type string (e.g. "NotFound", "ValidationError",
// "ConflictError"), not the nested {"error": {"code":...,"message":...}}
// shape APIResponse.Error/APIError models. That mismatch is why
// json.Unmarshal(respBody, &APIResponse{}) always failed with a type error
// for a real 4xx/5xx response from this server, discarding the server's
// actual code/message/details (#501).
type serverErrorBody struct {
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Message string          `json:"message"`
	Code    int             `json:"code"`
	Details json.RawMessage `json:"details,omitempty"`
}

// HTTPError is returned by makeRequest for every 4xx/5xx HTTP response. It
// carries the server's actual structured error type/message when the body
// parses — as either the flat shape sendError emits (the common case against
// this codebase's own server) or, defensively, the nested
// {"error":{"code","message","details"}} shape in case some other upstream
// emits that instead — rather than collapsing every distinct failure mode
// (not found vs. validation vs. permission denied vs. rate limited) into an
// identical generic "HTTP 404: 404 Not Found" string.
//
// Callers that need to distinguish specific outcomes should use
// errors.As(err, &httpErr) and branch on StatusCode/ErrorType (or the
// IsNotFound helper) instead of string-matching Error().
type HTTPError struct {
	StatusCode int
	Status     string
	ErrorType  string // e.g. "NotFound", "ValidationError", "ConflictError"; empty if unavailable
	Message    string
	Details    string
}

// newHTTPError builds an HTTPError for a 4xx/5xx response, extracting
// whatever structured detail the body actually contains. It never panics and
// always returns a non-nil, usable error, even for an empty or non-JSON body
// (e.g. a proxy/WAF interstitial or a plain-text upstream error page) — the
// raw body is preserved in Details rather than silently dropped.
func newHTTPError(statusCode int, status string, body []byte) *HTTPError {
	e := &HTTPError{StatusCode: statusCode, Status: status}

	var flat serverErrorBody
	if err := json.Unmarshal(body, &flat); err == nil && (flat.Error != "" || flat.Message != "") {
		e.ErrorType = flat.Error
		e.Message = flat.Message
		e.Details = rawJSONToString(flat.Details)
		return e
	}

	// Defensive fallback: some upstream might emit the nested APIResponse.Error
	// shape instead of the flat sendError shape.
	var nested APIResponse
	if err := json.Unmarshal(body, &nested); err == nil && nested.Error != nil {
		e.ErrorType = nested.Error.Code
		e.Message = nested.Error.Message
		e.Details = nested.Error.Details
		return e
	}

	// Body didn't parse as either known shape (empty, non-JSON, or an
	// unrelated JSON document) — preserve the raw text as Details rather than
	// pretending it's a structured error.
	e.Details = string(body)
	return e
}

// rawJSONToString renders a json.RawMessage as plain text: unwraps a JSON
// string to its literal value, otherwise falls back to the raw JSON text
// (e.g. an object/array details payload).
func rawJSONToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

func (e *HTTPError) Error() string {
	switch {
	case e.ErrorType != "" && e.Message != "":
		if e.Details != "" {
			return fmt.Sprintf("%s: %s (%s)", e.ErrorType, e.Message, e.Details)
		}
		return fmt.Sprintf("%s: %s", e.ErrorType, e.Message)
	case e.Message != "":
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
	case e.Details != "":
		return fmt.Sprintf("HTTP %d: %s: %s", e.StatusCode, e.Status, e.Details)
	default:
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Status)
	}
}

// IsNotFound reports whether the server identified this failure as a
// not-found condition. Checked against the actual HTTP status rather than
// ErrorType text, since handler-chosen ErrorType strings aren't a guaranteed-
// stable API contract — callers should prefer this over matching Error() text.
func (e *HTTPError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// isRetryableError determines whether a failed request is worth retrying
// (#317: this previously always returned true regardless of the error,
// meaning genuinely non-retryable failures — a marshal error, or a 401/403/404
// — burned the full retry budget with quadratic backoff for no benefit).
//
// Retryable: network-level failures (connection refused/reset, DNS, timeout —
// anything from http.Client.Do or reading the response body) and 5xx/429
// upstream statuses. Not retryable: request-construction failures (marshal,
// NewRequest) and 4xx client errors other than 429 — none of these can ever
// succeed on retry, since the request itself (not the network) is the problem.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 500 || httpErr.StatusCode == http.StatusTooManyRequests
	}
	msg := err.Error()
	if strings.Contains(msg, "failed to marshal request body") || strings.Contains(msg, "failed to create request") {
		return false
	}
	// Everything else reaching here is a network-level failure (request failed:
	// ..., failed to read response body: ...) — transient by nature.
	return true
}

// Get makes a GET request with caching
func (c *HTTPClient) Get(ctx context.Context, path string) (*APIResponse, error) {
	// Check cache for GET requests
	cacheKey := "GET:" + path
	c.cacheMux.RLock()
	if entry, exists := c.cache[cacheKey]; exists {
		// Check if cache entry is still valid
		if time.Since(entry.timestamp) < entry.ttl {
			c.cacheMux.RUnlock()
			return entry.response, nil
		}
	}
	c.cacheMux.RUnlock()

	// Make the request
	resp, err := c.Request(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	// Cache successful GET responses for 5 minutes
	if resp.Success {
		c.cacheMux.Lock()
		c.cache[cacheKey] = &cacheEntry{
			response:  resp,
			timestamp: time.Now(),
			ttl:       5 * time.Minute,
		}
		c.cacheMux.Unlock()
	}

	return resp, nil
}

// Post makes a POST request
func (c *HTTPClient) Post(ctx context.Context, path string, body interface{}) (*APIResponse, error) {
	return c.Request(ctx, "POST", path, body)
}

// Put makes a PUT request
func (c *HTTPClient) Put(ctx context.Context, path string, body interface{}) (*APIResponse, error) {
	return c.Request(ctx, "PUT", path, body)
}

// Delete makes a DELETE request
func (c *HTTPClient) Delete(ctx context.Context, path string) (*APIResponse, error) {
	return c.Request(ctx, "DELETE", path, nil)
}
