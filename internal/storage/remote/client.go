package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

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
	
	// Circuit breaker state
	failureCount    int
	lastFailureTime time.Time
	circuitOpen     bool
	
	// Response cache
	cache     map[string]*cacheEntry
	cacheMux  sync.RWMutex
}

// NewHTTPClient creates a new HTTP client for remote API calls
func NewHTTPClient(config *Config) (*HTTPClient, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: config.GetTimeout(),
	}

	// Configure TLS if needed
	if !config.TLSVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &HTTPClient{
		client:        httpClient,
		baseURL:       config.BaseURL,
		apiKey:        config.GetAPIKeyFromEnv(),
		retryAttempts: config.RetryAttempts,
		userAgent:     "keyorix-cli/1.0",
		cache:         make(map[string]*cacheEntry),
		cacheMux:      sync.RWMutex{},
	}, nil
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

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Request makes an HTTP request with retry logic and circuit breaker
func (c *HTTPClient) Request(ctx context.Context, method, path string, body interface{}) (*APIResponse, error) {
	// Check circuit breaker
	if c.circuitOpen {
		// Check if we should try to close the circuit
		if time.Since(c.lastFailureTime) > 30*time.Second {
			c.circuitOpen = false
			c.failureCount = 0
		} else {
			return nil, fmt.Errorf("circuit breaker is open, service unavailable")
		}
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
		c.failureCount = 0
		return resp, nil
	}

	c.recordFailure()
	return nil, fmt.Errorf("request failed after %d attempts: %w", c.retryAttempts, lastErr)
}

// recordFailure records a failure and potentially opens the circuit breaker
func (c *HTTPClient) recordFailure() {
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
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
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

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		if apiResp.Error == nil {
			apiResp.Error = &APIError{
				Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
				Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status),
			}
		}
		// Return error for HTTP error status codes to trigger retry logic
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return &apiResp, nil
}

// isRetryableError determines if an error is retryable
func isRetryableError(err error) bool {
	// Retry on network errors, timeouts, etc.
	// This is a simplified implementation
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