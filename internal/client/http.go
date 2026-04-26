package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Config holds the configuration for HTTP client
type Config struct {
	Endpoint string        `yaml:"endpoint"`
	APIKey   string        `yaml:"api_key"`
	Timeout  time.Duration `yaml:"timeout"`
}

// HTTPClient implements the same interface as core service but via HTTP
type HTTPClient struct {
	client   *http.Client
	endpoint string
	apiKey   string
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(config *Config) (*HTTPClient, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		endpoint: config.Endpoint,
		apiKey:   config.APIKey,
	}, nil
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *APIError       `json:"error,omitempty"`
}

// APIError represents an API error
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

// request makes an HTTP request to the server
func (c *HTTPClient) request(ctx context.Context, method, path string, body interface{}) (*APIResponse, error) {
	url := c.endpoint + path

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
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "keyorix-cli/1.0")

	// Add authentication if API key is provided
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

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
		return &apiResp, nil
	}

	return &apiResp, nil
}

// Health checks the health of the remote server
func (c *HTTPClient) Health(ctx context.Context) error {
	resp, err := c.request(ctx, "GET", "/health", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !resp.Success {
		if resp.Error != nil {
			return fmt.Errorf("server health check failed: %s", resp.Error.Error())
		}
		return fmt.Errorf("server health check failed: unexpected response")
	}

	return nil
}

// CreateSecret creates a new secret via HTTP API
func (c *HTTPClient) CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	resp, err := c.request(ctx, "POST", "/api/v1/secrets", secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("create secret failed: %s", resp.Error.Error())
	}

	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// GetSecret retrieves a secret by ID via HTTP API
func (c *HTTPClient) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d", id)
	resp, err := c.request(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("get secret failed: %s", resp.Error.Error())
	}

	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// UpdateSecret updates an existing secret via HTTP API
func (c *HTTPClient) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	path := fmt.Sprintf("/api/v1/secrets/%d", secret.ID)
	resp, err := c.request(ctx, "PUT", path, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("update secret failed: %s", resp.Error.Error())
	}

	var result models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// DeleteSecret deletes a secret by ID via HTTP API
func (c *HTTPClient) DeleteSecret(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/secrets/%d", id)
	resp, err := c.request(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("delete secret failed: %s", resp.Error.Error())
	}

	return nil
}

// ListSecrets lists secrets via HTTP API
func (c *HTTPClient) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, error) {
	path := "/api/v1/secrets"

	// Add query parameters for filtering if needed
	// This is a simplified implementation - you can enhance it based on your filter struct

	resp, err := c.request(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("list secrets failed: %s", resp.Error.Error())
	}

	var result []*models.SecretNode
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// Additional methods for sharing functionality can be added here
// ShareSecret, UpdateSharePermission, RevokeShare, etc.
// Following the same pattern as above
