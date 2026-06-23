// Package keyorix is a tiny HTTP client for the Keyorix by-reference value endpoint
// (GET /api/v1/secrets/value?ref=project/environment/name, ADR-059). It is deliberately
// dependency-free and reads one value at a time; the operator never logs values.
package keyorix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client reads secret values from a Keyorix server with a bearer (machine-identity)
// token. The token is sent on every request and never logged.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

// New builds a client for the given Keyorix base URL and bearer token.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchValue returns the current value of the secret referenced by
// "project/environment/name".
func (c *Client) FetchValue(ctx context.Context, ref string) ([]byte, error) {
	q := url.Values{}
	q.Set("ref", ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/secrets/value?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("not authorized (HTTP %d) — check the token and its secrets.read permission", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("secret reference %q not found", ref)
	case resp.StatusCode == http.StatusBadRequest:
		return nil, fmt.Errorf("invalid reference %q (want project/environment/name)", ref)
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return []byte(body.Data.Value), nil
}
