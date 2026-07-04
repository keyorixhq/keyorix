// Package keyorix is a tiny HTTP client for the Keyorix by-reference value endpoint
// (GET /api/v1/secrets/value?ref=project/environment/name, ADR-059). It is deliberately
// dependency-free and reads one value at a time; the operator never logs values.
package keyorix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSecretGone is wrapped into the error FetchValue returns when the Keyorix server
// AFFIRMATIVELY reports the referenced secret no longer exists or is no longer
// accessible (HTTP 404 Not Found — the server's ref resolution already collapses
// "never existed" and "soft-deleted" into 404 — or HTTP 403 Forbidden, meaning the
// caller's own scope was denied for that specific reference, e.g. a revoked
// machine-identity role). Callers use errors.Is(err, ErrSecretGone) to distinguish
// this confirmed case from a transient failure (network error, timeout, 5xx, or a 401
// — which only says the bearer token itself is bad/expired and says nothing about the
// referenced secret's fate) where taking a destructive action on a previously synced
// target would cause an unnecessary outage for workloads that depend on it.
var ErrSecretGone = errors.New("secret reference no longer exists or is not accessible")

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
	case resp.StatusCode == http.StatusNotFound:
		// The server's ref-resolution collapses "never existed" and "soft-deleted"
		// into an identical 404 (closing an existence oracle) — either way the
		// secret this reference names is gone.
		return nil, fmt.Errorf("secret reference %q not found: %w", ref, ErrSecretGone)
	case resp.StatusCode == http.StatusForbidden:
		// Distinct from 401: this means the request was authenticated but the
		// caller's own scope/grant for THIS reference was denied — e.g. a revoked
		// machine-identity role or a suspended secret. Treated the same as "gone".
		return nil, fmt.Errorf("secret reference %q forbidden (HTTP 403) — access revoked: %w", ref, ErrSecretGone)
	case resp.StatusCode == http.StatusUnauthorized:
		// Unlike 403, a 401 says the token itself is invalid/expired — it says
		// nothing about whether the referenced secret still exists or is still
		// permitted, so this must NOT be treated as ErrSecretGone.
		return nil, fmt.Errorf("not authorized (HTTP 401) — check the token is valid")
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
