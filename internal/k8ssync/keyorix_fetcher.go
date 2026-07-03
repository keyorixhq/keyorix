package k8ssync

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

// ErrUpstreamGone is a sentinel a Fetch error wraps when the failure is DEFINITIVE —
// the secret no longer exists upstream (404, or absent from the environment listing)
// or access to it has been revoked (401/403) — as opposed to a transient failure
// (network error, timeout, 5xx) that might clear on the next reconcile pass. #140:
// the sync loop uses this distinction to actively remove a de-authorized/deleted
// secret's stale materialized value from the cluster, rather than leaving it as-is
// indefinitely (which a plain, unclassified fetch error did).
var ErrUpstreamGone = errors.New("k8ssync: secret not found or access revoked upstream")

// KeyorixFetcher reads secret values from a Keyorix server over HTTP, resolving a
// reference of the form "<environment>/<name>" (e.g. "production/db-password") to the
// secret's current value. It satisfies Fetcher. Auth is a bearer token (typically a
// machine-identity / service-account token); the token is sent on every request and
// never logged.
type KeyorixFetcher struct {
	baseURL string
	token   string
	hc      *http.Client
}

// NewKeyorixFetcher builds a fetcher for the given Keyorix base URL (e.g.
// https://keyorix.internal) and bearer token. A nil-safe default HTTP client with a
// sane timeout is used.
func NewKeyorixFetcher(baseURL, token string) *KeyorixFetcher {
	return &KeyorixFetcher{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch resolves ref ("<environment>/<name>") to the secret's id and returns its
// current value.
func (f *KeyorixFetcher) Fetch(ctx context.Context, ref string) ([]byte, error) {
	env, name, err := parseRef(ref)
	if err != nil {
		return nil, err
	}
	id, err := f.resolveID(ctx, env, name)
	if err != nil {
		return nil, err
	}
	return f.fetchValue(ctx, id)
}

// parseRef splits "<environment>/<name>" into its parts. The name may itself contain
// slashes (a path-like secret name); only the first segment is the environment.
func parseRef(ref string) (env, name string, err error) {
	ref = strings.TrimSpace(ref)
	i := strings.IndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("invalid ref %q: expected \"<environment>/<name>\"", ref)
	}
	return ref[:i], ref[i+1:], nil
}

// resolveID finds the id of the secret named name in environment env. The list is
// filtered server-side by environment; the name match is exact (case-insensitive).
func (f *KeyorixFetcher) resolveID(ctx context.Context, env, name string) (uint, error) {
	q := url.Values{}
	q.Set("environment", env)
	q.Set("page_size", "1000")
	q.Set("page", "1")
	var body struct {
		Secrets []struct {
			ID   uint   `json:"ID"`
			Name string `json:"Name"`
		} `json:"secrets"`
	}
	if err := f.getJSON(ctx, "/api/v1/secrets?"+q.Encode(), &body); err != nil {
		return 0, fmt.Errorf("list secrets in %q: %w", env, err)
	}
	for _, s := range body.Secrets {
		if strings.EqualFold(s.Name, name) {
			return s.ID, nil
		}
	}
	return 0, fmt.Errorf("secret %q not found in environment %q: %w", name, env, ErrUpstreamGone)
}

// fetchValue returns the decrypted value of the secret with the given id.
func (f *KeyorixFetcher) fetchValue(ctx context.Context, id uint) ([]byte, error) {
	var body struct {
		Value string `json:"value"`
	}
	if err := f.getJSON(ctx, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), &body); err != nil {
		return nil, fmt.Errorf("read secret %d value: %w", id, err)
	}
	return []byte(body.Value), nil
}

// getJSON performs an authenticated GET and decodes the {"data": …} envelope into out.
func (f *KeyorixFetcher) getJSON(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Accept", "application/json")

	resp, err := f.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("not authorized (HTTP %d) — check the agent's token and its permissions: %w", resp.StatusCode, ErrUpstreamGone)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found (HTTP 404): %w", ErrUpstreamGone)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if env.Data == nil {
		return fmt.Errorf("empty data in response")
	}
	return json.Unmarshal(env.Data, out)
}
