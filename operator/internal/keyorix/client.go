// Package keyorix is a tiny HTTP client for the Keyorix by-reference value endpoint
// (GET /api/v1/secrets/value?ref=project/environment/name, ADR-059). It is deliberately
// dependency-free and reads one value at a time; the operator never logs values.
package keyorix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBodyBytes caps how much of FetchValue's HTTP response body is ever
// decoded (#428 follow-up). Without a cap, json.NewDecoder(resp.Body) buffers an
// arbitrarily large (or gzip-bomb-expanded, since Go's transport auto-decompresses)
// response fully into memory — and this operator runs as a single cluster-wide
// singleton reconciler (see maxConcurrentReconciles in the controller package), so an
// OOM here doesn't just fail one reconcile, it halts secret sync for every
// KeyorixSecret in the cluster. Mirrors the same constant/idiom already used by
// internal/mcp/keyorix.go's getJSON for the identical by-reference value endpoint.
const maxResponseBodyBytes = 10 << 20 // 10 MiB

// ErrSecretGone is wrapped into the error FetchValue returns when the Keyorix server
// AFFIRMATIVELY reports the referenced secret no longer exists or is no longer
// accessible (HTTP 404 Not Found — the server's ref resolution already collapses
// "never existed" and "soft-deleted" into 404 — or HTTP 403 Forbidden, meaning the
// caller's own scope was denied for that specific reference, e.g. a revoked
// machine-identity role). Callers use errors.Is(err, ErrSecretGone) to distinguish
// this confirmed case from a transient failure (network error, timeout, 5xx) where
// taking a destructive action on a previously synced target would cause an unnecessary
// outage for workloads that depend on it.
//
// A 401 is deliberately NOT folded into ErrSecretGone: unlike 403, it says the bearer
// token itself is invalid/expired, not that the referenced secret's own existence or
// grant was checked and denied. It gets its own sentinel, ErrUnauthorized, below.
var ErrSecretGone = errors.New("secret reference no longer exists or is not accessible")

// ErrUnauthorized is wrapped into the error FetchValue returns on HTTP 401. A 401 is
// distinct from 403/404 (see ErrSecretGone) in what it tells us about the referenced
// secret, but it is NOT merely "transient and ignorable" either: the overwhelmingly
// common real-world cause of a previously-working bearer token suddenly turning invalid
// is that an admin revoked or rotated the machine-identity credential — i.e. access was
// deliberately cut. That is exactly the same "stop serving the stale value" signal as a
// confirmed-gone 404/403, so callers (the controller's Reconcile) treat
// errors.Is(err, ErrUnauthorized) the same as ErrSecretGone for the purpose of wiping a
// previously-materialized target Secret, while still recording a distinct status reason
// so it's clear from the CR's condition which of the two actually happened.
var ErrUnauthorized = errors.New("bearer token rejected (unauthorized)")

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
		hc:      &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirect},
	}
}

// refuseRedirect blocks the http.Client from following ANY redirect. Go's default
// redirect behavior only strips the Authorization header when the redirect target's
// Host differs from the original — it never checks scheme. A same-host redirect from
// https:// to http:// (a misconfigured reverse proxy in front of the Keyorix server, or
// a compromised server) would otherwise keep this client's bearer token attached and
// send it — and the plaintext secret value in the response — over cleartext. This
// client only ever talks to a single, fixed, operator-validated base URL (see
// validateServer in the controller package, which also requires https) and has no
// legitimate reason to follow a redirect at all, so refusing every redirect outright is
// the simplest and safest fix.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

// FetchValue returns the current value of the secret referenced by
// "project/environment/name".
func (c *Client) FetchValue(ctx context.Context, ref string) ([]byte, error) {
	q := url.Values{}
	q.Set("ref", ref)
	// c.hc (built in New above) already sets CheckRedirect to refuseRedirect, and
	// the caller (KeyorixSecretReconciler.buildDesired) validates ks.Spec.Server
	// against an operator-configured --allowed-servers allowlist via
	// validateServer BEFORE ever constructing this Client — see
	// keyorixsecret_controller.go. The query can't see either: CheckRedirect is
	// set on the same composite literal in a different function, and the
	// validated field (KeyorixSecretSpec.Server) is three frames upstream of
	// Client.baseURL with no name overlap the query's field-identity check can
	// follow.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/secrets/value?"+q.Encode(), nil) // codeql[go/keyorix-ssrf-unvalidated-outbound-request]
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
		// permitted, so this must NOT be treated as ErrSecretGone. It IS wrapped as
		// ErrUnauthorized (see its doc comment) so the controller can still treat a
		// revoked/rotated credential as an access-cut signal worth wiping for.
		return nil, fmt.Errorf("not authorized (HTTP 401) — check the token is valid: %w", ErrUnauthorized)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return []byte(body.Data.Value), nil
}
