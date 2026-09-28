// Package healthscan implements `keyorix-migrate vault scan`: a strictly read-only inspection
// of a Vault (or OpenBao) install, safe to run against production. Client is the one and only
// way any check in this package talks to Vault, and it can issue exactly two HTTP methods — GET
// and LIST — nothing else. request() enforces this as a runtime guard (not just an API-shape
// convention): an unrecognized method is rejected before any request is built or any network
// call is attempted, proven by TestRequest_RejectsWriteMethods.
//
// This is a deliberately separate client from ../vaultsource (the `keyorix-migrate vault`
// import command's client): vaultsource is a KV-mount-scoped recursive walk/read; healthscan
// reads arbitrary sys/*, auth/* and identity/* paths outside any KV mount. Auth, TLS, redirect
// refusal and the response-size cap are ported from vaultsource/httpsafe rather than shared
// directly, matching this module's existing "ported, not shared" precedent
// (docs/design-keyorix-migrate.md's "Vault client" section) — vaultsource.Client exposes no
// generic request method a caller outside the package could reuse.
package healthscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/migrate/internal/httpsafe"
)

// MethodList is Vault's native list verb — not one of Go's net/http method constants, but a
// real HTTP method Vault's API accepts directly (equivalent to GET ...?list=true, which this
// client uses to avoid depending on a non-standard verb some HTTP middleware/proxies reject).
const MethodList = "LIST"

// allowedMethods is the complete set of HTTP methods this client will ever issue against a
// configured Vault. Checked in request() before anything else happens.
var allowedMethods = map[string]bool{
	http.MethodGet: true,
	MethodList:     true,
}

// Config holds every connection/auth setting a Client needs. Exactly one of Token or
// (RoleID, SecretID) must be set; Namespace is optional. Mirrors vaultsource.Config's shape
// deliberately — same flags, same env vars, same operator experience — but healthscan additionally
// accepts TLSSkipVerify, which vaultsource intentionally never offers (vaultsource writes secret
// VALUES over that connection; healthscan never reads a secret value at all — see Client's doc
// comment — so the risk profile differs enough to justify the one divergence, and only when the
// operator opts in explicitly and is warned loudly every time, see New).
type Config struct {
	Addr      string
	Namespace string

	Token string

	RoleID   string
	SecretID string

	// CACertPath / CACertDir pin the TLS trust root to a private/internal CA, replacing (not
	// appending to) the system trust store — same semantics as vaultsource.Config.
	CACertPath string
	CACertDir  string

	// TLSSkipVerify disables TLS certificate verification entirely. Refused by default; New
	// honors it only when explicitly set to true, and always writes a loud warning to warnOut
	// first. There is no way to set this from an env var — an operator who wants it must pass
	// the flag, every run, on purpose.
	TLSSkipVerify bool
}

// Client talks to Vault's HTTP API read-only: GET and LIST only, enforced in request().
type Client struct {
	addr      string
	namespace string
	token     string
	hc        *http.Client
}

// New builds a Client, performing AppRole login immediately if configured (so a bad
// role-id/secret-id fails fast at startup). warnOut receives the TLS-skip-verify warning, when
// applicable — always a real io.Writer (os.Stderr in production, a buffer in tests), never
// silently swallowed by the caller's choice.
func New(ctx context.Context, cfg Config, warnOut io.Writer) (*Client, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vault address is required (--addr or $VAULT_ADDR)")
	}
	if cfg.Token == "" && (cfg.RoleID == "" || cfg.SecretID == "") {
		return nil, fmt.Errorf("vault auth is required: --vault-token/$VAULT_TOKEN, or both --vault-role-id and --vault-secret-id")
	}

	tlsConfig, err := buildTLSConfig(cfg, warnOut)
	if err != nil {
		return nil, err
	}
	hc := httpsafe.Client()
	hc.Transport = httpsafe.CappedTransport{Base: &http.Transport{TLSClientConfig: tlsConfig}}

	c := &Client{
		addr:      strings.TrimRight(cfg.Addr, "/"),
		namespace: cfg.Namespace,
		hc:        hc,
	}

	if cfg.Token != "" {
		c.token = cfg.Token
		return c, nil
	}
	token, err := c.appRoleLogin(ctx, cfg.RoleID, cfg.SecretID)
	if err != nil {
		return nil, fmt.Errorf("vault AppRole login: %w", err)
	}
	c.token = token
	return c, nil
}

// buildTLSConfig returns nil (Go's default system trust store) when neither a CA pin nor
// TLSSkipVerify is set. TLSSkipVerify wins over a CA pin if both are somehow set (skip-verify
// makes a trust root moot) and always writes a warning first — this is the ONE place in this
// module that InsecureSkipVerify is permitted to appear; see redact_test.go /
// TestNoSilentSkipVerify for why that stays true by construction.
func buildTLSConfig(cfg Config, warnOut io.Writer) (*tls.Config, error) {
	if cfg.TLSSkipVerify {
		fmt.Fprintln(warnOut, "WARNING: --tls-skip-verify disables TLS certificate verification for this scan. "+ //nolint:errcheck
			"Anyone able to intercept the connection to Vault can read your Vault token and every value "+
			"this tool reads (metadata only — see Client's doc comment — but the token itself is still a credential). "+
			"Use --vault-cacert/--vault-capath for a private CA instead whenever possible.")
		return &tls.Config{InsecureSkipVerify: true}, nil // #nosec G402 -- explicit, loud, operator opt-in only (--tls-skip-verify, no env var), never the default; see doc comment above.
	}
	if cfg.CACertPath == "" && cfg.CACertDir == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath) // #nosec G304 -- operator-supplied CA cert path, a CLI flag, not user/network input
		if err != nil {
			return nil, fmt.Errorf("read --vault-cacert %q: %w", cfg.CACertPath, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--vault-cacert %q contains no usable PEM certificates", cfg.CACertPath)
		}
	}
	if cfg.CACertDir != "" {
		entries, err := os.ReadDir(cfg.CACertDir)
		if err != nil {
			return nil, fmt.Errorf("read --vault-capath %q: %w", cfg.CACertDir, err)
		}
		loaded := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			pem, err := os.ReadFile(filepath.Join(cfg.CACertDir, e.Name())) // #nosec G304 -- operator-supplied CA directory, a CLI flag, not user/network input
			if err != nil {
				return nil, fmt.Errorf("read %q in --vault-capath: %w", e.Name(), err)
			}
			if pool.AppendCertsFromPEM(pem) {
				loaded++
			}
		}
		if loaded == 0 {
			return nil, fmt.Errorf("--vault-capath %q contains no usable PEM certificates", cfg.CACertDir)
		}
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// appRoleLogin exchanges an AppRole role-id/secret-id pair for a client token via
// POST {addr}/v1/auth/approle/login. This is the one and only POST this package ever issues —
// an authentication handshake, not a scan read — ported from vaultsource.Client.appRoleLogin
// (unexported there, so duplicated rather than reused; see this file's package doc comment).
func (c *Client) appRoleLogin(ctx context.Context, roleID, secretID string) (string, error) {
	body, err := json.Marshal(struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}{RoleID: roleID, SecretID: secretID})
	if err != nil {
		return "", fmt.Errorf("build AppRole login body: %w", err)
	}

	reqURL := c.addr + "/v1/auth/approle/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("build AppRole login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setCommonHeaders(req, "")

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("AppRole login request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("AppRole login returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, httpsafe.MaxResponseBytes)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode AppRole login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole login response carried no client_token")
	}
	return result.Auth.ClientToken, nil
}

func (c *Client) setCommonHeaders(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	req.Header.Set("Accept", "application/json")
}

// StatusNotFound and StatusForbidden are re-exported as named results so check functions can
// branch on them without importing net/http themselves for just this.
const (
	StatusOK        = http.StatusOK
	StatusNotFound  = http.StatusNotFound
	StatusForbidden = http.StatusForbidden
)

// Get issues a read-only GET against {addr}/v1/{path} and returns the HTTP status and raw
// response body. A 403 is returned as (403, body, nil) — not an error — so callers can turn a
// permission-denied response into a "NOT CHECKED (permission denied)" finding rather than
// aborting the run; see docs/vault-health-scan.md.
func (c *Client) Get(ctx context.Context, path string) (int, []byte, error) {
	return c.request(ctx, http.MethodGet, path)
}

// List issues a read-only LIST against {addr}/v1/{path} (encoded as GET ...?list=true, Vault's
// documented equivalent) and returns the HTTP status and raw response body. Same 403 handling
// as Get.
func (c *Client) List(ctx context.Context, path string) (int, []byte, error) {
	return c.request(ctx, MethodList, path)
}

// request is the ONLY place this package builds an HTTP request. method is checked against
// allowedMethods FIRST, before anything else — no request is constructed and no network call is
// attempted for a rejected method. This is what TestRequest_RejectsWriteMethods proves.
func (c *Client) request(ctx context.Context, method, path string) (int, []byte, error) {
	if !allowedMethods[method] {
		return 0, nil, fmt.Errorf("healthscan: refusing HTTP method %q — this client only issues GET and LIST (read-only by construction)", method)
	}

	reqURL := c.addr + "/v1/" + escapePath(path)
	httpMethod := http.MethodGet
	if method == MethodList {
		u, err := url.Parse(reqURL)
		if err != nil {
			return 0, nil, fmt.Errorf("build request url: %w", err)
		}
		q := u.Query()
		q.Set("list", "true")
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, httpMethod, reqURL, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	c.setCommonHeaders(req, c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, httpsafe.MaxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
