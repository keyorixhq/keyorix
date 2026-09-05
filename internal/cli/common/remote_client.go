package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/config"
)

const (
	bearerPrefix   = "Bearer "
	hdrContentType = "Content-Type"
	mimeJSON       = "application/json"
)

// maxRemoteResponseBytes caps how much of a Keyorix server response body this
// client will read into memory before decoding. RemoteClient backs every CLI
// command's remote mode (projects, secrets, environments, users, audit
// listings…), so a generous cap is used — matching the same 10MB idiom used
// for the equivalent MCP client response decode (internal/mcp/keyorix.go) —
// rather than a tight one tuned to any single endpoint's typical payload. This
// bounds a malicious or misbehaving server response from exhausting client
// memory via an unbounded json.Decode of resp.Body.
const maxRemoteResponseBytes = 10 << 20 // 10MB

// WarnUntrustedCWDConfigServerURL warns that a security-relevant server URL was
// sourced from a keyorix.yaml file in the current working directory — a file an
// attacker can plant to redirect this CLI command to a server they control
// (config.Load resolves a CWD-relative ./keyorix.yaml regardless of
// KEYORIX_CONFIG_PATH). #G73: every command that uses a CWD-config-sourced
// remote URL for a security-relevant action (issuing/persisting real
// credentials, an outbound connectivity probe) must carry this warning, not
// just ResolveRemote's own callers.
func WarnUntrustedCWDConfigServerURL() {
	fmt.Fprintf(os.Stderr, "⚠️  Using a remote server config from ./keyorix.yaml in the current directory. If you did not place it here, a malicious file could be redirecting the CLI — prefer KEYORIX_SERVER/KEYORIX_TOKEN or 'keyorix connect'.\n")
}

// ResolveRemote returns the server endpoint and Bearer token from all config sources.
//
// Priority: env vars > ~/.keyorix/cli.yaml (written by 'keyorix connect')
//
//	> keyorix.yaml (written by 'keyorix auth login --server')
//
// Returns ok=false when no usable remote configuration exists, meaning the
// caller should fall back to embedded (direct-DB) mode.
func ResolveRemote() (endpoint, token string, ok bool) { // NOSONAR -- cognitive complexity 25, suppress go:S3776
	token = os.Getenv("KEYORIX_TOKEN")
	endpoint = os.Getenv("KEYORIX_SERVER")

	// CLI config (~/.keyorix/cli.yaml — written by 'keyorix connect')
	if cliCfg, err := cliconfig.LoadCLIConfig(""); err == nil && cliCfg.IsClientMode() {
		if endpoint == "" && cliCfg.Client.Endpoint != "" {
			if verr := ValidateRemoteEndpointURL(cliCfg.Client.Endpoint); verr != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Ignoring remote endpoint from ~/.keyorix/cli.yaml: %v\n", verr)
			} else {
				endpoint = cliCfg.Client.Endpoint
			}
		}
		if token == "" {
			token = cliCfg.Client.Auth.GetAPIKey()
		}
	}

	// Main config (keyorix.yaml — written by 'keyorix auth login --server'). config.Load
	// resolves a CWD-relative ./keyorix.yaml, so a type:remote config planted in the
	// working directory could silently redirect the CLI to an attacker server. Warn when
	// the remote endpoint/token is sourced from it (env and ~/.keyorix/cli.yaml above are
	// the trusted sources).
	if endpoint == "" || token == "" {
		if mainCfg, err := config.Load(""); err == nil &&
			mainCfg.Storage.Type == "remote" && mainCfg.Storage.Remote != nil {
			fromMain := false
			if endpoint == "" && mainCfg.Storage.Remote.BaseURL != "" {
				if verr := ValidateRemoteEndpointURL(mainCfg.Storage.Remote.BaseURL); verr != nil {
					fmt.Fprintf(os.Stderr, "⚠️  Ignoring remote endpoint from ./keyorix.yaml: %v\n", verr)
				} else {
					endpoint = mainCfg.Storage.Remote.BaseURL
					fromMain = true
				}
			}
			if token == "" && mainCfg.Storage.Remote.GetAPIKey() != "" {
				token = mainCfg.Storage.Remote.GetAPIKey()
				fromMain = true
			}
			if fromMain {
				WarnUntrustedCWDConfigServerURL()
			}
		}
	}

	// A non-HTTPS endpoint sends the bearer token in cleartext — warn loudly (a loopback
	// target for local testing is fine).
	WarnIfInsecureEndpoint(endpoint)

	ok = endpoint != "" && token != ""
	return
}

// WarnIfInsecureEndpoint prints the same cleartext-transmission warning that
// ResolveRemote emits when a security-relevant remote endpoint is not HTTPS
// (and not a loopback target used for local testing). ResolveRemote's own
// check only fires when a *previously persisted* remote config is later read
// back — it can't protect a credential that is about to be written or sent
// for the first time. #G74: callers that persist an API key against a
// user-supplied server URL (e.g. 'auth login', 'config set-remote') or that
// transmit real credentials directly (e.g. 'system init --server' bootstrap)
// must call this before committing to that URL, not rely on ResolveRemote
// catching it afterwards. Returns true if a warning was printed.
func WarnIfInsecureEndpoint(endpoint string) bool {
	if endpoint == "" || endpointIsSecure(endpoint) {
		return false
	}
	fmt.Fprintf(os.Stderr, "⚠️  Remote endpoint %q is not HTTPS — the access token is sent in cleartext and is MITM-capturable.\n", endpoint)
	return true
}

// ValidateRemoteEndpointURL checks that a configured remote server endpoint is a
// well-formed absolute http(s) URL. Deliberately does NOT reject private/loopback
// hosts: this is a user/operator-configured endpoint pointing at their own Keyorix
// server, which is legitimately an on-prem/private-network address (mirrors this
// codebase's own connect.address exception for Vault, internal/connect/vault.go's
// validateConnectorURL) — this only rejects a malformed or non-HTTP(S) destination.
func ValidateRemoteEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid remote endpoint %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("remote endpoint %q must use http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("remote endpoint %q is missing a host", raw)
	}
	return nil
}

// endpointIsSecure reports whether the endpoint is https or a loopback target.
func endpointIsSecure(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// RemoteClient makes authenticated requests to the Keyorix HTTP API.
// Every response is unwrapped from the server's {"data": …} envelope before
// it is decoded into the caller-supplied target.
type RemoteClient struct {
	Endpoint string
	Token    string
	hc       *http.Client
}

// NewRemoteClient constructs a RemoteClient from the current configuration.
// Returns (nil, false) when no remote configuration is found so callers can
// fall back to embedded mode.
func NewRemoteClient() (*RemoteClient, bool) {
	endpoint, token, ok := ResolveRemote()
	if !ok {
		return nil, false
	}
	return newHardenedRemoteClient(endpoint, token)
}

// NewRemoteClientWithCredentials builds a RemoteClient for an explicit
// endpoint/token pair rather than the one ResolveRemote resolves from
// env/config — for the rare caller that needs to override just the token
// (e.g. 'keyorix run --token', which still wants the endpoint resolved via
// the normal ResolveRemote chain but a token supplied on the command line).
// Carries the exact same hardened http.Client (request timeout + anti-SSRF
// redirect refusal) as NewRemoteClient so callers don't have to reimplement
// it. Returns (nil, false) when endpoint fails validation.
func NewRemoteClientWithCredentials(endpoint, token string) (*RemoteClient, bool) {
	return newHardenedRemoteClient(endpoint, token)
}

// newHardenedRemoteClient builds a RemoteClient with the http.Client hardening
// every remote-mode CLI request needs, shared by NewRemoteClient and
// NewRemoteClientWithCredentials so there is exactly one place this is set up.
func newHardenedRemoteClient(endpoint, token string) (*RemoteClient, bool) {
	rc := &RemoteClient{
		Endpoint: endpoint,
		Token:    token,
		// #1521: a single total-round-trip http.Client.Timeout can't tell "the
		// server is unreachable" from "a large transfer is slowly, genuinely
		// progressing over a slow link" -- both look identical to a clock that
		// only measures elapsed time since the request started. Split into two
		// timeouts with different jobs instead (see newRemoteTransport):
		// defaultConnectTimeout fails fast when the server can't be reached at
		// all (no TCP handshake), and defaultIdleTransferTimeout only fires when
		// NO bytes have moved for that long -- a slow-but-progressing transfer
		// keeps resetting it and is never killed just for taking a while.
		//
		// CheckRedirect: without it, a 3xx response from the configured server
		// (including a CWD-planted ./keyorix.yaml — see ResolveRemote's warning
		// above) could bounce the bearer-token-bearing request to an internal
		// host (e.g. cloud IMDS) at request time (CWE-918). This client backs
		// essentially all CLI remote-mode traffic, so this one guard covers it.
		hc: &http.Client{
			Transport:     newRemoteTransport(defaultConnectTimeout, defaultIdleTransferTimeout),
			CheckRedirect: refuseRemoteClientRedirect,
		},
	}
	// rc.Endpoint is a distinct field declaration from ClientConfig.Endpoint/
	// RemoteConfig.BaseURL (already validated above in ResolveRemote) -- this direct
	// read of rc.Endpoint is what lets a static analyzer recognize the same
	// validation as covering the field Get/Post/Put/Patch/Delete below actually read.
	if err := ValidateRemoteEndpointURL(rc.Endpoint); err != nil {
		return nil, false
	}
	return rc, true
}

func refuseRemoteClientRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

// defaultConnectTimeout bounds only the TCP handshake (DNS + dial). A few
// seconds is enough for any genuinely reachable server on a real network; an
// unreachable or misconfigured KEYORIX_SERVER fails within this window
// instead of the old 30s total-round-trip budget.
const defaultConnectTimeout = 5 * time.Second

// defaultIdleTransferTimeout bounds how long a connection may go without
// producing or consuming a single byte, once connected. It is NOT a total
// elapsed-time budget: idleConn (below) resets it on every successful
// Read/Write, so a large secret import over a slow-but-working link can run
// far longer than this value in total, as long as it keeps moving. Only a
// genuine stall -- no progress at all for this long -- trips it. Matches the
// old defaultRemoteClientTimeout value so an already-fast link's behavior is
// unchanged; only the SHAPE of the timeout (idle vs. total) changes.
const defaultIdleTransferTimeout = 30 * time.Second

// newRemoteTransport builds an http.Transport whose dial phase is bounded by
// connectTimeout and whose connection (once established) is bounded by
// idleTimeout on a no-progress basis -- see defaultConnectTimeout/
// defaultIdleTransferTimeout's doc comments for why these are split rather
// than one flat http.Client.Timeout. Exposed (not inlined into
// newHardenedRemoteClient) so tests can construct a transport with short
// timeouts instead of waiting out the real 5s/30s defaults.
func newRemoteTransport(connectTimeout, idleTimeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: connectTimeout}
	return &http.Transport{
		// #1606 regression (Part 2 regression audit, 2026-09-04): the #1521
		// connect/idle timeout split replaced the implicit http.DefaultTransport
		// (via a bare &http.Client{Timeout: ...}, which silently fell back to
		// DefaultTransport and its Proxy: http.ProxyFromEnvironment) with this
		// hand-rolled Transport -- which omitted Proxy entirely, silently
		// dropping HTTP_PROXY/HTTPS_PROXY/NO_PROXY support for every one of
		// this client's 100+ CLI remote-mode call sites. In an on-prem/
		// regulated deployment that mandates all egress through an audit/DLP
		// proxy, every CLI command upgrading to this version would silently
		// stop using it -- either failing to connect (safe-but-broken) or,
		// worse, connecting directly and escaping the organization's
		// monitored egress path if a direct route happens to be reachable.
		// DialContext below is unaffected either way: when Proxy returns a
		// proxy URL, net/http's own Transport machinery dials/CONNECTs to the
		// PROXY via this DialContext and negotiates the tunnel itself -- the
		// idle-timeout wrapping here is orthogonal to proxying.
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &idleConn{Conn: conn, idle: idleTimeout}, nil
		},
	}
}

// idleConn wraps a net.Conn so a read/write deadline resets on every
// successful Read or Write, rather than the connection having a single fixed
// deadline for its whole lifetime. This is what turns idleTimeout into a
// no-progress timeout instead of a total-transfer-time timeout: TLS
// handshake bytes, request-body upload bytes, and response-body download
// bytes each push the deadline back out, so only a genuine stop in traffic
// -- not merely a long transfer -- ever times out.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// classifyTransportError turns a low-level dial/read/write network error
// into a message that tells the caller WHICH kind of failure this was,
// instead of the same generic wording for every case:
//   - dial phase failed (connection refused, no route, DNS failure, or the
//     connectTimeout itself expired): the server was never reachable at all.
//   - a read or write on an established connection hit idleTimeout: the
//     server WAS reachable and the transfer WAS progressing, then stopped.
//
// Any other error (HTTP-level, context cancellation, JSON decode) passes
// through wrapped in the caller-supplied fallback wording unchanged -- this
// only special-cases the two network-shaped failures the connect/idle split
// above can actually distinguish.
func (c *RemoteClient) classifyTransportError(err error, fallback string) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch opErr.Op {
		case "dial":
			return fmt.Errorf("could not reach server at %s: %w", c.Endpoint, err)
		case "read", "write":
			if ne, ok := opErr.Err.(net.Error); ok && ne.Timeout() {
				return fmt.Errorf("transfer stalled after %s with no data sent or received (server: %s): %w",
					defaultIdleTransferTimeout, c.Endpoint, err)
			}
		}
	}
	return fmt.Errorf("%s: %w", fallback, err)
}

// Ping verifies the configured remote server is actually reachable, via the
// unauthenticated /health endpoint (unlike every other call on this client,
// /health returns a bare JSON object with no {"data":…} envelope, so this
// does not go through decodeEnvelope). Some commands' only real API call is
// conditional on the input actually needing one (e.g. `secret render`
// against a template with zero ${secret:...} references never calls
// keyorixResolver at all) — for those, "no error occurred" does not mean
// "the configured remote was reached." Call Ping unconditionally before
// treating such a command as successful, so an unreachable/misconfigured
// KEYORIX_SERVER is caught even on an input that happens not to exercise
// the resolver.
func (c *RemoteClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+"/health", nil)
	if err != nil {
		return fmt.Errorf("build health-check request: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "server health check failed")
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for health check", resp.StatusCode)
	}
	return nil
}

// Get performs a GET to path, strips the {"data":…} envelope, and decodes into out.
func (c *RemoteClient) Get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return decodeEnvelope(resp, out, path)
}

// GetRaw performs a GET and returns the raw, un-enveloped response body. Used for
// endpoints that serve a non-JSON artifact directly (e.g. the text/csv compliance and
// inventory exports), where the dashboard downloads the same bytes.
func (c *RemoteClient) GetRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set("Accept", "text/csv, */*")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, c.classifyTransportError(err, fmt.Sprintf("read response from %s", path))
	}
	return body, nil
}

// Post serialises body as JSON, POSTs to path, strips the envelope, and decodes
// into out (out may be nil, matching Put/Patch, when the caller doesn't need the
// response body).
func (c *RemoteClient) Post(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		return decodeEnvelope(resp, out, path)
	}
	return nil
}

// decodeEnvelope strips {"data":…} and unmarshals the inner payload into out.
func decodeEnvelope(resp *http.Response, out interface{}, path string) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRemoteResponseBytes)).Decode(&env); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	if env.Data == nil {
		return fmt.Errorf("empty data in response from %s", path)
	}
	return json.Unmarshal(env.Data, out)
}

// Put serialises body as JSON, PUTs to path, strips the envelope, and decodes into out.
func (c *RemoteClient) Put(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		return decodeEnvelope(resp, out, path)
	}
	return nil
}

// Patch sends a PATCH to path with a JSON body and decodes the response envelope
// into out (out may be nil).
func (c *RemoteClient) Patch(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)
	req.Header.Set("Accept", mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		return decodeEnvelope(resp, out, path)
	}
	return nil
}

// DeleteWithBody sends a DELETE to path carrying a JSON body (some endpoints —
// e.g. DELETE /user-roles — identify the target in the body rather than the URL).
// No response body is expected.
func (c *RemoteClient) DeleteWithBody(ctx context.Context, path string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)
	req.Header.Set(hdrContentType, mimeJSON)

	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return nil
}

// Delete sends a DELETE to path. No response body is expected.
func (c *RemoteClient) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Endpoint+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+c.Token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return c.classifyTransportError(err, "request failed")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, path)
	}
	return nil
}
