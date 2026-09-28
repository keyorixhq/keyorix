//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"testing"
)

// client is an authenticated HTTP client against one running server instance.
// Every call is routed through do(), which (a) fails the test immediately on
// any 5xx response -- SESSION-I's core assertion, "no 5xx anywhere" -- and
// (b) records which routes.json route key it exercised, feeding
// assertRouteCoverage's final completeness check.
//
// Auth: POST /auth/login returns {"data":{"token": "..."}} AND sets the
// kx_session/csrf_token cookies (server/http/handlers/auth.go's Login). This
// client deliberately uses ONLY the bearer token, on a cookie jar-free
// http.Client, never the cookies -- server/middleware/csrf.go's RequireCSRF
// only checks the X-CSRF-Token header when the SESSION COOKIE is present on
// the request ("a pure-Bearer caller ... is immune to CSRF by construction");
// carrying no cookie at all sidesteps CSRF entirely, exactly like a
// PAT/machine-token/CI caller. Simpler than double-submitting a CSRF header
// and correct for what this driver is: an API client, not a browser.
type client struct {
	t       *testing.T
	baseURL string
	token   string
	http    *http.Client

	mu  sync.Mutex
	hit map[string]bool // route-inventory key ("METHOD /pattern") -> exercised
}

func newClient(t *testing.T, baseURL string) *client {
	return &client{
		t:       t,
		baseURL: baseURL,
		http:    &http.Client{},
		hit:     map[string]bool{},
	}
}

// login authenticates and stores the bearer token for subsequent calls.
// routeKey is "POST /auth/login" for coverage purposes.
func (c *client) login(username, password string) {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp := c.doRaw(http.MethodPost, "POST /auth/login", "/auth/login", body, "")
	defer resp.Body.Close() //nolint:errcheck
	var env struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		c.t.Fatalf("login: decode response: %v", err)
	}
	if !env.Success || env.Data.Token == "" {
		c.t.Fatalf("login: no token in response (success=%v)", env.Success)
	}
	c.token = env.Data.Token
}

// call issues an authenticated request. routeKey is the exact "METHOD
// /pattern" string from scripts/e2e/routes.json (e.g. "GET /api/v1/secrets/{id}"),
// used purely for coverage bookkeeping -- path is the REAL request path with
// path params substituted in (e.g. "/api/v1/secrets/42"). Returns the parsed
// envelope; callers that need the raw data payload should type-assert
// env.Data or re-marshal it into a concrete struct.
func (c *client) call(method, routeKey, path string, body interface{}) envelope {
	c.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			c.t.Fatalf("%s %s: marshal request body: %v", method, path, err)
		}
	}
	resp := c.doRaw(method, routeKey, path, raw, c.token)
	defer resp.Body.Close() //nolint:errcheck

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s (%s): read response body: %v", method, routeKey, path, err)
	}

	if resp.StatusCode >= 500 {
		c.t.Fatalf("%s %s (%s): server returned %d (5xx) -- no 5xx is allowed anywhere in this smoke run:\n%s",
			method, routeKey, path, resp.StatusCode, string(respBytes))
	}

	var env envelope
	env.StatusCode = resp.StatusCode
	if len(respBytes) > 0 {
		if jerr := json.Unmarshal(respBytes, &env); jerr != nil {
			// Not every route returns the {"success","data"} envelope (e.g.
			// /openapi.yaml, /metrics) -- callers of those don't use env.Data,
			// so a non-JSON body here isn't necessarily an error; still
			// stash the raw bytes so a caller that DOES expect JSON gets a
			// useful failure message instead of a zero-value envelope.
			env.Raw = respBytes
		}
	}
	return env
}

// callExpect wraps call and REPORTS (t.Errorf, not t.Fatalf) if the
// response's HTTP status isn't one of want -- for asserting an expected
// 200/201 (or, where the smoke intentionally checks a denial, 403/404)
// rather than merely "not 5xx". Deliberately non-fatal: a single wrong
// status code in one group (this driver covers ~300 routes; getting every
// exact status right on the first pass is unrealistic) would otherwise stop
// the whole run before later groups get a chance to run at all, hiding
// unrelated real failures behind it. call() above still hard-fails (t.Fatalf)
// on any 5xx or transport error -- THAT is the invariant this driver
// actually exists to enforce; a wrong-but-non-5xx status is downgraded to a
// reported mismatch so the run keeps going and surfaces everything at once.
func (c *client) callExpect(method, routeKey, path string, body interface{}, want ...int) envelope {
	c.t.Helper()
	env := c.call(method, routeKey, path, body)
	for _, w := range want {
		if env.StatusCode == w {
			return env
		}
	}
	c.t.Errorf("%s %s (%s): expected status in %v, got %d: %s",
		method, routeKey, path, want, env.StatusCode, string(env.Raw))
	return env
}

// doRaw performs the actual HTTP round trip and records routeKey as hit
// regardless of outcome (a route that was called and returned an error is
// still "exercised" for coverage purposes -- coverage tracks reachability
// through the driver, not success).
func (c *client) doRaw(method, routeKey, path string, body []byte, token string) *http.Response {
	c.t.Helper()
	c.mu.Lock()
	c.hit[routeKey] = true
	c.mu.Unlock()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		c.t.Fatalf("%s %s: build request: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s (%s): request failed: %v", method, routeKey, path, err)
	}
	return resp
}

// skip explicitly records a route as covered by a reviewed skip, without
// making any HTTP call -- for the small set of routes this smoke driver
// cannot reach mechanically (see skipList in coverage.go for every entry and
// its justification).
func (c *client) skip(routeKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hit[routeKey] = true
}

func (c *client) hitKeys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.hit))
	for k := range c.hit {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// envelope mirrors server/http/handlers/helpers.go's sendSuccess/sendError
// JSON shape: {"success":bool,"data":...,"message":...} or
// {"success":false,"error":{"type","message",...}}.
type envelope struct {
	StatusCode int             `json:"-"`
	Success    bool            `json:"success"`
	Data       json.RawMessage `json:"data"`
	Message    string          `json:"message"`
	Raw        []byte          `json:"-"`
}

// unmarshalData decodes env.Data into v, failing the test with a readable
// message on error (rather than a bare json.Unmarshal error with no context
// about which call produced it).
func (c *client) unmarshalData(env envelope, v interface{}, context string) {
	c.t.Helper()
	if len(env.Data) == 0 {
		c.t.Fatalf("%s: response has no data payload (success=%v, message=%q)", context, env.Success, env.Message)
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		c.t.Fatalf("%s: decode data payload: %v\nraw: %s", context, err, string(env.Data))
	}
}

var _ = fmt.Sprintf // keep fmt imported for future Sprintf-based messages
