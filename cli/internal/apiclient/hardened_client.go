// hardened_client.go -- hand-written, not part of client.gen.go ("DO NOT EDIT"). Builds
// the http.Client every cli/cmd command should construct its apiclient.Client with.
//
// The generated client's own default (client.gen.go's NewClient: `client.Client =
// &http.Client{}` when no WithHTTPClient option is supplied) has none of the hardening
// the OLD CLI's remote-mode client carried (internal/cli/common/remote_client.go,
// newHardenedRemoteClient, issues #1521/#1606): no request timeout (a stalled connection
// to a slow, hung, or malicious server blocks the CLI forever), no response size cap
// (every generated …WithResponse method reads the full body via io.ReadAll with no
// limit, so an oversized response can exhaust client memory), and no redirect policy
// (the zero-value http.Client follows up to 10 redirects automatically, including to a
// different host than the one the operator configured -- CWE-918/SSRF-adjacent, since
// this request carries a bearer token).
//
// This closes all three for every command built through cli/cmd's newAPIClient, without
// touching the generated file.
package apiclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxResponseBodyBytes bounds how much of a single HTTP response this client reads into
// memory, matching the old CLI's internal/cli/common.maxRemoteResponseBytes cap: large
// enough for any real Keyorix API response (including a full secret export), small
// enough that a malicious or misbehaving server can't exhaust client memory.
const maxResponseBodyBytes = 10 << 20 // 10MB

// requestTimeout bounds a single HTTP round trip end-to-end (connect + TLS + the full
// response body). The old CLI split connect and idle-transfer timeouts (#1521) so a
// large, slowly-but-genuinely-progressing transfer wouldn't be killed early; this client
// keeps one simpler total timeout instead -- 60s comfortably covers a `secret export` /
// `run` fetch of several thousand secrets over a normal link, while still failing an
// unreachable or hung server well within an operator's patience. If a real large-
// transfer/slow-link false positive shows up in practice, port the connect/idle split.
const requestTimeout = 60 * time.Second

// ErrResponseTooLarge is returned (wrapped) from a response body Read once more than
// maxResponseBodyBytes has been read, so a caller sees a clear cause instead of a
// truncated-JSON parse error.
var ErrResponseTooLarge = errors.New("keyorix: response body exceeds the maximum allowed size")

// NewHardenedHTTPClient returns the *http.Client every apiclient.Client in this CLI
// should be built with, via WithHTTPClient -- not the generated NewClient's bare
// &http.Client{} default.
func NewHardenedHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       requestTimeout,
		Transport:     &cappingTransport{base: http.DefaultTransport},
		CheckRedirect: refuseRedirect,
	}
}

// refuseRedirect matches the old CLI's internal/cli/common.refuseRemoteClientRedirect: a
// 3xx response from the configured server could otherwise bounce this bearer-token-
// bearing request to a different, attacker-influenced host (CWE-918). The operator's
// configured --server/KEYORIX_SERVER/stored server_url is the only host this client
// should ever talk to.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

// cappingTransport wraps a RoundTripper so every response body is capped at
// maxResponseBodyBytes: reading past the cap returns ErrResponseTooLarge instead of
// silently continuing to grow the in-memory read every generated …WithResponse method
// performs via io.ReadAll(rsp.Body).
type cappingTransport struct {
	base http.RoundTripper
}

func (t *cappingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	resp.Body = &cappedReadCloser{r: resp.Body, remaining: maxResponseBodyBytes}
	return resp, nil
}

// cappedReadCloser errors out as soon as more than `remaining` bytes have been read from
// the wrapped body, rather than silently truncating (io.LimitReader alone would truncate
// silently, turning an oversized response into a confusing "unexpected end of JSON
// input" instead of a clear cause).
type cappedReadCloser struct {
	r         io.ReadCloser
	remaining int64
	tripped   bool
}

func (c *cappedReadCloser) Read(p []byte) (int, error) {
	if c.tripped {
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > c.remaining+1 {
		p = p[:c.remaining+1]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if c.remaining < 0 {
		c.tripped = true
		return n, ErrResponseTooLarge
	}
	return n, err
}

func (c *cappedReadCloser) Close() error {
	return c.r.Close()
}
