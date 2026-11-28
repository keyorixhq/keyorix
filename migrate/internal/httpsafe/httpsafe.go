// Package httpsafe holds the small set of HTTP hardening primitives every cloud-source client
// in this module needs: a redirect refusal and a response-size cap, plus, for the Azure SDK
// path only, an error-body scrub. This is a deliberate,
// migrate-owned COPY of the same safeguards internal/connect/hardened_client.go already applies
// to the server's own AWS/Azure connectors — migrate cannot import internal/connect (module
// boundary, docs/design-keyorix-migrate.md's "Module boundaries" section), so the logic is
// ported, not shared, matching vaultsource's own precedent of carrying these two safeguards
// forward unchanged rather than weakening them for this tool.
package httpsafe

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ClientTimeout bounds every request a cloud-source client makes, matching vaultsource's
// clientTimeout precedent.
const ClientTimeout = 30 * time.Second

// MaxResponseBytes caps how much of a single HTTP response body a cloud-source client reads
// into memory, matching vaultsource's maxResponseBytes precedent — generous enough for a large
// secret value, still bounded against a malicious or misbehaving endpoint.
const MaxResponseBytes = 10 << 20 // 10MB

// RefuseRedirect matches vaultsource's CheckRedirect: a credential-bearing request must never
// follow a redirect to a host the operator did not configure.
func RefuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// CappedTransport wraps Base, limiting every response body read to MaxResponseBytes — a
// malicious or compromised cloud endpoint must not be able to force this process to buffer an
// unbounded body before the SDK on top of it ever gets a chance to reject it.
type CappedTransport struct {
	Base http.RoundTripper
}

func (t CappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	resp.Body = &cappedReadCloser{r: io.LimitReader(resp.Body, MaxResponseBytes), c: resp.Body}
	return resp, nil
}

// cappedReadCloser pairs a size-limited Reader with the original response body's Close, so the
// underlying connection is still released normally.
type cappedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *cappedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *cappedReadCloser) Close() error               { return l.c.Close() }

// Client builds an *http.Client with the redirect refusal and response cap applied — the
// standard shape every cloud-source package's client() constructor uses.
func Client() *http.Client {
	return &http.Client{
		Timeout:       ClientTimeout,
		Transport:     CappedTransport{Base: http.DefaultTransport},
		CheckRedirect: RefuseRedirect,
	}
}

// AzureClient is Client plus ErrorBodyScrubTransport, for the Azure SDK path. It is not used
// for AWS: the AWS SDK reads its error codes from the error body, which the scrub replaces.
func AzureClient() *http.Client {
	return NewAzureClient(http.DefaultTransport)
}

// NewAzureClient is AzureClient over the given base transport (tests pass one that trusts
// their TLS server), so tests exercise the same wrapper stack production uses.
func NewAzureClient(base http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:       ClientTimeout,
		Transport:     ErrorBodyScrubTransport{Base: CappedTransport{Base: base}},
		CheckRedirect: RefuseRedirect,
	}
}

// ErrorBodyScrubTransport replaces the body of every response whose status is not 200 OK
// with a short, fixed JSON body before the SDK sees it — a migrate-owned copy of
// internal/connect's errorBodyScrubRoundTripper (#4061). azcore's ResponseError.Error()
// prints the whole response body, so without this a vault, proxy or impersonating endpoint
// answering GetSecret with any non-200 status (a 403/5xx echoing the secret, or a 203/206
// from a proxy carrying the real body) would put the secret value into the error
// keyorix-migrate prints. azsecrets.GetSecret only accepts 200, so a 2xx other than 200 is
// an error too and is scrubbed the same way. azcore also parses an unexpected-status body
// as nested JSON, which a small deeply nested body can amplify far past MaxResponseBytes;
// the fixed body bounds that work. The status code and headers are kept, so the SDK's retry
// and auth-challenge decisions are unchanged. The original body is read for at most
// errorBodyDrainBytes and never surfaced.
type ErrorBodyScrubTransport struct {
	Base http.RoundTripper
}

// errorBodyDrainBytes bounds how much of an error response's original body is consumed
// before it is discarded.
const errorBodyDrainBytes = 4 << 10

// scrubbedErrorBody returns what the SDK sees in place of an error response body: a fixed
// message and, when the original body carries a plain top-level error.code made only of
// [A-Za-z0-9_.-] (at most 64 bytes), that code (e.g. "SecretNotFound"). Nothing else from
// the original body is passed on.
func scrubbedErrorBody(original []byte) string {
	code := "UpstreamError"
	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(original, &parsed) == nil && validErrorCode(parsed.Error.Code) {
		code = parsed.Error.Code
	}
	return `{"error":{"code":"` + code + `","message":"upstream error response body suppressed"}}`
}

func validErrorCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func (t ErrorBodyScrubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode == http.StatusOK {
		return resp, err
	}
	var original []byte
	if resp.Body != nil {
		original, _ = io.ReadAll(io.LimitReader(resp.Body, errorBodyDrainBytes))
		_ = resp.Body.Close()
	}
	body := scrubbedErrorBody(original)
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Uncompressed = true
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Range")
	resp.Header.Del("Content-Md5")
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
}
