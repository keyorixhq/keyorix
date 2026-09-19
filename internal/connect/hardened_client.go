// hardened_client.go — the shared outbound-hardening pieces every Connect
// backend's HTTP client uses: refuse-all-redirects, a post-decompression
// response-size cap, and a link-local-refusing dialer/target check. See
// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md §2/§3/§5 for
// the investigation and design reasoning behind each piece.
package connect

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// connectMaxResponseBytes is the shared post-decompression response-size cap for
// every Connect backend's outbound HTTP client. Reuses vaultMaxResponseBytes (1
// MiB) as the standard rather than inventing a second number — Vault's own
// existing io.LimitReader already proved this bound sound (§3's gzip-bomb
// measurement: ~0.9 MiB peak heap / 7ms elapsed against a 1 GiB decompression
// bomb, vs. ~4 GiB / ~6s for AWS/Azure with no cap at all). Larger than any of
// the three backends' own documented maximum secret-value size (AWS Secrets
// Manager 64 KiB, Azure Key Vault 25 KiB, GCP Secret Manager 64 KiB) — the cap
// exists to bound a HOSTILE response's amplification, not to model a real
// secret's size, so it's set well above any legitimate value rather than tight
// against one (see the findings doc §5 for the full table and reasoning).
const connectMaxResponseBytes = vaultMaxResponseBytes

// refuseRedirect is the shared CheckRedirect policy for every Connect backend's
// outbound HTTP client: none of these backends' real single-secret-read APIs
// (Vault KV GET, Key Vault GetSecret, GetSecretValue) has any legitimate reason
// to redirect, so refuse outright — matching Vault's own pre-existing policy —
// rather than attempt to classify a same-host/non-private redirect target.
func refuseRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// connectDialTimeout/connectDialKeepAlive match the 30s/30s convention all
// three backends' own pre-fix defaults independently used (Go's own
// http.DefaultTransport, azure-sdk-for-go's defaultHTTPClient, and
// aws-sdk-go-v2's awshttp.NewBuildableClient() all set exactly these values) —
// preserved explicitly here because netutil.Dialer's own zero-value Dial
// (a bare (&net.Dialer{}).DialContext) has NEITHER a connect timeout nor a
// keep-alive, and connectGuardedDialer must replace each backend's own
// DialContext entirely (to inject the link-local check), so leaving Dial unset
// would silently drop this timeout — an unbounded dial attempt is a real
// availability regression, not just a cosmetic parity gap.
const (
	connectDialTimeout   = 30 * time.Second
	connectDialKeepAlive = 30 * time.Second
)

// connectGuardedDialer builds the shared link-local-refusing dialer: no
// legitimate Connect backend deployment (Vault, Azure Key Vault, AWS Secrets
// Manager, GCP Secret Manager) lives at a link-local address, including cloud
// instance-metadata (169.254.169.254, shared by AWS/GCP/Azure) — unlike a full
// private-range block, this costs the on-prem deployment baseline nothing,
// since RFC-1918/on-prem addresses remain a first-class legitimate target for
// Vault/Azure (validateConnectorAddressNotLinkLocal's own doc comment). Applied
// on EVERY dial (not validated once at registration) so a hostname-configured
// address that later resolves to a link-local target — a DNS-rebinding attacker,
// or a legitimate hostname whose DNS answer simply changes — is refused too, not
// just a literal link-local IP typed directly into config.
//
// This guard is BLIND to the request's actual target when a proxy is
// configured: with Transport.Proxy set, DialContext dials the PROXY's address,
// never the origin target, so this check alone would validate the proxy, not
// what's being requested through it. targetGuardRoundTripper (below) is what
// closes that gap — the two are complementary, not redundant: this one closes
// DNS-rebinding for the direct-dial (no-proxy) case, that one closes the
// literal-IP-target-via-proxy case.
func connectGuardedDialer() netutil.Dialer {
	return netutil.Dialer{
		Disallow: netutil.IsLinkLocal,
		Dial:     (&net.Dialer{Timeout: connectDialTimeout, KeepAlive: connectDialKeepAlive}).DialContext,
	}
}

// targetGuardRoundTripper rejects a request whose own target host (req.URL,
// not the dial address) is a literal link-local IP — independent of whether a
// proxy is configured. This matters because when Transport.Proxy is set (all
// three backend base transports set it, matching their own pre-fix defaults —
// see vaultBaseTransport/azureBaseTransport/awsBaseTransport), DialContext
// dials the PROXY's address for a plain-HTTP request, or the proxy first for
// an HTTPS CONNECT tunnel — connectGuardedDialer's per-dial check would only
// ever see and validate the PROXY's address in either case, never the origin
// target carried in the request itself. This check runs on the request BEFORE
// the proxy/dial layer gets it, so it applies regardless of proxy
// configuration.
//
// Scope, stated explicitly (per this codebase's own "state what a mechanism
// doesn't do" discipline): this can only catch a LITERAL link-local IP as the
// request target. A HOSTNAME that resolves to link-local only at the PROXY's
// own DNS resolution is NOT caught here — the client never sees or controls
// that resolution when a proxy is in use; connectGuardedDialer's per-dial
// resolve-and-validate closes the equivalent gap only in the no-proxy case.
// Closing the with-proxy hostname case would require either resolving the
// hostname client-side first (defeating the point of using a proxy) or
// trusting the proxy's own egress policy (out of scope for Keyorix, which
// does not control the proxy).
type targetGuardRoundTripper struct {
	Transport http.RoundTripper
}

func (rt targetGuardRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(req.URL.Hostname()); ip != nil && netutil.IsLinkLocal(ip) {
		return nil, fmt.Errorf("netutil: refusing request to disallowed address %s", ip)
	}
	return rt.Transport.RoundTrip(req)
}

// responseTooLargeError is returned (via cappedBodyReader) when a response
// body would exceed connectMaxResponseBytes after decompression —
// MaxBytesReader-style: net/http.MaxBytesReader (server-side request bodies)
// uses the exact same read-n+1 algorithm cappedBodyReader implements; net/http
// has no exported client-side response-body equivalent, so this is a
// purpose-built adaptation of that same, well-tested pattern. Distinguishable
// via errors.Is from an ordinary truncated-body decode failure (a generic
// "unexpected end of JSON input"-shaped error), so a caller or test can tell
// "the cap fired" from "some unrelated decode error happened to occur near
// the same boundary".
//
// Implements two SDK-recognized "don't retry me" marker interfaces,
// structurally (no import of either SDK's internal retry-classification
// package needed or possible — both are genuinely internal). Without this,
// BOTH SDKs' retry classifiers treat an unrecognized I/O error surfacing
// during body-read as potentially transient and retry the whole request —
// confirmed empirically: Azure's azcore client, under its own DEFAULT retry
// policy (azurekv.go sets no override), added ~8s of real exponential-backoff
// delay retrying a cap failure against the exact same, still-oversized
// response 3 extra times, before this fix.
//   - Azure (azcore): matched via errors.As against
//     sdk/internal/errorinfo.NonRetriable, an exported interface requiring
//     only Error() string + NonRetriable() — satisfiable without importing
//     that internal package at all, since Go interface satisfaction is
//     structural.
//   - AWS (aws-sdk-go-v2): matched via errors.As against
//     aws/retry.RetryableError, an exported interface requiring
//     RetryableError() bool — returning false is what explicitly marks this
//     non-retryable; a type that doesn't implement it at all falls through to
//     OTHER retryability heuristics instead (e.g. RetryableConnectionError's
//     structural net.OpError/url.Error checks), which is what let this slip
//     through un-classified in the first place.
type responseTooLargeError struct{}

func (responseTooLargeError) Error() string {
	return "connect: response body exceeds the configured size cap"
}
func (responseTooLargeError) NonRetriable()        {}
func (responseTooLargeError) RetryableError() bool { return false }

var errResponseTooLarge error = responseTooLargeError{}

// cappedBodyReader mirrors net/http.MaxBytesReader's own algorithm: each Read
// asks the underlying reader for at most ONE MORE byte than the remaining
// budget, so a single Read call can distinguish "the stream ended exactly at
// the cap" (no error) from "the stream had more data past the cap"
// (errResponseTooLarge) without a separate probe read across calls or an
// off-by-one on the exact-size boundary.
type cappedBodyReader struct {
	r         io.Reader
	remaining int64
	err       error
}

func (c *cappedBodyReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > c.remaining+1 {
		p = p[:c.remaining+1]
	}
	n, err := c.r.Read(p)
	if int64(n) <= c.remaining {
		c.remaining -= int64(n)
		c.err = err
		return n, err
	}
	n = int(c.remaining)
	c.remaining = 0
	c.err = errResponseTooLarge
	return n, c.err
}

// sizeCappedRoundTripper wraps an underlying http.RoundTripper's response body
// in a cappedBodyReader AFTER any transparent Content-Encoding decompression
// the underlying transport already performed. Capping the raw WIRE bytes would
// not bound a gzip-bomb's decompressed size — net/http's own gzip unwrapping
// happens inside the underlying RoundTrip call, before this wrapper ever sees
// the response — so the cap has to sit on resp.Body itself, downstream of that
// unwrapping, exactly where Vault's own io.LimitReader(resp.Body, ...) already
// sits (vault.go's GetSecret), just relocated to the transport layer since
// AWS/Azure's own SDKs read the response body internally with no
// connector-level interception point to add a cap at.
type sizeCappedRoundTripper struct {
	Transport http.RoundTripper
	MaxBytes  int64
}

// limitedReadCloser preserves the real resp.Body.Close (releasing the underlying
// connection back to net/http's pool) while limiting Read to the underlying
// cappedBodyReader — io.NopCloser would silently drop the real Close, which
// net/http needs to safely reuse or discard the connection.
type limitedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (l limitedReadCloser) Close() error { return l.closer.Close() }

func (rt sizeCappedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.Transport.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = limitedReadCloser{Reader: &cappedBodyReader{r: resp.Body, remaining: rt.MaxBytes}, closer: resp.Body}
	return resp, nil
}

// vaultBaseTransport returns Vault's own pre-fix starting point: plain Go
// stdlib defaults. vault.go never had any SDK layer or custom transport
// tuning — it's implemented directly over net/http (see its own header
// comment) — so http.DefaultTransport really is the correct, unmodified
// baseline to preserve here, not a simplification.
func vaultBaseTransport() *http.Transport {
	return http.DefaultTransport.(*http.Transport).Clone()
}

// azureBaseTransport hand-replicates azure-sdk-for-go's own unexported default
// transport (sdk/azcore@v1.23.1/runtime/transport_default_http_client.go,
// pinned version per go.mod at the time this was written) — azcore exports no
// accessor for it (unlike AWS's awshttp.NewBuildableClient().GetTransport(),
// see awsBaseTransport below), so this can't be machine-derived the same way
// and needs re-verifying by hand against that file whenever azcore is bumped.
// Omitted deliberately: azcore's own extra HTTP/2 ReadIdleTimeout(10s)/
// PingTimeout(5s) tuning (via http2.ConfigureTransports) — a connection-health
// nicety, not a correctness or security property, and replicating it would
// mean vendoring golang.org/x/net/http2 directly for a minor gap; Go's own
// ForceAttemptHTTP2 already configures a working (if less tightly tuned) HTTP/2
// transport automatically.
func azureBaseTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: tls.RenegotiateFreelyAsClient,
		},
	}
}

// awsBaseTransport returns a REAL clone of aws-sdk-go-v2's own default
// transport, via the SDK's own exported constructor
// (awshttp.NewBuildableClient().GetTransport(), which returns
// defaultHTTPTransport() when no transport has been set) — not a hand-copied
// literal, so it tracks the SDK's actual defaults automatically across version
// bumps, including its FIPS-140-mode TLS curve-preference restriction
// (DefaultHTTPTransportTLSCurvePreferencesFIPS) that a hand-copy would risk
// silently drifting out of sync with.
func awsBaseTransport() *http.Transport {
	return awshttp.NewBuildableClient().GetTransport()
}

// newConnectHardenedTransport wraps base (a backend-specific starting point —
// see vaultBaseTransport/azureBaseTransport/awsBaseTransport — never Go's
// generic default substituted in place of a backend's own tuned one) with
// connectGuardedDialer's link-local-refusing DialContext, sizeCappedRoundTripper's
// post-decompression size cap, and targetGuardRoundTripper's proxy-blind-spot
// target check. Redirect refusal is NOT part of this — it's an
// http.Client.CheckRedirect field, wired separately by each backend's own
// client construction (see refuseRedirect) since CheckRedirect lives on
// http.Client, not http.RoundTripper.
func newConnectHardenedTransport(base *http.Transport) http.RoundTripper {
	base = base.Clone()
	d := connectGuardedDialer()
	base.DialContext = d.DialContext
	return targetGuardRoundTripper{Transport: sizeCappedRoundTripper{Transport: base, MaxBytes: connectMaxResponseBytes}}
}

// validateConnectorAddressNotLinkLocal rejects a connector's configured address
// when it is a literal IP netutil.IsLinkLocal flags (link-local, including cloud
// instance-metadata at 169.254.169.254) — no legitimate Vault or Azure Key Vault
// deployment lives at a link-local address, unlike general private/on-prem space
// (RFC-1918), which stays intentionally unguarded (validateConnectorURL's own
// doc comment: "Vault connectors are admin-configured and commonly point at
// on-prem/private-network instances by design").
//
// A HOSTNAME (not a literal IP) is deliberately NOT resolved here: doing so would
// only check the answer at THIS moment, not at actual dial time, reintroducing
// the DNS-rebinding gap netutil.Dialer's own package doc (G48) exists to close.
// This is a fast, fail-loud check for the literal-IP case only — the per-dial
// netutil.Dialer wired into connectGuardedDialer is the enforcement that matters
// for a hostname, since it resolves and validates on every connection, not once.
func validateConnectorAddressNotLinkLocal(backend, address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return nil // a malformed address is some other validator's job, not this one's
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		return nil // a hostname, not a literal IP -- see doc comment above
	}
	if netutil.IsLinkLocal(ip) {
		return fmt.Errorf("%s: connector address %q is a link-local address (%s); no legitimate backend lives there", backend, address, ip)
	}
	return nil
}
