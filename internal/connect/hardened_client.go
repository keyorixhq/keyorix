// hardened_client.go — the shared outbound-hardening pieces every Connect
// backend's HTTP client uses: refuse-all-redirects, a post-decompression
// response-size cap, and a link-local-refusing dialer. See
// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md §2/§3/§5 for
// the investigation and design reasoning behind each piece; this file is the
// implementation of that draft.
package connect

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// connectMaxResponseBytes is the shared post-decompression response-size cap for
// every Connect backend's outbound HTTP client. Reuses vaultMaxResponseBytes (1
// MiB) as the standard rather than inventing a second number — Vault's own
// existing io.LimitReader already proved this bound sound (§3's gzip-bomb
// measurement: ~0.9 MiB peak heap / 7ms elapsed against a 1 GiB decompression
// bomb, vs. ~4 GiB / ~6s for AWS/Azure with no cap at all).
const connectMaxResponseBytes = vaultMaxResponseBytes

// refuseRedirect is the shared CheckRedirect policy for every Connect backend's
// outbound HTTP client: none of these backends' real single-secret-read APIs
// (Vault KV GET, Key Vault GetSecret, GetSecretValue) has any legitimate reason
// to redirect, so refuse outright — matching Vault's own pre-existing policy —
// rather than attempt to classify a same-host/non-private redirect target.
func refuseRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

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
func connectGuardedDialer() netutil.Dialer {
	return netutil.Dialer{Disallow: netutil.IsLinkLocal}
}

// sizeCappedRoundTripper wraps an underlying http.RoundTripper's response body in
// an io.LimitReader AFTER any transparent Content-Encoding decompression the
// underlying transport already performed. Capping the raw WIRE bytes would not
// bound a gzip-bomb's decompressed size — net/http's own gzip unwrapping happens
// inside the underlying RoundTrip call, before this wrapper ever sees the
// response — so the cap has to sit on resp.Body itself, downstream of that
// unwrapping, exactly where Vault's own io.LimitReader(resp.Body, ...) already
// sits (vault.go's GetSecret), just relocated to the transport layer since
// AWS/Azure's own SDKs read the response body internally with no connector-level
// interception point to add a cap at.
type sizeCappedRoundTripper struct {
	Transport http.RoundTripper
	MaxBytes  int64
}

// limitedReadCloser preserves the real resp.Body.Close (releasing the underlying
// connection back to net/http's pool) while limiting Read to the underlying
// LimitReader — io.NopCloser would silently drop the real Close, which net/http
// needs to safely reuse or discard the connection.
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
	resp.Body = limitedReadCloser{Reader: io.LimitReader(resp.Body, rt.MaxBytes), closer: resp.Body}
	return resp, nil
}

// newConnectHardenedTransport builds the shared http.RoundTripper every Connect
// backend's outbound client uses: connectGuardedDialer's link-local-refusing
// DialContext, wrapped in sizeCappedRoundTripper's post-decompression size cap.
// Redirect refusal is NOT part of the transport — it's an http.Client.CheckRedirect
// field, wired separately by each backend's own client construction (see
// refuseRedirect) since CheckRedirect lives on http.Client, not http.RoundTripper.
func newConnectHardenedTransport() http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	d := connectGuardedDialer()
	base.DialContext = d.DialContext
	return sizeCappedRoundTripper{Transport: base, MaxBytes: connectMaxResponseBytes}
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
