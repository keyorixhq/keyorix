package notifychan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// #3427: the SSRF guards of the webhook and chat sinks, driven as tables over
// BOTH constructors so neither client can drift from the other.
//
//   - redirects: a Location that is a private/loopback/link-local literal, a
//     hostname resolving to a private/loopback address, or an https->http
//     downgrade is refused, and the redirect target receives nothing;
//   - endpoint forms: IPv4-mapped / NAT64 / IPv4-compatible IPv6, the
//     unspecified address, and the decimal/octal/hex spellings of an IPv4
//     address, which net.ParseIP does not recognise and which therefore reach
//     the hostname (resolve-and-check) branch.
//
// Loopback is deliberately PERMITTED by this package (a local receiver is a
// supported dev target; see isDisallowedIP), so the "[::1]" rows pin that.

// setLookup swaps lookupIPAddr for the test and restores it on cleanup.
func setLookup(t *testing.T, fn func(host string) ([]net.IPAddr, error)) {
	t.Helper()
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = fn
}

func answerWith(t *testing.T, ips ...string) {
	t.Helper()
	setLookup(t, func(string) ([]net.IPAddr, error) {
		out := make([]net.IPAddr, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(s)})
		}
		return out, nil
	})
}

// sinkBuilder builds one sink kind against an endpoint and returns its
// http.Client plus a synchronous single-attempt send.
type sinkBuilder struct {
	name  string
	build func(t *testing.T, endpoint string) (*http.Client, func() error)
}

func sinkBuilders() []sinkBuilder {
	ev := core.NotificationEvent{UserID: 1, Type: "x", Title: "t"}
	return []sinkBuilder{
		{"webhook", func(t *testing.T, ep string) (*http.Client, func() error) {
			s, err := newWebhook(WebhookConfig{Endpoint: ep}, time.Millisecond)
			require.NoError(t, err)
			t.Cleanup(s.Close)
			return s.client, func() error { _, err := s.send(context.Background(), ev); return err }
		}},
		{"chat", func(t *testing.T, ep string) (*http.Client, func() error) {
			s, err := newChat(ChatConfig{Kind: ChatSlack, WebhookURL: ep}, time.Millisecond)
			require.NoError(t, err)
			t.Cleanup(s.Close)
			return s.client, func() error { _, err := s.send(context.Background(), ev); return err }
		}},
	}
}

func portOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return p
}

// TestSSRFMatrix_RedirectToDisallowedTargetIsRefused: the origin answers every
// POST with a 307 (method and body kept) to a Location the guard must not
// follow. The target is a real local server; it must see no request.
func TestSSRFMatrix_RedirectToDisallowedTargetIsRefused(t *testing.T) {
	setLookup(t, func(host string) ([]net.IPAddr, error) {
		switch host {
		case "internal.rebind.test":
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.9")}}, nil
		case "loopback.rebind.test":
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return nil, errors.New("unexpected lookup of " + host)
	})

	cases := []struct {
		name     string
		location func(targetPort string) string
	}{
		{"private IPv4 literal", func(p string) string { return "http://10.0.0.5:" + p + "/x" }},
		{"link-local IMDS literal", func(string) string { return "http://169.254.169.254/latest/meta-data/" }},
		{"IPv4-mapped IPv6 private literal", func(p string) string { return "http://[::ffff:10.0.0.5]:" + p + "/x" }},
		{"loopback IPv4 literal, other port", func(p string) string { return "http://127.0.0.1:" + p + "/x" }},
		{"loopback IPv6 literal", func(p string) string { return "http://[::1]:" + p + "/x" }},
		{"hostname resolving to private", func(p string) string { return "http://internal.rebind.test:" + p + "/x" }},
		{"hostname resolving to loopback", func(p string) string { return "http://loopback.rebind.test:" + p + "/x" }},
	}
	for _, sb := range sinkBuilders() {
		for _, tc := range cases {
			t.Run(sb.name+"/"+tc.name, func(t *testing.T) {
				var targetHits, originHits atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					targetHits.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				defer target.Close()
				loc := tc.location(portOf(t, target))
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					originHits.Add(1)
					http.Redirect(w, r, loc, http.StatusTemporaryRedirect)
				}))
				defer origin.Close()

				_, send := sb.build(t, origin.URL)
				err := send()

				require.Error(t, err, "redirect to %s must not be followed", loc)
				assert.Contains(t, err.Error(), "refusing cross-host redirect")
				assert.EqualValues(t, 1, originHits.Load())
				assert.EqualValues(t, 0, targetHits.Load(), "the redirect target must receive nothing")
			})
		}
	}
}

// TestSSRFMatrix_HTTPSToHTTPDowngradeIsRefused: an https endpoint that bounces
// to plain http on the SAME host (so the cross-host rule does not apply) must
// be refused, or the bearer token and signed body go out in cleartext. The
// client's transport is swapped for the test server's trusted one; its
// CheckRedirect (the code under test) is untouched.
func TestSSRFMatrix_HTTPSToHTTPDowngradeIsRefused(t *testing.T) {
	for _, sb := range sinkBuilders() {
		t.Run(sb.name, func(t *testing.T) {
			var hits atomic.Int32
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Redirect(w, r, "http://"+r.Host+"/downgraded", http.StatusTemporaryRedirect)
			}))
			defer origin.Close()

			client, send := sb.build(t, origin.URL)
			client.Transport = origin.Client().Transport
			err := send()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "refusing https->http redirect")
			assert.EqualValues(t, 1, hits.Load())
		})
	}
}

// ssrfRefusedLiterals are IP-literal hosts the sinks must refuse. Loopback is
// not among them (permitted by design, see ssrfAllowedLiterals).
var ssrfRefusedLiterals = []struct{ name, host string }{
	{"private 10/8", "10.0.0.1"},
	{"private 192.168/16", "192.168.1.1"},
	{"link-local IMDS", "169.254.169.254"},
	{"IPv4-mapped private", "[::ffff:10.0.0.1]"},
	{"IPv4-mapped IMDS, dotted", "[::ffff:169.254.169.254]"},
	{"IPv4-mapped IMDS, hex", "[::ffff:a9fe:a9fe]"},
	{"IPv6 link-local", "[fe80::1]"},
	{"IPv6 unique-local", "[fd00::1]"},
	{"NAT64-embedded IMDS", "[64:ff9b::a9fe:a9fe]"},
	{"NAT64-embedded private", "[64:ff9b::a00:1]"},
	{"IPv4-compatible IMDS", "[::a9fe:a9fe]"},
	{"unspecified IPv4", "0.0.0.0"},
	{"this-network IPv4", "0.1.2.3"},
	{"unspecified IPv6", "[::]"},
}

// ssrfAllowedLiterals pin the documented permissive side: loopback (a local
// receiver for development) and genuinely public addresses.
var ssrfAllowedLiterals = []struct{ name, host string }{
	{"IPv6 loopback", "[::1]"},
	{"IPv4 loopback", "127.0.0.1"},
	{"IPv4-mapped loopback", "[::ffff:127.0.0.1]"},
	{"public IPv4", "203.0.113.5"},
	{"public IPv6", "[2001:db8::1]"},
}

func resolverMustNotRun(t *testing.T) {
	t.Helper()
	setLookup(t, func(host string) ([]net.IPAddr, error) {
		t.Errorf("an IP literal must not be resolved (lookup of %q)", host)
		return nil, errors.New("unexpected lookup")
	})
}

// constructors runs fn against every entry point that validates an endpoint.
func constructors(t *testing.T, endpoint string, wantErr bool, wantSubstr string) {
	t.Helper()
	assertResult := func(t *testing.T, err error) {
		t.Helper()
		if wantErr {
			require.Error(t, err, "%s must be refused", endpoint)
			assert.Contains(t, err.Error(), wantSubstr)
		} else {
			require.NoError(t, err, "%s must be accepted", endpoint)
		}
	}
	t.Run("validateEndpoint", func(t *testing.T) {
		assertResult(t, validateEndpoint(endpoint, false, false))
	})
	t.Run("NewWebhook", func(t *testing.T) {
		s, err := NewWebhook(WebhookConfig{Endpoint: endpoint, AllowInsecureTransport: true})
		if s != nil {
			defer s.Close()
		}
		assertResult(t, err)
	})
	t.Run("NewChat", func(t *testing.T) {
		s, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: endpoint})
		if s != nil {
			defer s.Close()
		}
		assertResult(t, err)
	})
}

func TestSSRFMatrix_EndpointIPLiteralForms(t *testing.T) {
	resolverMustNotRun(t)
	for _, tc := range ssrfRefusedLiterals {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			constructors(t, "https://"+tc.host+"/hook", true, "private/link-local")
		})
	}
	for _, tc := range ssrfAllowedLiterals {
		t.Run("allowed/"+tc.name, func(t *testing.T) {
			constructors(t, "https://"+tc.host+"/hook", false, "")
		})
	}
}

// TestSSRFMatrix_DialGuardRefusesLiteralForms: the dial-time guard the sinks
// install (netutil.Dialer with isDisallowedIP) refuses the same literals, so a
// literal reaching the transport by a path that skipped validateEndpoint is
// still stopped. Refusal happens before any socket is opened.
func TestSSRFMatrix_DialGuardRefusesLiteralForms(t *testing.T) {
	d := netutil.Dialer{Disallow: isDisallowedIP, Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("an IP literal must not be resolved")
		return nil, errors.New("unexpected lookup")
	}}
	for _, tc := range ssrfRefusedLiterals {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := d.DialContext(context.Background(), "tcp", tc.host+":443")
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disallowed address")
		})
	}
}

// ssrfNonCanonicalHosts are spellings of an IPv4 address that net.ParseIP
// rejects, so the URL host is treated as a NAME. A libc-style resolver
// (inet_aton) turns them back into an address; the Go resolver fails on them.
// The guard must refuse both outcomes when the answer is private, and fail
// closed when the lookup errors.
var ssrfNonCanonicalHosts = []struct{ name, host string }{
	{"decimal", "167772161"},
	{"octal dotted", "012.0.0.1"},
	{"hex integer", "0x0a000001"},
	{"hex dotted", "0x0a.0.0.1"},
	{"short form", "10.1"},
	{"decimal IMDS", "2852039166"},
	{"hex IMDS", "0xa9fea9fe"},
	{"trailing dot", "10.0.0.1."},
}

func TestSSRFMatrix_NonCanonicalIPv4Spellings(t *testing.T) {
	for _, tc := range ssrfNonCanonicalHosts {
		t.Run("resolves to private/"+tc.name, func(t *testing.T) {
			answerWith(t, "10.0.0.1")
			constructors(t, "https://"+tc.host+"/hook", true, "private/link-local")
		})
		t.Run("resolves to link-local/"+tc.name, func(t *testing.T) {
			answerWith(t, "169.254.169.254")
			constructors(t, "https://"+tc.host+"/hook", true, "private/link-local")
		})
		t.Run("lookup fails/"+tc.name, func(t *testing.T) {
			setLookup(t, func(string) ([]net.IPAddr, error) { return nil, errors.New("no such host") })
			constructors(t, "https://"+tc.host+"/hook", true, "could not resolve")
		})
	}
}

// TestSSRFMatrix_DialGuardRefusesNonCanonicalSpellings: at dial time the same
// names are resolved again and a private answer is refused (the DNS-rebind
// path for a name that validated clean at construction).
func TestSSRFMatrix_DialGuardRefusesNonCanonicalSpellings(t *testing.T) {
	d := netutil.Dialer{Disallow: isDisallowedIP, Resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}, nil
	}}
	for _, tc := range ssrfNonCanonicalHosts {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := d.DialContext(context.Background(), "tcp", tc.host+":443")
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disallowed address")
		})
	}
}
