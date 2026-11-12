package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3427 (notification-channel SSRF guards), the shapes the create/update
// validator and the escalation client must refuse. Companion to
// notification_channel_ssrf_guards_test.go (resolve-and-check loop, one
// redirect) and notification_channel_unspecified_ssrf_test.go.

// refuseOnCreateAndUpdate drives raw through the real CreateNotificationChannel
// and UpdateNotificationChannel (no webhookURLValidator override) and requires
// a refusal naming want, with nothing written.
func refuseOnCreateAndUpdate(t *testing.T, raw, want string) {
	t.Helper()
	for _, typ := range []string{"webhook", "slack", "teams"} {
		c := NewKeyorixCore(new(MockStorage)) // no expectations: any write panics
		created, err := c.CreateNotificationChannel(context.Background(),
			&models.NotificationChannel{Name: "n", Type: typ, URL: raw, Enabled: true}, "tester", 1)
		require.Error(t, err, "create %s %s", typ, raw)
		assert.Nil(t, created)
		assert.Contains(t, err.Error(), want, "create %s %s", typ, raw)
	}

	store := new(MockStorage)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(&models.NotificationChannel{
		ID: 7, Name: "n", Type: "webhook", URLEnc: plaintextURLEnc("https://hooks.public.test/ok"), Enabled: true,
	}, nil)
	c := NewKeyorixCore(store)
	updated, err := c.UpdateNotificationChannel(context.Background(), 7, map[string]any{"url": raw}, 1)
	require.Error(t, err, "update %s", raw)
	assert.Nil(t, updated)
	assert.Contains(t, err.Error(), want, "update %s", raw)
	store.AssertNotCalled(t, "UpdateNotificationChannel", mock.Anything, mock.Anything)
}

// IP literals never reach the resolver; a lookup here would mean the literal
// check was skipped.
func TestNotificationChannel_CreateAndUpdateRefuseIPLiteralForms(t *testing.T) {
	orig := channelLookupIPAddr
	t.Cleanup(func() { channelLookupIPAddr = orig })
	channelLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		t.Errorf("an IP literal must not be resolved (lookup of %q)", host)
		return nil, errors.New("unexpected lookup")
	}

	for _, tc := range []struct{ name, url string }{
		{"private 10/8", "https://10.0.0.1/hook"},
		{"private with port", "https://10.0.0.1:8443/hook"},
		{"private behind userinfo", "https://user:pw@10.0.0.1/hook"},
		{"loopback IPv4", "https://127.0.0.1/hook"},
		{"loopback IPv6", "https://[::1]/hook"},
		{"loopback IPv6 with port", "https://[::1]:8443/hook"},
		{"link-local IMDS", "https://169.254.169.254/latest/meta-data"},
		{"IPv4-mapped private", "https://[::ffff:10.0.0.1]/hook"},
		{"IPv4-mapped loopback", "https://[::ffff:127.0.0.1]/hook"},
		{"IPv4-mapped IMDS, dotted", "https://[::ffff:169.254.169.254]/hook"},
		{"IPv4-mapped IMDS, hex", "https://[::ffff:a9fe:a9fe]/hook"},
		{"IPv6 link-local", "https://[fe80::1]/hook"},
		{"IPv6 unique-local", "https://[fd00::1]/hook"},
		{"NAT64-embedded IMDS", "https://[64:ff9b::a9fe:a9fe]/hook"},
		{"IPv4-compatible IMDS", "https://[::a9fe:a9fe]/hook"},
		{"unspecified IPv4", "https://0.0.0.0/hook"},
		{"unspecified IPv6", "https://[::]/hook"},
		{"non-https scheme, private literal", "http://10.0.0.1/hook"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := "private/link-local"
			if tc.url[:5] == "http:" {
				want = "must use https"
			}
			refuseOnCreateAndUpdate(t, tc.url, want)
		})
	}
}

// Spellings of an IPv4 address that net.ParseIP rejects reach the resolve
// branch as hostnames. A libc-style resolver turns them back into the address
// they spell; the Go resolver fails on them. Both outcomes must be refused.
func TestNotificationChannel_CreateAndUpdateRefuseNonCanonicalIPv4Spellings(t *testing.T) {
	spellings := []struct{ name, host string }{
		{"decimal", "167772161"},
		{"decimal loopback", "2130706433"},
		{"decimal IMDS", "2852039166"},
		{"octal dotted", "012.0.0.1"},
		{"octal loopback", "0177.0.0.1"},
		{"hex integer", "0x0a000001"},
		{"hex dotted", "0x0a.0.0.1"},
		{"hex IMDS", "0xa9fea9fe"},
		{"short form", "10.1"},
		{"short loopback", "127.1"},
		{"trailing dot", "10.0.0.1."},
		{"IPv6 zone", "[fe80::1%25eth0]"},
	}
	for _, tc := range spellings {
		url := "https://" + tc.host + "/hook"
		t.Run("resolves to private/"+tc.name, func(t *testing.T) {
			resolverFor(t, []string{"10.0.0.1"}, nil)
			refuseOnCreateAndUpdate(t, url, "private/link-local")
		})
		t.Run("resolves to loopback/"+tc.name, func(t *testing.T) {
			resolverFor(t, []string{"127.0.0.1"}, nil)
			refuseOnCreateAndUpdate(t, url, "private/link-local")
		})
		t.Run("lookup fails/"+tc.name, func(t *testing.T) {
			resolverFor(t, nil, errors.New("no such host"))
			refuseOnCreateAndUpdate(t, url, "could not resolve")
		})
	}
}

// The validator is not simply "refuse everything": public literals pass.
func TestValidateWebhookURL_AcceptsPublicLiteralForms(t *testing.T) {
	for _, u := range []string{
		"https://93.184.216.34/hook",
		"https://93.184.216.34:8443/hook",
		"https://[2001:db8::1]/hook",
		"https://[::ffff:93.184.216.34]/hook",
	} {
		require.NoError(t, validateWebhookURL(u), u)
	}
}

// TestPostJSONToURL_RefusesRedirectToDisallowedLocation drives the production
// escalation client (c.httpClient nil) against an origin that answers 302 with
// each Location below. noEscalationRedirect refuses every redirect, so the
// shape of the Location does not matter -- this pins that it stays that way
// for the shapes that would be dangerous if redirects were ever allowed
// (private/loopback/link-local literals, a name that resolves to private, an
// https->http downgrade). Only the dial target is swapped: any dial other
// than the origin's means a redirect was followed.
func TestPostJSONToURL_RefusesRedirectToDisallowedLocation(t *testing.T) {
	const originHost = "hooks.origin.test"
	for _, tc := range []struct{ name, location string }{
		{"private IPv4 literal", "https://10.0.0.5/steal"},
		{"link-local IMDS literal", "https://169.254.169.254/latest/meta-data/"},
		{"loopback IPv4 literal", "https://127.0.0.1:9/steal"},
		{"loopback IPv6 literal", "https://[::1]:9/steal"},
		{"IPv4-mapped IPv6 literal", "https://[::ffff:10.0.0.5]/steal"},
		{"hostname resolving to private", "https://internal.rebind.test/steal"},
		{"https to http downgrade, same host", "http://" + originHost + "/steal"},
		{"https to http downgrade, private literal", "http://10.0.0.5/steal"},
		{"relative path, same host", "/elsewhere"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var originHits atomic.Int32
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originHits.Add(1)
				http.Redirect(w, r, tc.location, http.StatusFound)
			}))
			defer origin.Close()

			pool := x509.NewCertPool()
			pool.AddCert(origin.Certificate())
			var strayDials atomic.Int32
			orig := escalationTransport
			defer func() { escalationTransport = orig }()
			escalationTransport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if addr != net.JoinHostPort(originHost, "443") {
						strayDials.Add(1)
						return nil, errors.New("test dialer: unexpected destination " + addr)
					}
					return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
				},
				TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
			}

			c := NewKeyorixCore(new(MockStorage))
			err := c.postJSONToURL(context.Background(), "https://"+originHost+"/hook", map[string]string{"k": "v"})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "redirect refused")
			assert.EqualValues(t, 1, originHits.Load(), "the origin is contacted once")
			assert.EqualValues(t, 0, strayDials.Load(), "no connection may be attempted to the Location")
		})
	}
}
