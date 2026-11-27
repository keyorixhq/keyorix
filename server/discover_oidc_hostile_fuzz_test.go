package main

// LIB-FUZZ-2 target 3b: discoverOIDC against a hostile discovery endpoint.
//
// Inventory. wireHumanSSO fetches <issuer>/.well-known/openid-configuration for
// every configured OIDC provider at start-up. The document names the
// authorization_endpoint and token_endpoint keyorix will use, and the jwks_uri
// that supplies the token-signing keys, so a compromised or MITM'd issuer chooses
// them. discoverOIDC (net/http + encoding/json, then the oauth2.Endpoint built
// from the result) is the only gate: the document must be 200 JSON, its own issuer
// must equal the configured one, and jwks_uri must be on the issuer's host; a
// redirect must stay on the same host and never downgrade https.
//
// Oracles, each independent of the code under test:
//   - no panic, and a hostile body or redirect chain cannot make the call hang;
//   - accepted => HTTP 200, the three endpoints are present, the document's issuer
//     (when it has one) equals the configured issuer, and jwks_uri's host (from
//     net/url, compared case-insensitively) is the issuer's host: never another
//     host, including the userinfo trick http://issuer@evil; the same holds for
//     token_endpoint (#4738), which must also be https unless the issuer is http;
//   - a redirect to another host is never followed: the second server, standing
//     for any other host, sees zero requests.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// discoveryOracle returns "" or the violation for an accepted discovery document.
func discoveryOracle(issuer string, status int, d *oidcDiscovery) string {
	switch {
	case status != 200:
		return "accepted a discovery response with HTTP status " + http.StatusText(status)
	case d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "":
		return "accepted a discovery document with a missing endpoint"
	case d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/"):
		return "accepted a discovery document for issuer " + d.Issuer
	}
	jwks, err := url.Parse(d.JWKSURI)
	if err != nil {
		return "accepted an unparseable jwks_uri"
	}
	iss, _ := url.Parse(issuer)
	if !strings.EqualFold(jwks.Hostname(), iss.Hostname()) {
		return "accepted jwks_uri on host " + jwks.Hostname() + ", issuer is " + iss.Hostname()
	}
	// #4738: the token_endpoint receives the client credentials. With no
	// token_endpoint_hosts configured it must be on the issuer's host, and https
	// unless the issuer itself is http (loopback).
	tok, err := url.Parse(d.TokenEndpoint)
	if err != nil {
		return "accepted an unparseable token_endpoint"
	}
	if !strings.EqualFold(tok.Hostname(), iss.Hostname()) {
		return "accepted token_endpoint on host " + tok.Hostname() + ", issuer is " + iss.Hostname()
	}
	if tok.Scheme != "https" && (tok.Scheme != "http" || iss.Scheme != "http") {
		return "accepted token_endpoint with scheme " + tok.Scheme + " for an " + iss.Scheme + " issuer"
	}
	return ""
}

func FuzzDiscoverOIDCHostile(f *testing.F) {
	var evilHits atomic.Int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	f.Cleanup(evil.Close)

	var (
		status   atomic.Int64
		location atomic.Value // string, "" for none
		body     atomic.Value // []byte
	)
	issuerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loc, _ := location.Load().(string); loc != "" && !strings.HasPrefix(r.URL.Path, "/landed") {
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(int(status.Load()))
		b, _ := body.Load().([]byte)
		_, _ = w.Write(b)
	}))
	f.Cleanup(issuerSrv.Close)
	issuer := issuerSrv.URL // http on loopback: the one non-https form discoverOIDC allows
	host := strings.TrimPrefix(issuer, "http://")

	expand := func(s string) string {
		return strings.NewReplacer("SELF", issuer, "EVIL", evil.URL, "HOST", host).Replace(s)
	}
	doc := func(jwks, iss string) []byte {
		return []byte(`{"issuer":"` + iss + `","authorization_endpoint":"` + issuer + `/a","token_endpoint":"` + issuer + `/t","jwks_uri":"` + jwks + `"}`)
	}
	docTok := func(tok string) []byte {
		return []byte(expand(`{"issuer":"SELF","authorization_endpoint":"SELF/a","token_endpoint":"` + tok + `","jwks_uri":"SELF/jwks"}`))
	}
	valid := doc(issuer+"/jwks", issuer)
	for _, s := range []struct {
		status uint16
		loc    string
		body   []byte
	}{
		{200, "", valid},
		{200, "SELF/landed", valid},
		{200, "EVIL/x", valid},
		{200, "//EVIL/x", valid},
		{200, "SELF/landed", doc("EVIL/jwks", "SELF")},
		{200, "", doc("http://HOST@evil.test/jwks", "SELF")},
		{200, "", doc("http://evil.test@HOST/jwks", "SELF")},
		{200, "", doc("http://HOST.evil.test/jwks", "SELF")},
		{200, "", doc("SELF/jwks", "https://evil.test")},
		{200, "", doc("SELF/jwks", "SELF/")},
		{200, "", doc("%zz", "SELF")},
		{200, "", docTok("EVIL/t")},
		{200, "", docTok("http://169.254.169.254/latest/meta-data")},
		{200, "", docTok("http://HOST@evil.test/t")},
		{200, "", docTok("http://localhost/t")},
		{200, "", docTok("ftp://HOST/t")},
		{200, "", docTok("%zz")},
		{500, "", valid},
		{200, "", []byte(`{"authorization_endpoint":1}`)},
		{200, "", []byte(`null`)},
		{200, "", nil},
	} {
		// The fuzz body serves HTTP 200+st%400, so a seed's status is stored as
		// its offset from 200. Before #4738 the literal was passed through, and
		// every "200" seed was served as 400: no seed reached the oracle.
		f.Add(s.status-200, s.loc, s.body)
	}

	f.Fuzz(func(t *testing.T, st uint16, loc string, doc []byte) {
		status.Store(int64(200 + int(st)%400))
		location.Store(strings.NewReplacer("\r", "", "\n", "").Replace(expand(loc)))
		body.Store([]byte(strings.ReplaceAll(string(doc), "SELF", issuer)))
		evilHits.Store(0)
		var (
			d   *oidcDiscovery
			err error
		)
		fuzzutil.Guard(t.Fatalf, "discoverOIDC", func() { d, err = discoverOIDC(issuer) })
		if n := evilHits.Load(); n != 0 {
			t.Fatalf("discovery followed a redirect to another host (%d requests); Location was %q", n, loc)
		}
		if err != nil {
			return
		}
		if msg := discoveryOracle(issuer, int(status.Load()), d); msg != "" {
			t.Fatalf("%s\n  document: %s", msg, doc)
		}
	})
}

// TestDiscoveryOracle_RedProof: the oracle names each planted acceptance.
func TestDiscoveryOracle_RedProof(t *testing.T) {
	const iss = "http://127.0.0.1:9"
	good := &oidcDiscovery{Issuer: iss, AuthorizationEndpoint: iss + "/a", TokenEndpoint: iss + "/t", JWKSURI: iss + "/jwks"}
	if msg := discoveryOracle(iss, 200, good); msg != "" {
		t.Fatalf("oracle rejects a correct document: %s", msg)
	}
	for name, c := range map[string]struct {
		status int
		mut    func(d oidcDiscovery) oidcDiscovery
	}{
		"error status":        {500, func(d oidcDiscovery) oidcDiscovery { return d }},
		"missing endpoint":    {200, func(d oidcDiscovery) oidcDiscovery { d.TokenEndpoint = ""; return d }},
		"other issuer":        {200, func(d oidcDiscovery) oidcDiscovery { d.Issuer = "https://evil.test"; return d }},
		"jwks other host":     {200, func(d oidcDiscovery) oidcDiscovery { d.JWKSURI = "http://evil.test/jwks"; return d }},
		"jwks userinfo trick": {200, func(d oidcDiscovery) oidcDiscovery { d.JWKSURI = "http://127.0.0.1:9@evil.test/jwks"; return d }},
		"jwks lookalike":      {200, func(d oidcDiscovery) oidcDiscovery { d.JWKSURI = "http://127.0.0.1.evil.test/jwks"; return d }},
		"token other host":    {200, func(d oidcDiscovery) oidcDiscovery { d.TokenEndpoint = "http://169.254.169.254/t"; return d }},
		"token userinfo":      {200, func(d oidcDiscovery) oidcDiscovery { d.TokenEndpoint = "http://127.0.0.1:9@evil.test/t"; return d }},
		"token scheme":        {200, func(d oidcDiscovery) oidcDiscovery { d.TokenEndpoint = "ftp://127.0.0.1:9/t"; return d }},
	} {
		d := c.mut(*good)
		if discoveryOracle(iss, c.status, &d) == "" {
			t.Errorf("oracle missed planted acceptance: %s", name)
		}
	}
}
