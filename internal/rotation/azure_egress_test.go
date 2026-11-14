package rotation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestAzureGraphHTTPClient_RefusesRedirects is the H1 regression guard: the
// Graph client must NOT follow a redirect. The stdlib default follows up to 10
// redirects to any host, which would bounce the bearer-token-bearing Graph
// request to wherever a compromised/MITM'd upstream points. The test wires the
// production client's own CheckRedirect onto a transport pointed at two loopback
// servers (server A 302-redirects to server B) and asserts server B is never
// reached.
//
// Red proof: with refuseAzureGraphRedirect removed from azureGraphHTTPClient
// (CheckRedirect nil), the client follows the 302 and server B records a hit —
// this test then fails. With the fix it stays at zero.
func TestAzureGraphHTTPClient_RefusesRedirects(t *testing.T) {
	var bHits atomic.Int32
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer serverB.Close()

	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, serverB.URL, http.StatusFound)
	}))
	defer serverA.Close()

	client := azureGraphHTTPClient()
	// The production CheckRedirect is what we are testing; keep it. Swap only the
	// transport so the loopback test servers are reachable regardless of the
	// guard's dialer (loopback is permitted by IsLinkLocal anyway, but this keeps
	// the test independent of real sockets through the guard).
	client.Transport = serverA.Client().Transport

	resp, err := client.Get(serverA.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	// Either outcome is acceptable as "did not follow": a returned error, or the
	// 3xx surfaced as the final response. What must NOT happen is reaching B.
	_ = err
	if got := bHits.Load(); got != 0 {
		t.Fatalf("H1: the Graph client followed a redirect to server B (%d hit(s)); it must refuse all redirects", got)
	}
}

// TestAzureGraphHTTPClient_RefusesLinkLocalDial is the defence-in-depth half of
// H1: the client's transport dials through a netutil.Dialer that refuses
// link-local targets (cloud IMDS 169.254.169.254), so even though the Graph host
// is a hard-coded public constant, a misdirected dial to a link-local address is
// refused before any socket is opened. A short context bounds the unfixed path
// (which would otherwise attempt a real dial) so this stays fast.
func TestAzureGraphHTTPClient_RefusesLinkLocalDial(t *testing.T) {
	client := azureGraphHTTPClient()
	// Pin the direct dial: with a proxy in the environment the request would go
	// to the proxy instead. The proxy hop is covered by
	// TestAzureGraphHTTPClient_GuardsProxyDial.
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	client.Transport = transport
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/v1.0/applications", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("H1: a dial to link-local 169.254.169.254 must be refused by the guard dialer")
	}
	if !strings.Contains(err.Error(), "disallowed address") {
		t.Fatalf("H1: expected the netutil guard to refuse the link-local dial, got a different error: %v", err)
	}
}

// TestAzureGraphHTTPClient_HonoursProxyFromEnvironment: the Graph client used
// http.DefaultTransport before the H1 hardening, so it honoured HTTPS_PROXY.
// The hardened transport must keep that, or Azure rotation breaks in every
// deployment whose only route to the internet is a proxy.
func TestAzureGraphHTTPClient_HonoursProxyFromEnvironment(t *testing.T) {
	transport, ok := azureGraphHTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Graph client transport is %T, want *http.Transport", azureGraphHTTPClient().Transport)
	}
	if transport.Proxy == nil {
		t.Fatal("Graph client transport has no Proxy: HTTPS_PROXY would be ignored")
	}
	if reflect.ValueOf(transport.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Fatal("Graph client transport Proxy is not http.ProxyFromEnvironment")
	}
	if !transport.ForceAttemptHTTP2 || transport.TLSHandshakeTimeout == 0 {
		t.Fatalf("Graph client transport lost the DefaultTransport tuning (HTTP/2 %v, TLS handshake timeout %v)",
			transport.ForceAttemptHTTP2, transport.TLSHandshakeTimeout)
	}
}

// TestAzureGraphHTTPClient_GuardsProxyDial: with a proxy configured, the dial
// the guard sees is the dial to the proxy, so a proxy on a link-local address
// (e.g. a poisoned HTTPS_PROXY pointing at cloud IMDS) is refused.
func TestAzureGraphHTTPClient_GuardsProxyDial(t *testing.T) {
	client := azureGraphHTTPClient()
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: "169.254.169.254:3128"})
	client.Transport = transport
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/v1.0/applications", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "disallowed address") {
		t.Fatalf("a dial to a link-local proxy must be refused by the guard dialer, got: %v", err)
	}
}
