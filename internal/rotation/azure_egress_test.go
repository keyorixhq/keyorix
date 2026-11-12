package rotation

import (
	"context"
	"net/http"
	"net/http/httptest"
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
