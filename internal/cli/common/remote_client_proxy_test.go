// remote_client_proxy_test.go — Part 2 regression audit finding on PR #1606:
// newRemoteTransport's hand-rolled http.Transport (added for the #1521
// connect/idle timeout split) omitted the Proxy field entirely, silently
// dropping HTTP_PROXY/HTTPS_PROXY/NO_PROXY support that every CLI
// remote-mode call site previously got for free via http.DefaultTransport.
// In an on-prem/regulated deployment mandating all egress through an
// audit/DLP proxy, upgrading silently stopped honoring that proxy.
package common

import (
	"net/http"
	"reflect"
	"testing"
	"time"
)

// TestNewRemoteTransport_ProxyFieldSet is the fast, no-network-setup pin:
// the transport must actually consult the environment for a proxy, not
// silently default to none.
func TestNewRemoteTransport_ProxyFieldSet(t *testing.T) {
	transport := newRemoteTransport(5*time.Second, 30*time.Second)
	if transport.Proxy == nil {
		t.Fatal("newRemoteTransport's Proxy field must not be nil -- every CLI remote-mode request must honor HTTP_PROXY/HTTPS_PROXY/NO_PROXY the same way http.DefaultTransport always did")
	}
}

// TestNewRemoteTransport_ProxyFuncIsHTTPProxyFromEnvironment pins the exact
// function assigned, not just non-nil-ness -- a stub or no-op func would
// also satisfy the nil check above but still silently drop proxy support.
//
// This intentionally does NOT drive a live request through a fake proxy
// listener with t.Setenv: http.ProxyFromEnvironment reads HTTP_PROXY/
// HTTPS_PROXY/NO_PROXY through a process-wide sync.Once in net/http (see
// golang.org/x/net/http/httpproxy via net/http's envProxyFunc) -- the FIRST
// call anywhere in the test binary's lifetime locks in that env snapshot for
// every subsequent call, env var or no. That makes a live round-trip test
// pass or fail based on unrelated test order/count within the package
// (verified: reliable alone, flaky under `-count=5` and inside the full
// `internal/cli/...` suite) -- a property of the stdlib cache, not of this
// fix. Function-pointer identity is deterministic and still proves the
// right function is wired in.
func TestNewRemoteTransport_ProxyFuncIsHTTPProxyFromEnvironment(t *testing.T) {
	transport := newRemoteTransport(5*time.Second, 30*time.Second)
	got := reflect.ValueOf(transport.Proxy).Pointer()
	want := reflect.ValueOf(http.ProxyFromEnvironment).Pointer()
	if got != want {
		t.Fatal("newRemoteTransport's Proxy field is not http.ProxyFromEnvironment -- HTTP_PROXY/HTTPS_PROXY/NO_PROXY will not be honored")
	}
}

// sanity: confirm the test's own assumption -- http.DefaultTransport (the
// implicit pre-#1521 behavior) DOES set Proxy, so the regression this test
// pins is real (the bug wasn't "Proxy was always nil everywhere").
func TestDefaultTransport_HasProxySet_Sanity(t *testing.T) {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not *http.Transport in this Go version -- sanity check inapplicable")
	}
	if dt.Proxy == nil {
		t.Fatal("sanity check failed: http.DefaultTransport.Proxy is nil -- the regression this test suite pins assumes it is not")
	}
}
