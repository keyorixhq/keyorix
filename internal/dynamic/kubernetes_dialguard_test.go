package dynamic

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// acceptCounter counts TCP connections a listener accepts. Counting accepts is
// the effect that matters for a dial guard: a guard that refuses the dial leaves
// the count at zero, while one that merely rejected the response would not.
type acceptCounter struct {
	net.Listener
	n atomic.Int64
}

func (l *acceptCounter) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// newCountingTLSServer starts a TLS API-server stand-in on loopback and returns
// it with its accept counter and its certificate as a PEM CA bundle.
func newCountingTLSServer(t *testing.T) (srv *httptest.Server, accepts *acceptCounter, caPEM string) {
	t.Helper()
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "stub", http.StatusInternalServerError)
	}))
	accepts = &acceptCounter{Listener: srv.Listener}
	srv.Listener = accepts
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return srv, accepts, caPEM
}

func k8sAdminDSN(t *testing.T, apiServer, caPEM string) string {
	t.Helper()
	b, err := json.Marshal(k8sConfig{
		Namespace:      "default",
		ServiceAccount: "sa",
		APIServer:      apiServer,
		Token:          "admin-token",
		CACert:         caPEM,
	})
	require.NoError(t, err)
	return string(b)
}

// TestKubernetesEngine_DialGuard pins the dial-time egress guard on the Kubernetes
// engine's explicit api_server (KFZ-2026-187): with allow_private_network_targets
// off, a private, loopback or link-local destination is refused at dial time, and
// a hostname that resolves public at registration but private at dial (DNS
// rebinding) is refused too. The assertions are on the effect, the accept count
// of the destination listener, not on the returned error.
func TestKubernetesEngine_DialGuard(t *testing.T) {
	t.Run("loopback api_server is refused when private targets are not allowed", func(t *testing.T) {
		srv, accepts, ca := newCountingTLSServer(t)
		eng, err := New("kubernetes", false, false)
		require.NoError(t, err)
		_, _, err = eng.Issue(t.Context(), k8sAdminDSN(t, srv.URL, ca), "", time.Hour)
		require.Error(t, err)
		require.Contains(t, err.Error(), "refusing to dial", "the guard, not a later failure, must be what stopped it")
		require.Zero(t, accepts.n.Load(), "the destination accepted a connection although private targets are not allowed")
	})

	t.Run("rebinding hostname is refused when it resolves private at dial time", func(t *testing.T) {
		srv, accepts, ca := newCountingTLSServer(t)
		_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
		require.NoError(t, err)
		orig := dialResolve
		t.Cleanup(func() { dialResolve = orig })
		var resolved atomic.Int64
		dialResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
			resolved.Add(1)
			require.Equal(t, "k8s.rebind.test", host)
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil // public at registration, private now
		}
		eng, err := New("kubernetes", false, false)
		require.NoError(t, err)
		_, _, err = eng.Issue(t.Context(), k8sAdminDSN(t, "https://k8s.rebind.test:"+port, ca), "", time.Hour)
		require.Error(t, err)
		// Without this the subtest would pass vacuously: an unguarded client cannot
		// resolve the made-up name at all, so zero accepts alone proves nothing.
		require.Positive(t, resolved.Load(), "the dial path never consulted the guard's resolver")
		require.Zero(t, accepts.n.Load(), "a rebound hostname reached a private destination")
	})

	t.Run("positive control: the same destination is dialled when private targets are allowed", func(t *testing.T) {
		srv, accepts, ca := newCountingTLSServer(t)
		eng, err := New("kubernetes", true, false)
		require.NoError(t, err)
		_, _, err = eng.Issue(t.Context(), k8sAdminDSN(t, srv.URL, ca), "", time.Hour)
		require.Error(t, err, "the stub API server answers 500, so Issue fails after the dial")
		require.Positive(t, accepts.n.Load(), "with the opt-out set the connection must go through, or the refusal above proves nothing")
	})
}
