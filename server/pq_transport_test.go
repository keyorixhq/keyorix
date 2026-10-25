// pq_transport_test.go -- RD-PQTLS-1: post-quantum key exchange on the HTTP listener.
//
// A REAL handshake between the listener's tls.Config as createTLSConfig builds it
// (so whatever the server sets or forgets to set, e.g. CurvePreferences, is what is
// tested) and the HTTP client the CLI uses (a clone of http.DefaultTransport, see
// cli/internal/apiclient.NewHardenedHTTPClientWithCAFile), asserting the NEGOTIATED
// group from tls.ConnectionState.CurveID. Every assertion is on what the wire
// produced, not on the config fields.
package main

import (
	"crypto/fips140"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/tlsmetrics"
)

// startPQHTTPServer serves a trivial handler behind createTLSConfig's tls.Config on a
// loopback listener, exactly as startHTTPServer wires it (ServeTLS with empty file names).
func startPQHTTPServer(t *testing.T, mode string, mutate ...func(*tls.Config)) string {
	t.Helper()
	certFile, keyFile := writeSelfSignedCert(t, t.TempDir())
	cfg := &config.Config{}
	cfg.Server.HTTP.TLS = config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	cfg.Server.HTTP.TLSMode = mode
	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createTLSConfig: %v", err)
	}
	for _, m := range mutate {
		m(tlsConfig)
	}
	srv := &http.Server{
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// cliShapedClient is the HTTP client the CLI builds for API calls: a clone of
// http.DefaultTransport with a TLS config that sets no CurvePreferences.
// InsecureSkipVerify is the only difference: the test certificate is self-signed.
func cliShapedClient(t *testing.T, mutate func(*tls.Config)) *http.Client {
	t.Helper()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("http.DefaultTransport is not an *http.Transport")
	}
	tr := base.Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // #nosec G402 -- throwaway self-signed test cert; the test is about the key-exchange group
	if mutate != nil {
		mutate(tr.TLSClientConfig)
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func handshakeCount(t *testing.T, listener, group string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "keyorix_tls_handshakes_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelValue(m, "listener") == listener && labelValue(m, "group") == group {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func TestPQTransport_HTTP_DefaultMode_NegotiatesX25519MLKEM768(t *testing.T) {
	addr := startPQHTTPServer(t, "")
	before := handshakeCount(t, "http", "X25519MLKEM768")

	resp, err := cliShapedClient(t, nil).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.TLS == nil {
		t.Fatal("no TLS connection state on the response")
	}
	if resp.TLS.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated group = %v (%#x), want X25519MLKEM768", resp.TLS.CurveID, uint16(resp.TLS.CurveID))
	}
	if got := handshakeCount(t, "http", "X25519MLKEM768") - before; got != 1 {
		t.Errorf("keyorix_tls_handshakes_total{listener=http,group=X25519MLKEM768} grew by %v, want 1", got)
	}
}

func TestPQTransport_HTTP_StrictMode_NegotiatesX25519MLKEM768(t *testing.T) {
	addr := startPQHTTPServer(t, config.TLSModeStrict)
	conn, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // #nosec G402 -- throwaway self-signed test cert
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS13 || st.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("version %#x group %v, want TLS 1.3 and X25519MLKEM768", st.Version, st.CurveID)
	}
}

// Control (the "watch it fail" check for the two tests above): a listener narrowed with
// CurvePreferences=[X25519], the mistake this file guards against, does NOT negotiate the
// hybrid, and the same observation (resp.TLS.CurveID, the metric label) shows it.
func TestPQTransport_Control_NarrowedListenerIsDetected(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("X25519 is not an allowed group in FIPS 140-3 mode; the control uses it")
	}
	addr := startPQHTTPServer(t, "", func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} })
	resp, err := cliShapedClient(t, nil).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.TLS.CurveID == tls.X25519MLKEM768 {
		t.Fatal("a listener restricted to X25519 negotiated the hybrid: the assertions in this file would not catch a narrowing")
	}
	if resp.TLS.CurveID != tls.X25519 {
		t.Fatalf("negotiated %v, want X25519", resp.TLS.CurveID)
	}
}

// A client that does not offer the hybrid (an older Go/OpenSSL, or a deliberately classical
// one) must still connect: the server prefers the hybrid but never requires it. P-256 is
// used so the same test is valid with and without GODEBUG=fips140 (X25519 is not
// FIPS-approved, see the next test).
func TestPQTransport_HTTP_ClassicalOnlyClientStillConnects(t *testing.T) {
	addr := startPQHTTPServer(t, "")
	before := handshakeCount(t, "http", "P-256")

	client := cliShapedClient(t, func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} })
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("a classical-only client must still connect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.TLS.CurveID != tls.CurveP256 {
		t.Fatalf("negotiated group = %v, want P-256", resp.TLS.CurveID)
	}
	if got := handshakeCount(t, "http", "P-256") - before; got != 1 {
		t.Errorf("classical handshake counted %v times, want 1", got)
	}
}

// An X25519-only client: connects normally, but is refused when the server runs in Go's
// FIPS 140-3 mode (GODEBUG=fips140=on|only), which removes X25519 from the allowed groups.
// The hybrid X25519MLKEM768 stays allowed there (golang/go#78298, fixed in Go 1.27 and
// the 1.26 branch); see docs/post-quantum-transport.md.
func TestPQTransport_HTTP_X25519OnlyClient_DependsOnFIPSMode(t *testing.T) {
	addr := startPQHTTPServer(t, "")
	client := cliShapedClient(t, func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} })
	resp, err := client.Get("https://" + addr + "/")
	if fips140.Enabled() {
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("an X25519-only client connected to a FIPS-mode server (group %v)", resp.TLS.CurveID)
		}
		return
	}
	if err != nil {
		t.Fatalf("an X25519-only client must connect outside FIPS mode: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.TLS.CurveID != tls.X25519 {
		t.Fatalf("negotiated group = %v, want X25519", resp.TLS.CurveID)
	}
}

// TLS 1.2 has no hybrid group: a TLS 1.2-only client negotiates a classical ECDHE group.
// This is the documented limit (PQ key exchange needs TLS 1.3), pinned so it stays visible.
func TestPQTransport_HTTP_TLS12ClientIsNotPostQuantum(t *testing.T) {
	addr := startPQHTTPServer(t, "")
	conn, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true}) // #nosec G402 -- throwaway self-signed test cert
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	if id := conn.ConnectionState().CurveID; id == tls.X25519MLKEM768 {
		t.Fatalf("TLS 1.2 negotiated %v: that should be impossible", id)
	}
}

// No code path may narrow the groups the server accepts: an unset CurvePreferences is
// what makes Go's default (hybrid first) apply. Checked on the config the listener uses.
func TestPQTransport_HTTP_ListenerDoesNotSetCurvePreferences(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t, t.TempDir())
	for _, mode := range []string{"", config.TLSModeStrict} {
		cfg := &config.Config{}
		cfg.Server.HTTP.TLS = config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
		cfg.Server.HTTP.TLSMode = mode
		tc, err := createTLSConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if tc.CurvePreferences != nil {
			t.Errorf("mode %q: CurvePreferences = %v, want nil (Go default includes X25519MLKEM768)", mode, tc.CurvePreferences)
		}
	}
	ac, err := buildAutoCertTLSConfig([]string{"example.com"}, config.TLSConfig{CertCacheDir: filepath.Join(t.TempDir(), "c")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if ac.CurvePreferences != nil {
		t.Errorf("autocert: CurvePreferences = %v, want nil", ac.CurvePreferences)
	}
}

// The documented revert switch: GODEBUG=tlsmlkem=0 removes the hybrid from Go's default
// groups. Both ends live in this process, so it turns the hybrid off for the server and the
// client alike; the connection still succeeds, classically. Outside FIPS mode the fallback
// is X25519; in FIPS mode it is a NIST curve.
func TestPQTransport_RevertSwitch_TLSMLKEM0_FallsBackToClassical(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=0")
	addr := startPQHTTPServer(t, "")
	resp, err := cliShapedClient(t, nil).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET with tlsmlkem=0: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if tlsmetrics.IsPostQuantum(resp.TLS.CurveID) {
		t.Fatalf("GODEBUG=tlsmlkem=0 still negotiated %v", resp.TLS.CurveID)
	}
	if resp.TLS.CurveID == 0 {
		t.Fatal("no ECDHE group negotiated")
	}
}
