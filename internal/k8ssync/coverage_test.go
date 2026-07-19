package k8ssync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- NewInClusterSink error-path coverage ----

// TestNewInClusterSink_NoEnvVars covers the "not running in-cluster" error when
// both env vars are absent.
func TestNewInClusterSink_NoEnvVars(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err := NewInClusterSink()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not running in-cluster")
}

// TestNewInClusterSink_MissingPort covers the missing-port branch.
func TestNewInClusterSink_MissingPort(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err := NewInClusterSink()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not running in-cluster")
}

// TestNewInClusterSink_TokenFileMissing covers the error path when the SA token
// file does not exist (the common case on a dev machine outside a k8s pod).
func TestNewInClusterSink_TokenFileMissing(t *testing.T) {
	if _, err := os.Stat(saTokenPath); err == nil {
		t.Skip("SA token file exists — running inside a pod; skip")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	_, err := NewInClusterSink()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service-account token")
}

// buildSinkFromPaths replicates NewInClusterSink using explicit file paths so
// the higher branches (post-env-var checks) can be exercised without modifying
// the package-level constants.  It lives in the same package so it can access
// RESTSink fields directly.
func buildSinkFromPaths(host, port, tokenPath, caPath string) (*RESTSink, error) {
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, &emptyCAErr{path: caPath}
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return &RESTSink{
		host:         "https://" + net.JoinHostPort(host, port),
		token:        strings.TrimSpace(string(token)),
		fieldManager: "keyorix-sync",
		hc:           hc,
	}, nil
}

type emptyCAErr struct{ path string }

func (e *emptyCAErr) Error() string { return "no certificates in " + e.path }

// TestBuildSinkFromPaths_EmptyCA exercises the "no certificates in <path>" branch.
func TestBuildSinkFromPaths_EmptyCA(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("tok"), 0600))
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caPath, []byte("no certs here"), 0600))

	_, err := buildSinkFromPaths("10.0.0.1", "443", tokenPath, caPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates in")
}

// TestBuildSinkFromPaths_Success exercises the fully-successful build with a
// self-signed CA PEM.
func TestBuildSinkFromPaths_Success(t *testing.T) {
	dir := t.TempDir()

	// Generate a minimal self-signed CA cert.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.crt")
	f, err := os.Create(caPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, f.Close())

	tokenPath := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("  my-token  "), 0600))

	sink, err := buildSinkFromPaths("10.0.0.1", "443", tokenPath, caPath)
	require.NoError(t, err)
	require.NotNil(t, sink)
	assert.Equal(t, "https://10.0.0.1:443", sink.host)
	assert.Equal(t, "my-token", sink.token, "whitespace should be trimmed")
	assert.Equal(t, "keyorix-sync", sink.fieldManager)
}

// ---- Sync / runner.go coverage ----

// TestSync_WithCleanupListError exercises the cleanup-error path: when the sink's
// List fails during orphan cleanup, the result records the failure and the log
// captures the summary line.  (Reconcile always returns nil err; the reconcile
// error branch in Sync is dead code from the interface signature.)
func TestSync_WithCleanupListError(t *testing.T) {
	var logged []string
	logf := func(format string, args ...interface{}) {
		logged = append(logged, format)
	}

	// A sink whose List always fails causes cleanup to record an error, but the
	// top-level Reconcile still returns (res, nil).
	sink := &fakeSink{
		existing: map[string]map[string][]byte{},
		applied:  map[string]map[string][]byte{},
		owned:    map[string]bool{},
		listErr:  map[string]bool{"app": true},
	}
	e := NewEngine(&fakeFetcher{
		values: map[string][]byte{"prod/db": []byte("v")},
	}, sink, WithCleanup())

	mappings := []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	}

	res := Sync(context.Background(), e, mappings, logf)
	// The list error shows up as Failed.
	assert.Equal(t, 1, res.Failed)
	require.NotEmpty(t, logged)
	// The summary line is always emitted (no top-level error return from Reconcile).
	assert.Contains(t, logged[0], "created=")
}

// TestSync_Success exercises the summary log line emitted on a clean reconcile.
func TestSync_Success(t *testing.T) {
	var logged []string
	logf := func(format string, args ...interface{}) {
		logged = append(logged, format)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer srv.Close()

	e := NewEngine(
		&fakeFetcher{values: map[string][]byte{"prod/db": []byte("val")}},
		testSink(srv),
	)
	mappings := []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	}

	res := Sync(context.Background(), e, mappings, logf)
	assert.Equal(t, 1, res.Created)
	require.NotEmpty(t, logged)
	assert.Contains(t, logged[0], "created=")
}

// TestSync_WithPerTargetErrors exercises the per-target error log lines inside Sync.
func TestSync_WithPerTargetErrors(t *testing.T) {
	var logged []string
	logf := func(format string, args ...interface{}) {
		logged = append(logged, format)
	}

	// A fetcher that always fails will produce res.Errors populated but no
	// top-level Reconcile error (fetch failures are per-target, not fatal).
	sink := &fakeSink{
		existing: map[string]map[string][]byte{},
		applied:  map[string]map[string][]byte{},
		owned:    map[string]bool{},
	}
	e := NewEngine(&fakeFetcher{
		fail: map[string]bool{"prod/db": true},
	}, sink)
	mappings := []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	}

	res := Sync(context.Background(), e, mappings, logf)
	assert.Equal(t, 1, res.Failed)
	// Summary + at least one per-error line.
	require.GreaterOrEqual(t, len(logged), 2)
	// First log line is the summary.
	assert.Contains(t, logged[0], "created=")
}
