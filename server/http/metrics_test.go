package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// /metrics serves Prometheus exposition format including the Go runtime collectors
// and our custom HTTP metrics, and PrometheusMiddleware records traffic.
func TestMetricsEndpoint(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// Generate some traffic so the HTTP counter has a sample to expose.
	resp, err := client.Get(srv.URL + "/health")
	require.NoError(t, err)
	_ = resp.Body.Close()

	resp, err = client.Get(srv.URL + "/metrics")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := readAll(t, resp.Body)

	assert.Contains(t, body, "go_goroutines", "Go runtime collector should be present")
	assert.Contains(t, body, "keyorix_http_requests_total", "custom HTTP counter should be present")
	assert.Contains(t, body, `route="/health"`, "the /health request should be recorded by route pattern")
}

// When cfg.Server.HTTP.MetricsToken is set, /metrics requires a matching
// "Authorization: Bearer <token>" header. The comparison uses
// subtle.ConstantTimeCompare (see router.go) rather than a plain `!=`, to
// avoid a timing side-channel on the token; this test only asserts the
// functional behavior is unchanged (correct token accepted, wrong/missing
// token rejected) — a timing side-channel isn't practically observable from
// a unit test.
func TestMetricsEndpoint_BearerToken(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	const token = "s3cret-metrics-token"

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.HTTP.MetricsToken = token
	router, err := NewRouter(cfg, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	get := func(authHeader string, setHeader bool) *http.Response {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
		require.NoError(t, err)
		if setHeader {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("correct token is accepted", func(t *testing.T) {
		resp := get("Bearer "+token, true)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("token differing only in the last byte is rejected", func(t *testing.T) {
		wrong := token[:len(token)-1] + "X"
		resp := get("Bearer "+wrong, true)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("completely different token is rejected", func(t *testing.T) {
		resp := get("Bearer totally-wrong-token", true)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing Authorization header is rejected", func(t *testing.T) {
		resp := get("", false)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("malformed Authorization header is rejected", func(t *testing.T) {
		resp := get(token, true) // missing "Bearer " prefix
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("empty Authorization header is rejected", func(t *testing.T) {
		resp := get("", true)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
