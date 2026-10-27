package http

import (
	"bytes"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/webui"
)

// AIRGAP-WEBUI-1 item 1: every file the web build ships must be served by the
// binary at its own path with its own Content-Type. A path registerWebUI does not
// know falls through to the SPA shell (text/html, 200), which is how /fonts/*
// silently degraded to system fonts: the browser got HTML where it asked for a
// woff2 and discarded it.
//
// What this does not cover: the real embedded dist/ holds only the committed
// placeholder in a test build, so the embedded-FS case walks that plus a
// synthetic dist (placeholder + a copy of web/public, which is exactly what Vite
// copies to the dist root) served through the same http.FS(fs.FS) wrapper the
// embed uses. A release build's extra files are covered by running this test
// after `make build-ui`.

// wantContentTypes maps a dist file extension to the media type the server must
// send. An extension missing here fails the test on purpose: add it, and decide
// what the browser must be told, rather than let it be sniffed.
var wantContentTypes = map[string]string{
	".woff2": "font/woff2",
	".woff":  "font/woff",
	".svg":   "image/svg+xml",
	".js":    "text/javascript",
	".mjs":   "text/javascript",
	".css":   "text/css",
	".json":  "application/json",
	".html":  "text/html",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".map":   "application/json",
	".txt":   "text/plain",
}

// syntheticDist builds a dist directory the way the release build does:
// the committed placeholder, plus web/public copied to the root, plus a hashed
// asset under assets/.
func syntheticDist(t *testing.T) string {
	t.Helper()
	dist := t.TempDir()

	placeholder, err := os.ReadFile(filepath.Join("..", "webui", "dist", "index.html"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dist, "index.html"), placeholder, 0o600))

	publicDir := filepath.Join("..", "..", "web", "public")
	n := 0
	require.NoError(t, filepath.WalkDir(publicDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(publicDir, p)
		require.NoError(t, err)
		data, err := os.ReadFile(p)
		require.NoError(t, err)
		dst := filepath.Join(dist, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o750))
		require.NoError(t, os.WriteFile(dst, data, 0o600))
		n++
		return nil
	}))
	require.Positive(t, n, "web/public must not be empty: it holds the fonts the SPA loads")

	require.NoError(t, os.MkdirAll(filepath.Join(dist, "assets"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dist, "assets", "index-abc123.js"), []byte("console.log(1)"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dist, "assets", "index-abc123.css"), []byte("body{}"), 0o600))
	return dist
}

func staticRouter(fsys http.FileSystem) http.Handler {
	r := chi.NewRouter()
	registerWebUI(r, fsys)
	return r
}

// assertEveryFileServed walks root and requests each file through h.
func assertEveryFileServed(t *testing.T, root fs.FS, h http.Handler) {
	t.Helper()
	seen := 0
	require.NoError(t, fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		seen++
		want, err := fs.ReadFile(root, p)
		require.NoError(t, err)

		url := "/" + p
		if p == "index.html" {
			url = "/" // http.FileServer redirects /index.html to ./, the shell is served at /
		}
		ext := strings.ToLower(path.Ext(p))
		wantType, known := wantContentTypes[ext]
		require.Truef(t, known, "%s: extension %q has no expected Content-Type; add it to wantContentTypes", p, ext)

		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, url, nil))
			if !assert.Equalf(t, http.StatusOK, rec.Code, "%s %s", method, url) {
				continue
			}
			mt, _, err := mime.ParseMediaType(rec.Header().Get("Content-Type"))
			require.NoErrorf(t, err, "%s %s Content-Type %q", method, url, rec.Header().Get("Content-Type"))
			assert.Equalf(t, wantType, mt, "%s %s Content-Type", method, url)
			if method == http.MethodGet && p != "index.html" {
				assert.Truef(t, bytes.Equal(want, rec.Body.Bytes()), "%s: body is not the file's own bytes (SPA shell served instead?)", url)
			}
		}
		return nil
	}))
	require.Positive(t, seen, "walked no files: the test would be vacuous")
}

func TestWebUIServesEveryDistFile(t *testing.T) {
	dist := syntheticDist(t)

	t.Run("on-disk", func(t *testing.T) {
		assertEveryFileServed(t, os.DirFS(dist), staticRouter(http.Dir(dist)))
	})
	t.Run("embedded-style-fs", func(t *testing.T) {
		assertEveryFileServed(t, os.DirFS(dist), staticRouter(http.FS(os.DirFS(dist))))
	})
	t.Run("real-embedded", func(t *testing.T) {
		assertEveryFileServed(t, webui.FS(), staticRouter(webui.HTTPFS()))
	})
}

func TestWebUIFontsAreNotTheSPAShell(t *testing.T) {
	dist := syntheticDist(t)
	for name, fsys := range map[string]http.FileSystem{
		"on-disk":  http.Dir(dist),
		"embedded": http.FS(os.DirFS(dist)),
	} {
		t.Run(name, func(t *testing.T) {
			h := staticRouter(fsys)
			for _, f := range []string{"/fonts/inter.woff2", "/fonts/jetbrains-mono.woff2"} {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, f, nil))
				require.Equal(t, http.StatusOK, rec.Code, f)
				assert.Equal(t, "font/woff2", rec.Header().Get("Content-Type"), f)
				assert.NotContains(t, rec.Header().Get("Content-Type"), "text/html", f)
				assert.Equal(t, "wOF2", rec.Body.String()[:4], "%s: not a woff2 file", f)
				assert.NotEmpty(t, rec.Header().Get("Cache-Control"), "%s: cache headers like /assets", f)
			}

			// Read-only like /assets: a mutating method is a 405, never the file.
			for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(m, "/fonts/inter.woff2", nil))
				assert.Equalf(t, http.StatusMethodNotAllowed, rec.Code, "%s /fonts/inter.woff2", m)
			}

			// No directory listing. (Bare /fonts without the slash is an unknown client
			// route and gets the SPA shell, exactly like bare /assets: not a listing.)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fonts/", nil))
			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.NotContains(t, rec.Body.String(), "inter.woff2", "GET /fonts/ lists the directory")
			assert.NotContains(t, rec.Header().Get("Content-Type"), "text/html")

			// A missing font is a JSON 404, not the SPA shell.
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fonts/nope.woff2", nil))
			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.NotContains(t, rec.Header().Get("Content-Type"), "text/html")
		})
	}
}

// Through the whole production router (NewRouter, security headers and all), with
// the build on disk the way a Docker or pilot install mounts it.
func TestWebUIFontsThroughNewRouter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dist := syntheticDist(t)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.HTTP.WebAssetsPath = dist
	router, err := NewRouter(cfg, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fonts/inter.woff2")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "font/woff2", resp.Header.Get("Content-Type"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "wOF2", string(body[:4]))
}
