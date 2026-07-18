// Package webui embeds the built web dashboard so a single keyorix-server binary
// can serve the UI with no separate web container — the air-gap "one file" deploy.
//
// dist/ holds a committed placeholder index.html so the repository always
// compiles. A release build replaces dist/ with the real keyorix-web output
// before compiling (see `make build-ui`), embedding the full SPA. Everything
// under dist/ except the placeholder is gitignored, so build artifacts are never
// committed.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// fsSub is the function used to create a sub-FS. It exists as a variable so
// tests can replace it to exercise the error-fallback branch of FS().
var fsSub = fs.Sub

// FS returns the embedded web build rooted at dist/.
func FS() fs.FS {
	sub, err := fsSub(distFS, "dist")
	if err != nil {
		return distFS // dist is always present (committed placeholder); stay non-nil
	}
	return sub
}

// HTTPFS returns the embedded build as an http.FileSystem.
func HTTPFS() http.FileSystem { return http.FS(FS()) }

// HasRealBuild reports whether a real web build (not just the placeholder) is
// embedded — detected by the Vite assets directory. Used only for a startup log.
func HasRealBuild() bool {
	_, err := fs.Stat(FS(), "assets")
	return err == nil
}
