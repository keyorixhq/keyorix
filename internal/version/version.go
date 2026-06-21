// Package version holds the build identity of the Keyorix server and CLI, injected at
// build time via -ldflags -X (see the Makefile). The defaults apply to a plain
// `go build` / `go run` (a developer build); release binaries built via `make release
// VERSION=<tag>` carry the real tag and commit.
package version

var (
	// Version is the release version (a git tag like "v0.68.0"), or "dev" for an
	// un-injected build.
	Version = "dev"
	// Commit is the short git commit the binary was built from, or "none".
	Commit = "none"
)
