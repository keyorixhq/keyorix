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

// APIVersion is the server's REST API version (ADR-108 PR 0's version-skew mechanism,
// docs/cli-split-inventory.md §5). Unlike Version/Commit above, it is NOT derived from the
// build -- it is a small, explicit compatibility number that only changes on a breaking
// change to the REST contract, so a thin CLI can compare itself against it before trusting
// any response shape. Bump it by hand when a change would break an older CLI.
const APIVersion = 1
