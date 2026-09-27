// Package migrateversion holds the build identity of keyorix-migrate, injected at build
// time via -ldflags -X (see the root Makefile's release target). Mirrors cli/internal/
// cliversion's shape, but is a wholly separate copy: migrate/ is its own Go module with
// its own release cadence (ADR-108 "moved out, not dropped") and must not import from the
// main module or the CLI module.
package migrateversion

// Version is this keyorix-migrate build's own release semver (e.g. "0.95.1"), or "dev"
// for an un-injected build.
var Version = "dev"
