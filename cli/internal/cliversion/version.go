// Package cliversion holds the build identity of the thin CLI, injected at build time via
// -ldflags -X (see the root Makefile's cli-build target). Mirrors internal/version's shape
// on the server side, but is a wholly separate copy: this module must not import anything
// from the main module (ADR-108 Decision A, enforced by internal/depguard).
package cliversion

// Version is this CLI build's own release semver (e.g. "1.4.2"), or "dev" for an
// un-injected build.
var Version = "dev"

// TargetAPIVersion is the server REST API version (the server's internal/version.APIVersion)
// this CLI build was written against. Bumped by hand whenever the CLI is updated to handle a
// breaking change introduced on a new server api_version -- see internal/skew.Check's doc
// comment for how this and Version are used together to classify version skew.
const TargetAPIVersion = 1
