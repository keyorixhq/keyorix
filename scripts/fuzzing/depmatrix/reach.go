// reach.go — REACH class assignment for each dependency.
//
// REACH classes (from most to least severe):
//   - UNTRUSTED: a non-test package that imports this module is reachable from
//     an HTTP/gRPC handler, CLI input file, network client reading a remote
//     reply, or a parser of imported/backup/config data.
//   - TRUSTED-ONLY: only fed our own data (audit logs, local config, etc.);
//     no known attacker-controlled input can reach this module's call sites.
//   - TOOLING: only imported in build/test-time tooling or test files.
//   - UNUSED: no non-test, non-fuzz file in the repo imports this module.
//
// WHAT THIS DOES NOT DO:
//   - Does not follow transitive imports (1-hop only). A package classified as
//     TRUSTED-ONLY may transitively call an UNTRUSTED package; that is not
//     captured here.
//   - Does not evaluate Go build constraints; a file excluded by build tags
//     may still be counted as an importer.
//   - Does not consult runtime wiring (config flags, etc.); UNTRUSTED means
//     the import graph reaches an attacker-influenced call site, not that every
//     deployment exposes it.
package main

import (
	"sort"
	"strings"
)

// reachClass is one of the four REACH values.
type reachClass string

const (
	reachUntrusted   reachClass = "UNTRUSTED"
	reachTrustedOnly reachClass = "TRUSTED-ONLY"
	reachTooling     reachClass = "TOOLING"
	reachUnused      reachClass = "UNUSED"
)

// classifyReach returns the REACH class for a module given the set of non-test
// packages that import it.
//
// Classification logic (in priority order):
//  1. If any importer is an "untrusted-input" package → UNTRUSTED.
//  2. If any importer is a "tooling" package (scripts/, tools/, devtools/, etc.) → TOOLING.
//  3. If there are no importers at all → UNUSED.
//  4. Otherwise → TRUSTED-ONLY.
func classifyReach(importingPkgs []string) reachClass {
	if len(importingPkgs) == 0 {
		return reachUnused
	}
	hasUntrusted := false
	allTooling := true
	for _, pkg := range importingPkgs {
		if isUntrustedPkg(pkg) {
			hasUntrusted = true
		}
		if !isToolingPkg(pkg) {
			allTooling = false
		}
	}
	if hasUntrusted {
		return reachUntrusted
	}
	if allTooling {
		return reachTooling
	}
	return reachTrustedOnly
}

// isUntrustedPkg returns true if packages under this prefix receive attacker-
// influenced input (HTTP/gRPC request bodies, CLI input files, remote backend
// replies, or imported/backup data).
//
// Package prefixes in this list were derived by tracing the main Keyorix server
// entrypoints (server/, internal/core/) through their direct dependencies. Any
// package prefix that appears in the production request-handling path is included.
func isUntrustedPkg(pkg string) bool {
	return matchesAny(pkg, untrustedPkgPrefixes)
}

// isToolingPkg returns true if the package is build/test-time tooling that
// is never part of the production binary.
func isToolingPkg(pkg string) bool {
	return matchesAny(pkg, toolingPkgPrefixes)
}

// untrustedPkgPrefixes is the set of package-path prefixes whose code runs
// in the request-handling path and may receive attacker-influenced inputs.
// Update when new entrypoints are added to the codebase.
var untrustedPkgPrefixes = []string{
	// HTTP/gRPC server and middleware
	"server",
	// Core business logic driven by server requests
	"internal/core",
	// Cryptographic operations on request data
	"internal/crypto",
	// External connector clients (AWS, Azure, GCP, Vault) called per request
	"internal/connect",
	// Dynamic secret engines (MySQL, Postgres, MongoDB, K8s, etc.)
	"internal/dynamic",
	// SAML parsing (untrusted IDP responses)
	"internal/saml",
	// OIDC token verification (untrusted issuer responses)
	"internal/oidcverify",
	// WebAuthn credential response parsing
	"internal/webauthnrp",
	// CLI command implementations (read user-provided input files)
	"cli/cmd",
	"cli/internal",
	// Public packages (bundleverify, licenseverify — parse external data)
	"pkg",
	// Backup archive parsing (externally-sourced backup files)
	"internal/backupfmt",
	// Migration from external sources (Vault, AWS SM, Azure KV)
	"migrate",
	// Storage layer (driven by handler requests)
	"internal/storage",
	// Encryption service (driven by handler requests)
	"internal/encryption",
	// Secret rotation (driven by scheduler, itself driven by API)
	"internal/rotation",
	// TLS reload (driven by server lifecycle)
	"internal/tlsreload",
	// Anomaly detection (fed by API request data)
	"internal/anomaly",
	// Notification channels (operator-configured, can receive external data)
	"internal/notify",
	// SCIM provisioning (receives external IdP data)
	"internal/scim",
	// Fuzz kit — not production, but its test helpers model untrusted input
	// flows; leave out (it is test-time only and would inflate FUZZ counts)
}

// toolingPkgPrefixes is the set of package-path prefixes that are build/test-
// time tooling and never part of the production binary.
var toolingPkgPrefixes = []string{
	"scripts",
	"tools",
	"devtools",
	"cmd/statemapgen",
	"cmd/validate-translations",
	"cmd/authzmatrix",
}

// matchesAny returns true if pkg equals or is under one of the given prefixes.
func matchesAny(pkg string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
			return true
		}
	}
	return false
}

// topImporters returns up to n importing packages, sorted alphabetically and
// de-duplicated, preferring shorter (more authoritative) package paths.
func topImporters(pkgs []string, n int) []string {
	sorted := make([]string, len(pkgs))
	copy(sorted, pkgs)
	sort.Strings(sorted)
	// Deduplicate.
	out := sorted[:0]
	for i, p := range sorted {
		if i == 0 || p != sorted[i-1] {
			out = append(out, p)
		}
	}
	if len(out) > n {
		return out[:n]
	}
	return out
}
