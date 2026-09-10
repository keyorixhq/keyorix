// Package configs embeds the shipped configuration template so that
// `keyorix system init` is self-contained: a binary on a user's $PATH has no
// reason to be run from a directory containing repo files, and reading the
// template from the caller's cwd meant `system init` failed on every clean
// checkout (found by dress rehearsal, 2026-09-10).
//
// keyorix.yaml.tpl stays here, where operators expect to find and edit it —
// this file only makes it reachable from the binary. Do not duplicate it.
package configs

import _ "embed"

//go:embed keyorix.yaml.tpl
var DefaultConfigTemplate []byte
