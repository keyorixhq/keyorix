// Package credstore persists the thin CLI's credentials. ADR-108 PR 0 decision
// (Andrei, 2026-09-23, docs/cli-split-inventory.md §4): one storage mechanism only -- no
// set-remote/use-local, no CWD-relative config file, no separate "connections" list. The
// default is a plaintext file at 0600 in the user config dir; an OS-keychain-backed
// implementation of the same Store interface is a later option, not decided here.
package credstore

// Credentials is everything the CLI needs to reach a server: the base URL and a bearer
// token (a long-lived API key/PAT, not a short-lived session -- there is no refresh flow,
// matching today's CLI per docs/cli-split-inventory.md §4).
type Credentials struct {
	ServerURL string `yaml:"server_url"`
	Token     string `yaml:"token"`
}

// Store loads and saves Credentials. FileStore is the only implementation today; a future
// KeychainStore would implement this same interface with no caller-side change.
type Store interface {
	// Save persists c, replacing anything previously stored.
	Save(c Credentials) error
	// Load returns the stored credentials. It returns an error if none are stored, or if
	// the backing storage looks tampered with (e.g. a credentials file with permissions
	// wider than 0600) -- callers must treat that as "not logged in," not silently proceed
	// with whatever could be read.
	Load() (Credentials, error)
	// Clear removes any stored credentials. Clearing when none exist is not an error.
	Clear() error
}
