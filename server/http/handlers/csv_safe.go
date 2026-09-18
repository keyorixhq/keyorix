package handlers

import "github.com/keyorixhq/keyorix/internal/csvsafe"

// csvSafe neutralises spreadsheet formula injection (CWE-1236) in a CSV cell. It delegates to the
// shared internal/csvsafe leaf so every layer uses ONE implementation of the neutralisation logic
// instead of carrying its own copy. Kept as a package-local name (a thin, drift-free forwarder) so
// the CSV export handlers and the csv-writer completeness guard keep the csvSafe symbol. Apply it
// to any user-controlled field (secret names, usernames, descriptions) written to a CSV export.
func csvSafe(s string) string { return csvsafe.Neutralize(s) }
