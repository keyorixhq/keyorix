package common

import "github.com/keyorixhq/keyorix/internal/csvsafe"

// CSVSafe neutralises spreadsheet formula injection (CWE-1236) in a CSV cell. It delegates to the
// shared internal/csvsafe leaf so every layer uses ONE implementation of the neutralisation logic
// instead of carrying its own copy. Kept as a package-local name (a thin, drift-free forwarder) so
// existing CLI callers and the csv-writer completeness guard keep the CSVSafe symbol. Apply it to
// any server-supplied free-text field written to a CSV a CLI command emits.
func CSVSafe(s string) string { return csvsafe.Neutralize(s) }
