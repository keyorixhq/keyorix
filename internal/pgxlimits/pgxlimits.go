// Package pgxlimits holds the resource ceilings keyorix applies to a pgx
// connection toward a PostgreSQL server it does not trust.
//
// It is a leaf package (pgx only) so both the production dial path
// (internal/dynamic.connectPostgres) and the fuzz harness
// (fuzz/thirdparty/pgx) take the SAME value from one place: the harness then
// fuzzes the configuration that ships, and the value cannot drift between them.
package pgxlimits

import "github.com/jackc/pgx/v5"

// MaxProtocolMessageBodyLen bounds the body length of any single message the
// server may send. pgx sizes its read buffer from the length the server CLAIMS
// before a body byte arrives; its own default ceiling is ~1 GiB (PostgreSQL's
// limit). A 5-byte header from a rogue server was measured to cost ~775 MB of
// allocation per connection and ~1.5 GB peak RSS, enough to OOM-kill a 512 MiB
// container within three dials.
//
// The engines using this run DDL and role statements whose replies are a few
// hundred bytes, so 16 MiB leaves a very wide margin for a legitimate row or
// notice. It is a ceiling on ONE message, not on a result set.
const MaxProtocolMessageBodyLen = 16 << 20

// Apply sets the bound on cfg. Every connection built from an admin_dsn must go
// through it (internal/dynamic enforces that with
// TestEveryPgxConnectInDynamicUsesTheBoundedConfig).
func Apply(cfg *pgx.ConnConfig) {
	cfg.MaxProtocolMessageBodyLen = MaxProtocolMessageBodyLen
}
