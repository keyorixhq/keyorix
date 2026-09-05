package connect

// KnownTypes is the exhaustive set of recognized ConnectorConfig.Type values —
// the single source of truth for "what is a valid Keyorix Connect connector
// type" (#1476). internal/config.Validate() checks every configured
// connector's Type against this list (validateConnectTypes,
// internal/config/config.go) so an unrecognized type fails boot instead of
// being silently skipped — the same fail-open shape ADR-082 closed for a
// missing/invalid connector scope. server/main.go's initializeCoreService
// still dispatches on a literal switch (each type needs a different
// constructor call, some with type-specific side effects — e.g. the
// gcp-secret-manager case's defensive project_id Fatal (config validation already
// requires it), the vault case's token TTL check — that don't reduce to a uniform
// map[string]func lookup), but
// server/connector_type_registry_test.go asserts that switch's case set is
// always exactly this list, so the two cannot silently drift apart.
var KnownTypes = []string{
	"aws-secrets-manager",
	"gcp-secret-manager",
	"azure-key-vault",
	"vault",
}
