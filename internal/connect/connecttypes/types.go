// Package connecttypes holds the list of recognized Keyorix Connect connector
// type names. It is a leaf (standard library only) so that internal/config can
// validate connector types without importing internal/connect, which links
// every cloud SDK (AWS, Azure, GCP, Vault). Before this split, that one import
// pulled the SDKs into config, into internal/i18n (which reads the locale from
// config), and into every package that translates an error message.
package connecttypes

// KnownTypes is the exhaustive set of recognized ConnectorConfig.Type values —
// the single source of truth for "what is a valid Keyorix Connect connector
// type" (#1476). internal/config.Validate() checks every configured
// connector's Type against this list (validateConnectTypes,
// internal/config/config.go) so an unrecognized type fails boot instead of
// being silently skipped — the same fail-open shape ADR-082 closed for a
// missing/invalid connector scope. server/main.go's initializeCoreService
// still dispatches on a literal switch, and
// server/connector_type_registry_test.go asserts that switch's case set is
// always exactly this list, so the two cannot silently drift apart.
var KnownTypes = []string{
	"aws-secrets-manager",
	"gcp-secret-manager",
	"azure-key-vault",
	"vault",
}
