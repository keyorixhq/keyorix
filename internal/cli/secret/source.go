// source.go — live-source import: connect to a running Vault / AWS Secrets
// Manager / Azure Key Vault, enumerate its secrets, and feed them into the same
// import path the file importer uses (see import.go).
//
// Per-provider fetchers live in source_vault.go, source_aws.go, source_azure.go.
// Each returns []secretEntry; everything downstream (dry-run, project/env
// resolution, doImport) is shared with the file path.
package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Live-source flags. --source selects a provider instead of --file/--format;
// the two modes are mutually exclusive (enforced in runImport).
var (
	importSource    string // "" = file mode; otherwise "vault" | "aws" | "azure"
	importPrefix    string // optional namespace prepended to every imported name
	importNoExplode bool   // store a JSON-object value as one secret instead of exploding it

	// Vault (KV engine)
	vaultAddr      string
	vaultToken     string
	vaultMount     string
	vaultPath      string
	vaultKVVersion int

	// AWS Secrets Manager
	awsRegion string
	awsPrefix string

	// Azure Key Vault
	azureVaultURL string

	// GCP Secret Manager
	gcpProject string
	gcpPrefix  string
)

// sourceSkipCount tallies secrets a live-source provider (collectAzure,
// collectGCP) dropped before they ever became a secretEntry — e.g. a Key
// Vault secret with no accessible value, or a Secret Manager entry with no
// enabled version. Providers print each skip by name as it happens (never
// silent); this counter lets runImport fold the total into the same
// "imported N, skipped M" summary already used for destination-side skips
// (already-exists), so a source-side drop is never invisible in the final
// output either. Reset by fetchFromSource before each dispatch — safe as
// plain package state because exactly one import runs per CLI process.
// Tests that call collectAzure/collectGCP directly (bypassing
// fetchFromSource) must reset it themselves before asserting on it.
var sourceSkipCount int

// fetchFromSource dispatches to the live provider named by --source and returns
// the secrets it found, ready for the shared import path. The optional --prefix
// is applied uniformly here so each provider need not know about it.
func fetchFromSource(ctx context.Context, source string) ([]secretEntry, error) {
	var (
		entries []secretEntry
		err     error
	)
	sourceSkipCount = 0
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "vault":
		entries, err = fetchFromVault(ctx)
	case "aws":
		entries, err = fetchFromAWS(ctx)
	case "azure":
		entries, err = fetchFromAzure(ctx)
	case "gcp":
		entries, err = fetchFromGCP(ctx)
	default:
		return nil, fmt.Errorf("unknown source %q (supported: vault, aws, azure, gcp)", source)
	}
	if err != nil {
		return nil, err
	}
	if importPrefix != "" {
		for i := range entries {
			entries[i].Name = importPrefix + entries[i].Name
		}
	}
	return entries, nil
}

// explodeValue maps one source value to one or more secretEntry.
//
// If raw is a flat JSON object whose values are all scalars (string/number/bool)
// — the common shape for an AWS/Azure "key-value" secret — it explodes into one
// entry per field named "<baseName>-<key>", mirroring parseVault's multi-key
// handling (import_parsers.go). Otherwise (a plain string, or a JSON object with
// nested values) it is stored as a single secret. --no-explode forces the
// single-secret behaviour regardless of shape.
func explodeValue(baseName, raw string) []secretEntry { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	if !importNoExplode {
		if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "{") {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal([]byte(trimmed), &obj); err == nil && len(obj) > 0 {
				entries := make([]secretEntry, 0, len(obj))
				allScalar := true
				for k, v := range obj {
					val, scalar := jsonScalar(v)
					if !scalar {
						allScalar = false
						break
					}
					if k == "" || val == "" {
						continue
					}
					entries = append(entries, secretEntry{Name: sanitizeSecretName(baseName + "-" + k), Value: val})
				}
				if allScalar && len(entries) > 0 {
					return entries
				}
			}
		}
	}
	return []secretEntry{{Name: sanitizeSecretName(baseName), Value: raw}}
}

// jsonScalar reports whether a JSON value is a scalar (string/number/bool/null)
// and returns its string form. Objects and arrays return ("", false) so the
// caller can fall back to storing the whole value as one secret.
func jsonScalar(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true // JSON string — unquoted
	}
	t := strings.TrimSpace(string(raw))
	if t == "" {
		return "", false
	}
	switch t[0] {
	case '{', '[':
		return "", false // object/array — not a scalar
	default:
		return t, true // number, bool, or null literal
	}
}

// sanitizeName normalises a source path/key into a Keyorix secret name: path
// separators, spaces, and colons collapse to '-', repeated '-' collapse, and
// surrounding '-' are trimmed. Case is preserved (source names are often
// meaningful and case-sensitive).
func sanitizeSecretName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}
