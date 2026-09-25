// Package cloudentry is the common shape awssource, azuresource, and gcpsource all produce —
// mirroring vaultsource.Entry/Skipped, but shared across the three cloud providers instead of
// each hand-rolling its own, since the mapping into plan.Entry (cmd/cloud_common.go) and the
// intra-batch name-collision check are identical for all three.
package cloudentry

// Entry is one secret (or, when Field is set, one exploded JSON field of a secret) a cloud
// source found, not yet mapped to a Keyorix name (cmd/cloud_common.go does that, the same way
// cmd/vault.go derives a Keyorix name from a vaultsource.Entry).
type Entry struct {
	// RawName is the provider's own secret name (AWS secret name, Azure secret name, GCP secret
	// short name) — unsanitized.
	RawName string
	// Field is the exploded JSON object key when --split-json produced this entry from a
	// multi-key JSON secret; "" for a whole-value import.
	Field string
	Value string
	// Metadata is provider-native, unprefixed (e.g. a description) — plan.Apply's Create branch
	// prefixes it with SourceKind + "." itself, matching vaultsource's "vault." convention.
	Metadata map[string]string
	// Version / CreatedAt are the provider's own version identifier and creation time for this
	// value, when the provider has one — empty otherwise. Mirrors vaultsource.Entry's
	// Version/CreatedAt (Andrei's 2026-09-25 "record the version even though only latest is
	// imported" decision, docs/design-keyorix-migrate.md).
	Version   string
	CreatedAt string
	// Locator is a human-readable source path for the report (e.g.
	// "aws-secrets-manager:us-east-1/team-a/db-password") — never used for identity.
	Locator string
}

// Skipped is one provider secret a source found but did not import, with a human-readable
// reason — mirrors vaultsource.Skipped.
type Skipped struct {
	Locator string
	Reason  string
}
