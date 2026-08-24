package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateConnectScopes covers ADR-082 §B/§C boot validation: missing/
// unrecognized scope, the project/platform contradiction checks, and valid
// project/platform entries. There is no escape hatch (amended — the original
// connect.allow_unscoped flag was removed: it let the server boot, but an
// unscoped connector still denied on every read, so it never restored actual
// usability). Each failure case asserts the aggregated error names every
// offending connector, not just the first one found.
func TestValidateConnectScopes(t *testing.T) {
	tests := []struct {
		name      string
		cc        ConnectConfig
		wantErr   bool
		wantNames []string // every name that must appear in the error message
	}{
		{
			name: "missing scope, single connector, fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "c1", Type: "vault"},
			}},
			wantErr:   true,
			wantNames: []string{"c1"},
		},
		{
			name: "missing scope, multiple connectors, aggregated in one error",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "c1", Type: "vault"},
				{Name: "c2", Type: "aws-secrets-manager"},
				{Name: "c3", Type: "azure-key-vault", Scope: "platform"}, // valid — must not appear
			}},
			wantErr:   true,
			wantNames: []string{"c1", "c2"},
		},
		{
			name: "unrecognized scope value fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "typo", Type: "vault", Scope: "projects"},
			}},
			wantErr:   true,
			wantNames: []string{"typo"},
		},
		{
			name: "unrecognized scope, multiple connectors, aggregated",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "bad1", Type: "vault", Scope: "Project"}, // wrong case
				{Name: "bad2", Type: "vault", Scope: "org"},
			}},
			wantErr:   true,
			wantNames: []string{"bad1", "bad2"},
		},
		{
			name: "scope project without project name fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "noproj", Type: "vault", Scope: "project"},
			}},
			wantErr:   true,
			wantNames: []string{"noproj"},
		},
		{
			name: "scope project without project name, multiple, aggregated",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "noproj1", Type: "vault", Scope: "project"},
				{Name: "noproj2", Type: "aws-secrets-manager", Scope: "project"},
				{Name: "ok", Type: "vault", Scope: "project", Project: "payments"}, // valid — must not appear
			}},
			wantErr:   true,
			wantNames: []string{"noproj1", "noproj2"},
		},
		{
			name: "scope platform with project set fails boot (contradiction)",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "bad-platform", Type: "vault", Scope: "platform", Project: "payments"},
			}},
			wantErr:   true,
			wantNames: []string{"bad-platform"},
		},
		{
			name: "scope platform with project set, multiple, aggregated",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "bad1", Type: "vault", Scope: "platform", Project: "payments"},
				{Name: "bad2", Type: "aws-secrets-manager", Scope: "platform", Project: "billing"},
			}},
			wantErr:   true,
			wantNames: []string{"bad1", "bad2"},
		},
		{
			name:    "no connectors is valid",
			cc:      ConnectConfig{},
			wantErr: false,
		},
		{
			name: "valid project-scoped entry",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws", Type: "aws-secrets-manager", Scope: "project", Project: "payments"},
			}},
			wantErr: false,
		},
		{
			name: "valid platform-scoped entry, no project",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "shared-vault", Type: "vault", Scope: "platform"},
			}},
			wantErr: false,
		},
		{
			name: "mixed valid project and platform entries",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws", Type: "aws-secrets-manager", Scope: "project", Project: "payments"},
				{Name: "gcp", Type: "gcp-secret-manager", Scope: "project", Project: "billing"},
				{Name: "shared-vault", Type: "vault", Scope: "platform"},
			}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnectScopes(tt.cc)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, name := range tt.wantNames {
				assert.Contains(t, err.Error(), name, "error must name every offending connector")
			}
		})
	}
}

// TestValidateConnectScopes_ValidEntriesExcludedFromAggregation asserts that a
// validly-scoped connector never appears in another connector's failure
// message — the aggregation groups only the connectors that actually fail
// each check.
func TestValidateConnectScopes_ValidEntriesExcludedFromAggregation(t *testing.T) {
	cc := ConnectConfig{Connectors: []ConnectorConfig{
		{Name: "broken", Type: "vault"}, // missing scope
		{Name: "fine", Type: "vault", Scope: "platform"},
	}}
	err := validateConnectScopes(cc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")
	assert.NotContains(t, err.Error(), "fine")
}

// TestValidate_ConnectScopesWired confirms Config.Validate() itself surfaces
// a connector scope error — not just the unexported helper in isolation —
// so the boot path (server/main.go's cfg.Validate() call) actually enforces
// ADR-082 §C.
func TestValidate_ConnectScopesWired(t *testing.T) {
	// G80 follow-up (2026-08-24): storage.type: remote used to be a convenient way
	// to skip the local DB path requirement below, but Config.Validate now rejects
	// "remote" unconditionally (validateRemoteStorageNotServer) — that error would
	// surface here instead of the connect-scope error this test means to check.
	// "local" + a Database.Path satisfies the same requirement without tripping it.
	c := &Config{
		Storage: StorageConfig{Type: "local", Database: DatabaseConfig{Path: "/tmp/keyorix-connect-scopes-test.db"}},
		Connect: ConnectConfig{Connectors: []ConnectorConfig{
			{Name: "unscoped-connector", Type: "vault"},
		}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unscoped-connector")
}

// TestValidateConnectTypes covers #1476 boot validation: a connector's Type
// must be one of connect.KnownTypes. Mirrors TestValidateConnectScopes's own
// structure and aggregation-assertion style — every failure case asserts the
// aggregated error names every offending connector, not just the first.
func TestValidateConnectTypes(t *testing.T) {
	tests := []struct {
		name      string
		cc        ConnectConfig
		wantErr   bool
		wantNames []string // every name that must appear in the error message
	}{
		{
			name: "unrecognized type, single connector, fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "c1", Type: "aws-secrets-mangler", Scope: "platform"}, // typo
			}},
			wantErr:   true,
			wantNames: []string{"c1"},
		},
		{
			name: "unrecognized type, multiple connectors, aggregated in one error",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "c1", Type: "bogus-type-1", Scope: "platform"},
				{Name: "c2", Type: "bogus-type-2", Scope: "platform"},
				{Name: "c3", Type: "vault", Scope: "platform"}, // valid — must not appear
			}},
			wantErr:   true,
			wantNames: []string{"c1", "c2"},
		},
		{
			name: "empty type fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "no-type", Scope: "platform"},
			}},
			wantErr:   true,
			wantNames: []string{"no-type"},
		},
		{
			name:    "no connectors is valid",
			cc:      ConnectConfig{},
			wantErr: false,
		},
		{
			name: "every recognized type is valid",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws", Type: "aws-secrets-manager", Scope: "platform"},
				{Name: "gcp", Type: "gcp-secret-manager", Scope: "platform"},
				{Name: "azure", Type: "azure-key-vault", Scope: "platform"},
				{Name: "vault", Type: "vault", Scope: "platform"},
			}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnectTypes(tt.cc)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, name := range tt.wantNames {
				assert.Contains(t, err.Error(), name, "error must name every offending connector")
			}
		})
	}
}

// TestValidateConnectTypes_ValidEntriesExcludedFromAggregation mirrors
// TestValidateConnectScopes_ValidEntriesExcludedFromAggregation: a
// recognized-type connector never appears in another connector's failure
// message.
func TestValidateConnectTypes_ValidEntriesExcludedFromAggregation(t *testing.T) {
	cc := ConnectConfig{Connectors: []ConnectorConfig{
		{Name: "broken", Type: "bogus-type", Scope: "platform"},
		{Name: "fine", Type: "vault", Scope: "platform"},
	}}
	err := validateConnectTypes(cc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")
	assert.NotContains(t, err.Error(), "fine")
}

// TestValidate_ConnectTypesWired confirms Config.Validate() itself surfaces a
// connector type error — not just the unexported helper in isolation — so the
// boot path actually enforces #1476.
func TestValidate_ConnectTypesWired(t *testing.T) {
	// G80 follow-up (2026-08-24): see TestValidate_ConnectScopesWired's comment —
	// "remote" no longer skips validation cleanly, it's rejected outright now.
	c := &Config{
		Storage: StorageConfig{Type: "local", Database: DatabaseConfig{Path: "/tmp/keyorix-connect-types-test.db"}},
		Connect: ConnectConfig{Connectors: []ConnectorConfig{
			{Name: "mistyped-connector", Type: "aws-secrets-mangler", Scope: "platform"},
		}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mistyped-connector")
}

// TestValidate_ConnectTypesRunsBeforeScopes confirms validateConnectTypes runs
// before validateConnectScopes in Config.Validate() (see that function's own
// comment for why: an unrecognized type is more fundamental than a scope-shape
// issue on a connector Keyorix would never construct). A connector with BOTH
// an unrecognized type AND a missing scope must surface the type error, not
// the scope error.
func TestValidate_ConnectTypesRunsBeforeScopes(t *testing.T) {
	// G80 follow-up (2026-08-24): see TestValidate_ConnectScopesWired's comment —
	// "remote" no longer skips validation cleanly, it's rejected outright now.
	c := &Config{
		Storage: StorageConfig{Type: "local", Database: DatabaseConfig{Path: "/tmp/keyorix-connect-order-test.db"}},
		Connect: ConnectConfig{Connectors: []ConnectorConfig{
			{Name: "doubly-broken", Type: "bogus-type"}, // no Type match AND no Scope
		}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized type", "expected the type error to surface first, got: %v", err)
}
