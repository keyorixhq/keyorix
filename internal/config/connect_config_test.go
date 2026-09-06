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

// TestValidateConnectGCPProjectID covers the confused-deputy gap closed by
// requiring project_id on every "gcp-secret-manager" connector: unlike Vault/Azure's
// Address (the connector's own tenant boundary), a GCP ref carries its own project
// ID, so an unset project_id would let a caller reach any GCP project the ambient
// ADC identity can access, regardless of the connector's Keyorix-side scope. Mirrors
// TestValidateConnectScopes/TestValidateConnectTypes's own structure and
// aggregation-assertion style. This test is RED against the pre-fix behavior (an
// unset project_id only logged a startup warning in server/main.go and booted
// fine) and GREEN once validateConnectGCPProjectID is wired into Config.Validate().
func TestValidateConnectGCPProjectID(t *testing.T) {
	tests := []struct {
		name      string
		cc        ConnectConfig
		wantErr   bool
		wantNames []string
	}{
		{
			name: "missing project_id, single gcp connector, fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "gcp1", Type: "gcp-secret-manager", Scope: "platform"},
			}},
			wantErr:   true,
			wantNames: []string{"gcp1"},
		},
		{
			name: "missing project_id, multiple gcp connectors, aggregated in one error",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "gcp1", Type: "gcp-secret-manager", Scope: "platform"},
				{Name: "gcp2", Type: "gcp-secret-manager", Scope: "platform"},
				{Name: "gcp3", Type: "gcp-secret-manager", Scope: "platform", ProjectID: "my-proj"}, // valid — must not appear
			}},
			wantErr:   true,
			wantNames: []string{"gcp1", "gcp2"},
		},
		{
			name: "non-gcp connector types are never checked",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws", Type: "aws-secrets-manager", Scope: "platform"},
				{Name: "azure", Type: "azure-key-vault", Scope: "platform"},
				{Name: "vault", Type: "vault", Scope: "platform"},
			}},
			wantErr: false,
		},
		{
			name:    "no connectors is valid",
			cc:      ConnectConfig{},
			wantErr: false,
		},
		{
			name: "gcp connector with project_id set is valid",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "gcp", Type: "gcp-secret-manager", Scope: "platform", ProjectID: "my-proj"},
			}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnectGCPProjectID(tt.cc)
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

// TestValidate_ConnectGCPProjectIDWired confirms Config.Validate() itself surfaces
// a missing gcp-secret-manager project_id — not just the unexported helper in
// isolation — so the boot path (server/main.go's cfg.Validate() call) actually
// enforces the requirement.
func TestValidate_ConnectGCPProjectIDWired(t *testing.T) {
	c := &Config{
		Storage: StorageConfig{Type: "local", Database: DatabaseConfig{Path: "/tmp/keyorix-connect-gcp-projectid-test.db"}},
		Connect: ConnectConfig{Connectors: []ConnectorConfig{
			{Name: "unbound-gcp", Type: "gcp-secret-manager", Scope: "platform"},
		}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unbound-gcp")
	assert.Contains(t, err.Error(), "project_id")
}

// TestValidateConnectAWSAccountID covers the AWS sibling of
// TestValidateConnectGCPProjectID — but account_id is deliberately OPTIONAL, not
// mandatory (see ConnectorConfig.AccountID's own doc comment for the risk-shape
// reason): a missing account_id must NOT fail boot, only a malformed one (not
// exactly 12 digits) does. Mirrors TestValidateConnectGCPProjectID's own structure
// and aggregation-assertion style.
func TestValidateConnectAWSAccountID(t *testing.T) {
	tests := []struct {
		name      string
		cc        ConnectConfig
		wantErr   bool
		wantNames []string
	}{
		{
			name: "missing account_id is valid -- optional, unlike GCP's project_id",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws1", Type: "aws-secrets-manager", Scope: "platform"},
			}},
			wantErr: false,
		},
		{
			name: "malformed account_id (not 12 digits), single connector, fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws1", Type: "aws-secrets-manager", Scope: "platform", AccountID: "12345"},
			}},
			wantErr:   true,
			wantNames: []string{"aws1"},
		},
		{
			name: "non-numeric account_id fails boot",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws1", Type: "aws-secrets-manager", Scope: "platform", AccountID: "not-an-account-id"},
			}},
			wantErr:   true,
			wantNames: []string{"aws1"},
		},
		{
			name: "malformed account_id, multiple connectors, aggregated in one error",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws1", Type: "aws-secrets-manager", Scope: "platform", AccountID: "bad"},
				{Name: "aws2", Type: "aws-secrets-manager", Scope: "platform", AccountID: "also-bad"},
				{Name: "aws3", Type: "aws-secrets-manager", Scope: "platform", AccountID: "123456789012"}, // valid — must not appear
			}},
			wantErr:   true,
			wantNames: []string{"aws1", "aws2"},
		},
		{
			name: "non-aws connector types are never checked",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "gcp", Type: "gcp-secret-manager", Scope: "platform", ProjectID: "my-proj"},
				{Name: "azure", Type: "azure-key-vault", Scope: "platform"},
				{Name: "vault", Type: "vault", Scope: "platform"},
			}},
			wantErr: false,
		},
		{
			name:    "no connectors is valid",
			cc:      ConnectConfig{},
			wantErr: false,
		},
		{
			name: "aws connector with well-formed account_id is valid",
			cc: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "aws", Type: "aws-secrets-manager", Scope: "platform", AccountID: "123456789012"},
			}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnectAWSAccountID(tt.cc)
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

// TestValidate_ConnectAWSAccountIDWired confirms Config.Validate() itself surfaces
// a malformed aws-secrets-manager account_id — not just the unexported helper in
// isolation — so the boot path (server/main.go's cfg.Validate() call) actually
// enforces the format check. Also confirms the converse: a missing account_id
// (the common, still-supported case) does NOT fail Validate() — account_id is
// optional, unlike gcp-secret-manager's project_id.
func TestValidate_ConnectAWSAccountIDWired(t *testing.T) {
	t.Run("malformed account_id fails Validate()", func(t *testing.T) {
		c := &Config{
			Storage: StorageConfig{Type: "local", Database: DatabaseConfig{Path: "/tmp/keyorix-connect-aws-accountid-test.db"}},
			Connect: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "malformed-aws", Type: "aws-secrets-manager", Scope: "platform", AccountID: "not-12-digits"},
			}},
		}
		err := c.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed-aws")
		assert.Contains(t, err.Error(), "account_id")
	})

	t.Run("missing account_id does not fail Validate()", func(t *testing.T) {
		c := &Config{
			Storage: StorageConfig{Type: "local", Database: DatabaseConfig{Path: "/tmp/keyorix-connect-aws-accountid-test2.db"}},
			Connect: ConnectConfig{Connectors: []ConnectorConfig{
				{Name: "unpinned-aws", Type: "aws-secrets-manager", Scope: "platform"},
			}},
		}
		require.NoError(t, c.Validate())
	})
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
