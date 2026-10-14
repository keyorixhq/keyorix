package config

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestValidatePooler(t *testing.T) {
	for _, tc := range []struct {
		storageType, pooler, wantErr string
	}{
		{"postgres", "", ""},
		{"postgres", "none", ""},
		{"postgres", "pgbouncer-session", ""},
		{"postgresql", "pgbouncer-transaction", ""},
		{"local", "", ""},
		{"local", "none", ""},
		{"local", "pgbouncer-transaction", "applies only to storage.type postgres"},
		{"remote", "pgbouncer-session", "applies only to storage.type postgres"},
		{"postgres", "pgbouncer", "is not supported"},
		{"postgres", "PgBouncer-Transaction", "is not supported"},
		{"postgres", "pgbouncer-statement", "is not supported"},
	} {
		err := validatePooler(tc.storageType, &DatabaseConfig{Pooler: tc.pooler})
		if tc.wantErr == "" {
			require.NoError(t, err, "%s/%q", tc.storageType, tc.pooler)
			continue
		}
		require.Error(t, err, "%s/%q", tc.storageType, tc.pooler)
		require.True(t, strings.Contains(err.Error(), tc.wantErr), "%v", err)
	}
}

// TestValidate_RefusesUnknownPooler: the refusal is reached through Validate.
func TestValidate_RefusesUnknownPooler(t *testing.T) {
	c := &Config{}
	c.Storage.Type = "postgres"
	c.Storage.Database.DSN = "host=db user=keyorix dbname=keyorix sslmode=require"
	c.Storage.Database.Pooler = "pgbouncer-statement"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "storage.database.pooler")
}

// TestResolvePostgresConnConfig_PoolerExecMode: only pgbouncer-transaction
// changes the pgx execution mode; every other value keeps pgx's default
// (cached prepared statements).
func TestResolvePostgresConnConfig_PoolerExecMode(t *testing.T) {
	for pooler, want := range map[string]pgx.QueryExecMode{
		"":                      pgx.QueryExecModeCacheStatement,
		"none":                  pgx.QueryExecModeCacheStatement,
		"pgbouncer-session":     pgx.QueryExecModeCacheStatement,
		"pgbouncer-transaction": pgx.QueryExecModeExec,
	} {
		d := &DatabaseConfig{DSN: "host=127.0.0.1 user=keyorix dbname=keyorix sslmode=disable", Pooler: pooler}
		cc, err := ResolvePostgresConnConfig(d)
		require.NoError(t, err, pooler)
		require.Equal(t, want, cc.DefaultQueryExecMode, pooler)
		if want == pgx.QueryExecModeExec {
			require.Zero(t, cc.StatementCacheCapacity, pooler)
			require.Zero(t, cc.DescriptionCacheCapacity, pooler)
		} else {
			require.NotZero(t, cc.StatementCacheCapacity, pooler)
		}
	}
}
