package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #4374: the operator's transport policy (dynamic_secrets.insecure_allow_plaintext_
// dynamic_secret_transport) covers postgres and mysql admin_dsns. A new or edited
// admin_dsn whose connection does not verify the server certificate is refused when
// it is saved, so the admin gets the error at once; one stored before the upgrade
// keeps issuing during the soft period (dsn.StoredSQLTransportGrace) with an audit
// event on every issue (dynamic_secrets_sql_transport_grace_test.go). Driven through
// the real engine factory, as server/main.go wires it. This file uses only what main
// already had, so it is the red/green proof of the save-time check.

func newSQLTransportCore(t *testing.T, allowInsecure bool) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	c, db, _, _ := newDynamicTestCore(t)
	c.SetDynamicAllowPrivateTargets(true) // the fake target sits on loopback
	c.SetDynamicAllowInsecureTransport(allowInsecure)
	c.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, true, allowInsecure) })
	return c, db
}

func createSQLConfig(c *KeyorixCore, name, backend, adminDSN string) (*models.DynamicSecretConfig, error) {
	return c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: name, ProjectID: 1, EnvironmentID: 2, BackendType: backend, AdminDSN: adminDSN,
		DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: testAdminActorID,
	})
}

var sqlTransportRefusals = []struct{ name, backend, dsn, option string }{
	{"postgres disable", "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=disable", "sslmode=disable"},
	{"postgres allow", "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=allow", "sslmode=allow"},
	{"postgres prefer", "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=prefer", "sslmode=prefer"},
	{"postgres require", "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=require", "sslmode=require"},
	{"postgres sslmode not set", "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app", "sslmode=prefer"},
	{"postgres keyword form", "postgres", "host=127.0.0.1 user=admin password=s3cret dbname=app sslmode=require", "sslmode=require"},
	{"mysql tls=false", "mysql", "admin:s3cret@tcp(127.0.0.1:3306)/app?tls=false", "tls=false"},
	{"mysql tls not set", "mysql", "admin:s3cret@tcp(127.0.0.1:3306)/app", "tls=false"},
	{"mysql skip-verify", "mysql", "admin:s3cret@tcp(127.0.0.1:3306)/app?tls=skip-verify", "tls=skip-verify"},
	{"mysql preferred", "mysql", "admin:s3cret@tcp(127.0.0.1:3306)/app?tls=preferred", "tls=preferred"},
	{"mysql plaintext fallback", "mysql", "admin:s3cret@tcp(127.0.0.1:3306)/app?tls=true&allowFallbackToPlaintext=true", "allowFallbackToPlaintext=true"},
}

func TestDynamicSecrets_CreateConfig_RefusesSQLTransportThatDoesNotVerify(t *testing.T) {
	t.Parallel()
	for _, tc := range sqlTransportRefusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, db := newSQLTransportCore(t, false)
			_, err := createSQLConfig(c, "weak", tc.backend, tc.dsn)
			fe, ok := errors.AsType[*dsn.ForbiddenOptionError](err)
			require.True(t, ok, "want a transport refusal, got %v", err)
			assert.Equal(t, tc.option, fe.Option)
			assert.Contains(t, err.Error(), "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport")
			assert.NotContains(t, err.Error(), "s3cret")
			var n int64
			require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&n).Error)
			assert.Zero(t, n, "nothing is stored")
		})
	}
}

func TestDynamicSecrets_CreateConfig_VerifyingSQLTransportAccepted(t *testing.T) {
	t.Parallel()
	c, _ := newSQLTransportCore(t, false)
	for i, d := range []struct{ backend, dsn string }{
		{"postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=verify-full"},
		{"mysql", "admin:s3cret@tcp(127.0.0.1:3306)/app?tls=true"},
	} {
		_, err := createSQLConfig(c, fmt.Sprintf("good-%d", i), d.backend, d.dsn)
		require.NoError(t, err, d.dsn)
	}
}

// An edited admin_dsn gets no soft period: refused at once, the stored one kept.
func TestDynamicSecrets_UpdateAdminDSN_RefusesSQLTransportThatDoesNotVerify(t *testing.T) {
	t.Parallel()
	for _, tc := range sqlTransportRefusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newSQLTransportCore(t, false)
			good := map[string]string{
				"postgres": "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=verify-full",
				"mysql":    "admin:s3cret@tcp(127.0.0.1:3306)/app?tls=true",
			}[tc.backend]
			cfg, err := createSQLConfig(c, "edit", tc.backend, good)
			require.NoError(t, err)
			_, err = c.UpdateDynamicSecretConfigAdminDSN(context.Background(), &UpdateDynamicSecretConfigAdminDSNRequest{
				ConfigID: cfg.ID, AdminDSN: tc.dsn, ActorID: testAdminActorID,
			})
			fe, ok := errors.AsType[*dsn.ForbiddenOptionError](err)
			require.True(t, ok, "want a transport refusal, got %v", err)
			assert.Equal(t, tc.option, fe.Option)
			stored, err := c.storage.GetDynamicSecretConfig(context.Background(), cfg.ID)
			require.NoError(t, err)
			plain, err := c.decryptAuthSecret(stored.AdminDSNEnc, stored.AdminDSNMeta, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
			require.NoError(t, err)
			assert.Equal(t, good, plain, "the stored admin_dsn is unchanged")
		})
	}
}

// With the operator's flag the save goes through and is audited, naming the
// config and option, never the DSN.
func TestDynamicSecrets_CreateConfig_OperatorFlagAllowsAndAudits(t *testing.T) {
	t.Parallel()
	c, db := newSQLTransportCore(t, true)
	_, err := createSQLConfig(c, "flagged", "postgres", "postgres://admin:s3cret@127.0.0.1:5432/app?sslmode=require")
	require.NoError(t, err)
	descs := auditDescriptions(t, db, "dynamic_secret.config_insecure_transport")
	require.Len(t, descs, 1)
	assert.Contains(t, descs[0], "sslmode=require")
	assert.Contains(t, descs[0], `"flagged"`)
	assert.Contains(t, descs[0], "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport")
	assert.NotContains(t, descs[0], "s3cret")
	assert.NotContains(t, descs[0], "127.0.0.1")
}
