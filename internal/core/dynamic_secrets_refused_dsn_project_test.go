// dynamic_secrets_refused_dsn_project_test.go — DYNAMIC-ADMIN-DSN-1 item 2: an
// operator finds, per project, the configs whose stored admin_dsn names a
// refused option (the ones UpdateDynamicSecretConfigAdminDSN fixes). SQLite and,
// with KEYORIX_TEST_PG_DSN, PostgreSQL.
package core

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

func TestDynamicSecrets_ListProjectRefusedAdminDSN_FindsWhatUpdateFixes(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		legacy := w.legacyConfig("adsn-list-legacy",
			"host=203.0.113.10 user=admin password="+adsnSecret+" sslrootcert=/etc/keyorix/private-ca.pem sslkey=/etc/keyorix/key.pem")
		w.legacyConfig("adsn-list-clean", adsnCleanDSN("app"))

		rep, err := w.core.ListProjectConfigsWithRefusedAdminDSN(w.ctx, w.f.adminID, w.f.projectID)
		require.NoError(t, err)
		require.Len(t, rep.Configs, 1, "only the legacy config: %+v", rep.Configs)
		got := rep.Configs[0]
		assert.Equal(t, legacy.ID, got.ConfigID)
		assert.Equal(t, "adsn-list-legacy", got.Name)
		assert.Equal(t, w.f.projectID, got.ProjectID)
		assert.Equal(t, w.f.envID, got.EnvironmentID)
		assert.Equal(t, []string{"sslrootcert", "sslkey"}, got.Options, "every refused option, by name")
		assert.Zero(t, rep.Unreadable)
		assert.NotContains(t, fmt.Sprintf("%+v", rep), adsnSecret)
		assert.NotContains(t, fmt.Sprintf("%+v", rep), "/etc/keyorix", "option names only, never their values")

		_, err = w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{
			ConfigID: legacy.ID, AdminDSN: adsnCleanDSN("fixed"), ActorID: w.f.adminID,
		})
		require.NoError(t, err)
		rep, err = w.core.ListProjectConfigsWithRefusedAdminDSN(w.ctx, w.f.adminID, w.f.projectID)
		require.NoError(t, err)
		assert.Empty(t, rep.Configs, "nothing left to fix after the update")
	})
}

func TestDynamicSecrets_ListProjectRefusedAdminDSN_Gate(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		w.legacyConfig("adsn-list-gate", "host=203.0.113.10 user=admin password="+adsnSecret+" passfile=/root/.pgpass")
		_, err := w.core.ListProjectConfigsWithRefusedAdminDSN(w.ctx, w.developer.ID, w.f.projectID)
		require.ErrorIs(t, err, ErrPermissionDenied, "the report is derived from decrypted DSNs: admin authority only")
		_, err = w.core.ListProjectConfigsWithRefusedAdminDSN(w.ctx, w.f.adminID, 0)
		require.ErrorIs(t, err, ErrValidation)
	})
}

func TestRefusedLocalFileOptions_NamesEveryOption(t *testing.T) {
	t.Parallel()
	got := dsn.RefusedLocalFileOptions("mongodb",
		"mongodb://u:"+adsnSecret+"@db.example.com/?tls=true&tlsCAFile=/a.pem&tlsCertificateKeyFile=/b.pem&authMechanism=MONGODB-AWS&tlsCAFile=/c.pem")
	assert.Equal(t, []string{"tlscafile", "tlscertificatekeyfile", "authmechanism=mongodb-aws"}, got)
	assert.Nil(t, dsn.RefusedLocalFileOptions("postgres", adsnCleanDSN("app")))
	assert.Nil(t, dsn.RefusedLocalFileOptions("redis", "redis://u:p@h/?sslrootcert=/x"), "unchecked backend")
	assert.Equal(t, []string{"passfile"}, dsn.RefusedLocalFileOptions("postgres", "postgres://u@h/d?pass%66ile=/p"), "escaped key")
	// Agrees with CheckLocalFileOptions on the first option.
	d := "host=h user=u passfile=/p sslcert=/c"
	fe, ok := errors.AsType[*dsn.ForbiddenOptionError](dsn.CheckLocalFileOptions("postgres", d))
	require.True(t, ok)
	assert.Equal(t, fe.Option, dsn.RefusedLocalFileOptions("postgres", d)[0])
}
