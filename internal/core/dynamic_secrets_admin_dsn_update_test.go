// dynamic_secrets_admin_dsn_update_test.go — DYNAMIC-ADMIN-DSN-1 items 1 and 2:
// a stored admin_dsn can be replaced in place, under the same checks as create,
// and the configs that need it can be listed. Every case runs on SQLite and,
// with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// adsnSecret is the password every DSN in these tests carries: it must never
// appear outside the encrypted admin_dsn column.
const adsnSecret = "adsn-S3cr3t-7f2c91"

const adsnEvent = "dynamic_secret.config_admin_dsn_updated"

// adsnCleanDSN is an accepted postgres DSN on a public (TEST-NET-3) literal, so
// the host guard decides without DNS.
func adsnCleanDSN(db string) string {
	return fmt.Sprintf("postgres://admin:%s@203.0.113.10:5432/%s?sslmode=require", adsnSecret, db)
}

// adsnWorld is one backend: a core over a fault-injecting store with the
// fixture's key set, and a project member without admin authority.
type adsnWorld struct {
	*smaWorld
	core      *KeyorixCore
	developer *models.User
}

func adsnBackends(t *testing.T, fn func(t *testing.T, w *adsnWorld)) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		c := NewKeyorixCore(sw.fs)
		c.SetAuthEncryptor(sw.f.enc)
		fake := &dynamictest.FakeEngine{NativeExpiry: true}
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
		fn(t, &adsnWorld{smaWorld: sw, core: c, developer: sw.f.user("adsn-dev", "project_developer")})
	})
}

// legacyConfig creates a config with a clean DSN, then stores storedDSN in its
// place the way a server before #3952 did (past create's option check).
func (w *adsnWorld) legacyConfig(name, storedDSN string) *models.DynamicSecretConfig {
	w.t.Helper()
	cfg, err := w.core.CreateDynamicSecretConfig(w.ctx, &CreateDynamicSecretConfigRequest{
		Name: name, ProjectID: w.f.projectID, EnvironmentID: w.f.envID, BackendType: "postgres",
		AdminDSN: adsnCleanDSN("app"), DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: w.f.adminID,
	})
	require.NoError(w.t, err)
	enc, meta, err := w.core.encryptAuthSecret(storedDSN, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	require.NoError(w.t, err)
	require.NoError(w.t, w.f.setup.Storage().SetDynamicSecretConfigAdminDSN(w.ctx, cfg.ID, enc, meta))
	return cfg
}

// storedDSN decrypts what the database holds for cfg, the value issue and revoke use.
func (w *adsnWorld) storedDSN(cfg *models.DynamicSecretConfig) string {
	w.t.Helper()
	var row models.DynamicSecretConfig
	require.NoError(w.t, w.db.First(&row, cfg.ID).Error)
	plain, err := w.core.decryptAuthSecret(row.AdminDSNEnc, row.AdminDSNMeta, ports.DynamicSecretConfigAAD(row.ID, row.ProjectID, row.EnvironmentID))
	require.NoError(w.t, err)
	return plain
}

func (w *adsnWorld) updateEvents() int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.AuditEvent{}).Where("event_type = ?", adsnEvent).Count(&n).Error)
	return n
}

func TestDynamicSecrets_UpdateAdminDSN_ReplacesStoredDSN(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		legacy := "postgres://admin:" + adsnSecret + "@203.0.113.10:5432/app?sslmode=verify-full&sslrootcert=/etc/keyorix/private-ca.pem"
		cfg := w.legacyConfig("adsn-replace", legacy)
		require.Equal(t, legacy, w.storedDSN(cfg), "precondition: the legacy DSN is stored")

		events := w.updateEvents()
		updated, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{
			ConfigID: cfg.ID, AdminDSN: adsnCleanDSN("app2"), ActorID: w.f.adminID,
		})
		require.NoError(t, err)
		assert.Equal(t, cfg.ID, updated.ID)
		assert.Equal(t, adsnCleanDSN("app2"), w.storedDSN(cfg), "the stored DSN is the new one")
		require.Equal(t, events+1, w.updateEvents(), "exactly one audit row")
		var ev models.AuditEvent
		require.NoError(t, w.db.Where("event_type = ?", adsnEvent).Order("id desc").First(&ev).Error)
		require.NotNil(t, ev.UserID)
		assert.Equal(t, w.f.adminID, *ev.UserID, "attributed to the actor")
		require.NotNil(t, ev.ProjectID)
		assert.Equal(t, w.f.projectID, *ev.ProjectID)
	})
}

func TestDynamicSecrets_UpdateAdminDSN_RefusesWhatCreateRefuses(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		cfg := w.legacyConfig("adsn-refuse", adsnCleanDSN("app"))
		for _, tc := range []struct{ name, dsn, option string }{
			{"sslrootcert", "postgres://admin:" + adsnSecret + "@203.0.113.10/app?sslrootcert=/etc/keyorix/ca.pem", "sslrootcert"},
			{"sslkey kv", "host=203.0.113.10 user=admin password=" + adsnSecret + " sslkey=/etc/keyorix/key.pem", "sslkey"},
			{"passfile escaped", "postgres://admin:" + adsnSecret + "@203.0.113.10/app?pass%66ile=/root/.pgpass", "passfile"},
			{"service", "host=203.0.113.10 user=admin password=" + adsnSecret + " service=prod", "service"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				events := w.updateEvents()
				_, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{
					ConfigID: cfg.ID, AdminDSN: tc.dsn, ActorID: w.f.adminID,
				})
				fe, ok := errors.AsType[*dsn.ForbiddenOptionError](err)
				require.True(t, ok, "want a refused-option error, got %v", err)
				assert.Equal(t, tc.option, fe.Option)
				assert.Equal(t, adsnCleanDSN("app"), w.storedDSN(cfg), "a refused DSN is not stored")
				assert.Equal(t, events, w.updateEvents(), "a refused update writes no audit row")
			})
		}
		t.Run("private host", func(t *testing.T) {
			_, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{
				ConfigID: cfg.ID, AdminDSN: "postgres://admin:" + adsnSecret + "@169.254.169.254/app", ActorID: w.f.adminID,
			})
			_, ok := errors.AsType[*DynamicSecretTargetRefusedError](err)
			require.True(t, ok, "want the egress refusal, got %v", err)
			assert.Equal(t, adsnCleanDSN("app"), w.storedDSN(cfg))
		})
		t.Run("missing", func(t *testing.T) {
			_, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{ConfigID: cfg.ID, ActorID: w.f.adminID})
			require.ErrorIs(t, err, ErrValidation)
			_, err = w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{ConfigID: cfg.ID + 1000, AdminDSN: adsnCleanDSN("x"), ActorID: w.f.adminID})
			require.ErrorIs(t, err, ErrDynamicSecretNotFound)
		})
	})
}

func TestDynamicSecrets_UpdateAdminDSN_NonAdminRefused(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		legacy := "postgres://admin:" + adsnSecret + "@203.0.113.10/app?sslrootcert=/etc/keyorix/ca.pem"
		cfg := w.legacyConfig("adsn-nonadmin", legacy)
		events := w.updateEvents()
		_, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{
			ConfigID: cfg.ID, AdminDSN: adsnCleanDSN("attacker"), ActorID: w.developer.ID,
		})
		require.ErrorIs(t, err, ErrPermissionDenied)
		assert.Equal(t, legacy, w.storedDSN(cfg), "a refused actor changes nothing")
		assert.Equal(t, events, w.updateEvents())
	})
}

// TestDynamicSecrets_UpdateAdminDSN_AuditFailureChangesNothing: the DSN and its
// audit row commit together (INV-CORE-security-mutation-audit-same-tx).
func TestDynamicSecrets_UpdateAdminDSN_AuditFailureChangesNothing(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		cfg := w.legacyConfig("adsn-auditfail", adsnCleanDSN("app"))
		for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
			t.Run(fk.String(), func(t *testing.T) {
				w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: fk, Err: errors.New("injected audit failure")})
				_, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{
					ConfigID: cfg.ID, AdminDSN: adsnCleanDSN("app2"), ActorID: w.f.adminID,
				})
				fired := w.fs.Fired()
				w.fs.Arm(nil)
				require.True(t, fired, "the update never appended its audit row")
				require.ErrorIs(t, err, ErrMutationAuditUnavailable)
				assert.Equal(t, adsnCleanDSN("app"), w.storedDSN(cfg), "no audit row, no change")
			})
		}
	})
}

// syncBuffer collects log output written from any goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestDynamicSecrets_UpdateAdminDSN_DSNNeverLeaves drives every outcome of an
// update and of the refused-DSN listing, then looks for the DSN's password where it must
// not be: the process log, every audit row, every returned error, and the
// config row's columns in clear. Not parallel: it captures the global logger.
func TestDynamicSecrets_UpdateAdminDSN_DSNNeverLeaves(t *testing.T) {
	adsnBackends(t, func(t *testing.T, w *adsnWorld) {
		logs := &syncBuffer{}
		prev, prevFlags := log.Writer(), log.Flags()
		log.SetOutput(logs)
		t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })

		cfg := w.legacyConfig("adsn-leak", "host=203.0.113.10 user=admin password="+adsnSecret+" sslrootcert=/etc/ca.pem")
		var errs []error
		update := func(actor uint, adminDSN string) {
			_, err := w.core.UpdateDynamicSecretConfigAdminDSN(w.ctx, &UpdateDynamicSecretConfigAdminDSNRequest{ConfigID: cfg.ID, AdminDSN: adminDSN, ActorID: actor})
			errs = append(errs, err)
		}
		update(w.developer.ID, adsnCleanDSN("nonadmin"))
		update(w.f.adminID, "postgres://admin:"+adsnSecret+"@203.0.113.10/app?sslkey=/etc/key.pem")
		update(w.f.adminID, "postgres://admin:"+adsnSecret+"@10.0.0.5/app")
		w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected audit failure")})
		update(w.f.adminID, adsnCleanDSN("auditfail"))
		w.fs.Arm(nil)
		update(w.f.adminID, adsnCleanDSN("ok"))
		require.NoError(t, errs[len(errs)-1], "precondition: the last update succeeds")
		for _, err := range errs[:len(errs)-1] {
			require.Error(t, err, "precondition: every other update is refused")
		}
		rep, err := w.core.ListProjectConfigsWithRefusedAdminDSN(w.ctx, w.f.adminID, w.f.projectID)
		require.NoError(t, err)
		assert.NotContains(t, fmt.Sprintf("%+v", rep), adsnSecret, "the refused-DSN listing carries the DSN")
		_, err = w.core.ListProjectConfigsWithRefusedAdminDSN(w.ctx, w.developer.ID, w.f.projectID)
		errs = append(errs, err)

		for _, err := range errs {
			if err != nil {
				assert.NotContains(t, err.Error(), adsnSecret, "an error carries the DSN")
				assert.NotContains(t, fmt.Sprintf("%+v", err), adsnSecret)
			}
		}
		assert.NotContains(t, logs.String(), adsnSecret, "the log carries the DSN")
		var events []models.AuditEvent
		require.NoError(t, w.db.Find(&events).Error)
		require.NotEmpty(t, events)
		for _, e := range events {
			assert.NotContains(t, fmt.Sprintf("%+v", e), adsnSecret, "audit event %d (%s) carries the DSN", e.ID, e.EventType)
		}
		var raw []map[string]any
		require.NoError(t, w.db.Table("dynamic_secret_configs").Where("id = ?", cfg.ID).Find(&raw).Error)
		require.Len(t, raw, 1)
		for col, v := range raw[0] {
			assert.False(t, strings.Contains(fmt.Sprintf("%s", v), adsnSecret), "column %s holds the DSN in clear", col)
		}
		assert.Equal(t, adsnCleanDSN("ok"), w.storedDSN(cfg), "precondition: the encrypted column holds the DSN")
	})
}
