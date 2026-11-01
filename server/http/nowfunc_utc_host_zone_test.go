// nowfunc_utc_host_zone_test.go -- SQLITE-UTC-NOWFUNC-1 item 1.
//
// GORM stamps created_at / updated_at through its NowFunc AFTER every BeforeSave
// hook has run, so a hook cannot normalise them (models.go, StatsSnapshot). With
// the default NowFunc (time.Now, host zone) a server on a host with a fixed
// non-UTC zone stored machine_identities.updated_at as
// "2026-10-31 12:44:58.849121 +1400 OT m=+0.45...", GetMachineIdentity failed to
// scan it, and POST .../machine-identities/{id}/tokens answered 404
// (machineInProject reports any read error as "not found").
//
// This is a black box through the real storage factory and the real router, run
// in a subprocess whose time.Local comes from TZ (no test assigns time.Local; see
// no_time_local_assignment_guard_test.go). Postgres has no stored-text form, so
// there the assertion is that the same requests succeed; SQLite additionally
// reads the stored bytes through a second raw connection.
package http

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/stretchr/testify/require"
)

// newNowFuncEnv is newOTEnv on the named backend. The raw handle is nil on Postgres.
func newNowFuncEnv(t *testing.T, backend string) *otEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg, _ := rrStorageConfig(t, backend)
	real, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	c := core.NewKeyorixCore(real)
	ctx := context.Background()
	c.SetBootstrapToken("nf-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "nfadmin", Email: "nfadmin@example.com", Password: "TestPassword123!", Token: "nf-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "nfadmin@example.com")
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "nfadmin", Password: "TestPassword123!"})
	require.NoError(t, err)

	router, err := NewRouter(&config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	e := &otEnv{t: t, c: c, srv: srv, admin: sess.SessionToken, adminID: admin.ID}
	if backend == "sqlite" {
		raw, err := sql.Open("sqlite", "file:"+cfg.Storage.Database.Path+"?mode=ro&_busy_timeout=5000")
		require.NoError(t, err)
		t.Cleanup(func() { _ = raw.Close() })
		e.raw = raw
	}
	return e
}

func TestGormNowFunc_StoresUTCOnNonUTCHost_SQLite(t *testing.T) {
	nowFuncAcrossHostZones(t, "TestGormNowFunc_StoresUTCOnNonUTCHost_SQLite", "sqlite")
}

func TestGormNowFunc_StoresUTCOnNonUTCHost_Postgres(t *testing.T) {
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	nowFuncAcrossHostZones(t, "TestGormNowFunc_StoresUTCOnNonUTCHost_Postgres", "postgres")
}

func nowFuncAcrossHostZones(t *testing.T, name, backend string) {
	if _, child := otHostTZChild(t); child {
		nowFuncOnThisHost(t, backend)
		return
	}
	// +14:00 (the reported host) and a half-hour negative zone.
	for _, zone := range []string{"Pacific/Kiritimati", "America/St_Johns"} {
		t.Run(zone, func(t *testing.T) {
			loadZone(t, zone)
			runInOTHostTZ(t, name, zone)
		})
	}
}

// nowFuncOnThisHost is the body, run inside a subprocess whose time.Local came from TZ.
func nowFuncOnThisHost(t *testing.T, backend string) {
	e := newNowFuncEnv(t, backend)
	defer e.dump()
	ctx := context.Background()

	proj, err := e.c.CreateProject(ctx, "nf-project", "NowFunc host zone")
	require.NoError(t, err)
	mi, err := e.c.CreateMachineIdentity(ctx, proj.ID, "nf-runner", "ci", "", "", e.adminID, 0)
	require.NoError(t, err)

	tokens := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", proj.ID, mi.ID)

	// The reported failure: the first token mint read the identity back and 404'd.
	status, body := e.do("POST", tokens, e.admin, map[string]any{"name": "nf-cred", "expires_in_days": 1})
	require.Equal(t, http.StatusCreated, status, "token mint on a non-UTC host: %s", body)
	// Reads of the same rows, and a second mint after the credential row exists.
	status, body = e.do("GET", tokens, e.admin, nil)
	require.Equal(t, http.StatusOK, status, string(body))
	status, body = e.do("POST", tokens, e.admin, map[string]any{"name": "nf-cred-2", "expires_in_days": 1})
	require.Equal(t, http.StatusCreated, status, "second token mint on a non-UTC host: %s", body)
	got, err := e.c.Storage().GetMachineIdentity(ctx, mi.ID)
	require.NoError(t, err)
	require.Equal(t, mi.ID, got.ID)

	if e.raw == nil {
		return
	}
	// The stored text carries no zone suffix (e.row fails on an offset or a monotonic "m=" tail).
	e.row("projects created_at", "(GORM NowFunc)", e.stored("SELECT typeof(created_at), created_at FROM projects WHERE id = ?", proj.ID), "")
	e.row("projects updated_at", "(GORM NowFunc)", e.stored("SELECT typeof(updated_at), updated_at FROM projects WHERE id = ?", proj.ID), "")
	e.row("machine_identities created_at", "(GORM NowFunc)", e.stored("SELECT typeof(created_at), created_at FROM machine_identities WHERE id = ?", mi.ID), "")
	e.row("machine_identities updated_at", "(GORM NowFunc)", e.stored("SELECT typeof(updated_at), updated_at FROM machine_identities WHERE id = ?", mi.ID), "")
	e.row("machine credential created_at", "(GORM NowFunc)", e.stored("SELECT typeof(created_at), created_at FROM machine_identity_credentials WHERE machine_identity_id = ? ORDER BY id LIMIT 1", mi.ID), "")
}
