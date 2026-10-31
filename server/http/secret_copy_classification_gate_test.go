package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// #3804: POST /secrets/{id}/copy folded every ErrPermissionDenied from the source
// read into 404 "Secret not found". Since #3796 that also caught the
// restricted-classification gate's refusals, which come only after the reader's
// ordinary read permission was granted: a reader who can see the secret was told
// it does not exist instead of what to do (get secrets.read.restricted, step up
// with the second factor). The gate refusal is now 403 with its reason; a caller
// with no read access to the secret still gets core's existence-hiding not-found
// (over HTTP the route's scoped secrets.read gate answers that caller first).

type copyGateWorld struct {
	router   http.Handler
	c        *core.KeyorixCore
	srcID    uint
	dstEnvID uint
	tokens   map[string]string
	ids      map[string]uint
}

func newCopyGateWorld(t *testing.T, gate func(c *core.KeyorixCore)) *copyGateWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db := sqlitetest.OpenWithConfig(t, "kxcopygate_", &gorm.Config{Logger: logger.Discard})
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	ls := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(ls)
	gate(c)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "copyadmin", Email: "copyadmin@example.com", Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := ls.GetUserByUsername(ctx, "copyadmin")
	require.NoError(t, err)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "copyproj"})
	require.NoError(t, err)
	src, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: proj.ID})
	require.NoError(t, err)
	dst, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "db-password", Value: []byte("COPY-GATE-PLAINTEXT-5d1"), ProjectID: proj.ID, EnvironmentID: src.ID,
		Type: "password", Classification: core.ClassificationRestricted, CreatedBy: "copyadmin", OwnerID: admin.ID,
	})
	require.NoError(t, err)

	perm := func(name string) models.Permission {
		var p models.Permission
		if e := db.Where("name = ?", name).First(&p).Error; e != nil {
			p = models.Permission{Name: name, Resource: "secrets", Action: name}
			require.NoError(t, db.Create(&p).Error)
		}
		return p
	}
	other, err := ls.CreateProject(ctx, &models.Project{Name: "otherproj"})
	require.NoError(t, err)
	role := func(name string, perms ...string) uint {
		r := models.Role{Name: "copy-" + name, NameFolded: "copy-" + name}
		require.NoError(t, db.Create(&r).Error)
		for _, p := range perms {
			pp := perm(p)
			require.NoError(t, db.Create(&models.RolePermission{RoleID: r.ID, PermissionID: pp.ID}).Error)
		}
		return r.ID
	}
	readWrite, writeOnly := role("read-write", "secrets.read", "secrets.write"), role("write-only", "secrets.write")
	ids := map[string]uint{}
	// user is a session of a new user holding roles[i] at scopes[i].
	user := func(name string, roles []uint, scopes []storage.Scope) string {
		u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: "Copy#User-Passw0rd-1"})
		require.NoError(t, err)
		ids[name] = u.ID
		for i, r := range roles {
			require.NoError(t, ls.AssignRole(ctx, u.ID, r, scopes[i]))
		}
		sess, _, err := c.Login(ctx, &core.LoginRequest{Username: name, Password: "Copy#User-Passw0rd-1"})
		require.NoError(t, err)
		return sess.SessionToken
	}
	here, elsewhere := storage.Scope{ProjectID: proj.ID}, storage.Scope{ProjectID: other.ID}

	r, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	return &copyGateWorld{router: r, c: c, srcID: sec.ID, dstEnvID: dst.ID, ids: ids, tokens: map[string]string{
		"reader": user("reader", []uint{readWrite}, []storage.Scope{here}),
		// May write the target environment but cannot read this project's
		// secrets (secrets.read only in another project).
		"noaccess": user("noaccess", []uint{readWrite, writeOnly}, []storage.Scope{elsewhere, here}),
	}}
}

func (w *copyGateWorld) copy(t *testing.T, who string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"environment_id": w.dstEnvID, "name": "db-password-copy"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/copy", w.srcID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.tokens[who])
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestCopySecret_ClassificationGateRefusal_Is403WithReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gate   func(c *core.KeyorixCore)
		reason string
	}{
		{"without secrets.read.restricted", func(c *core.KeyorixCore) { c.SetClassificationRestrictedRequiresPermission(true) }, core.PermSecretReadRestricted},
		{"without a recent step-up", func(c *core.KeyorixCore) { c.SetClassificationRestrictedRequiresMFAStepUp(true, 5) }, "re-authenticate with your second factor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newCopyGateWorld(t, tc.gate)

			code, body := w.copy(t, "reader")
			assert.Equal(t, http.StatusForbidden, code, "a gate refusal of a reader who can see the secret is 403, not 404: %s", body)
			assert.Contains(t, body, tc.reason, "the 403 must carry the gate's reason")
			assert.NotContains(t, body, "COPY-GATE-PLAINTEXT-5d1")

			// No read access to the secret: core still folds the ordinary refusal into
			// the same not-found a missing secret gets, and nothing names the gate.
			_, err := w.c.CopySecret(context.Background(), w.srcID, w.dstEnvID, "x", "noaccess", w.ids["noaccess"], "", "")
			require.Error(t, err)
			assert.True(t, storage.IsSecretNotFound(err), "a caller who cannot read the source must get not-found: %v", err)
			assert.NotContains(t, err.Error(), "restricted", "the not-found must not name the gate")
			code, body = w.copy(t, "noaccess")
			assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, code, body)
			assert.NotContains(t, body, "restricted", "a caller without read access must not learn the gate")
		})
	}
}
