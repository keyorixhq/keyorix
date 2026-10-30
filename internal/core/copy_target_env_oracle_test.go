package core

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// AUTHZ-ORACLE-1 item 2: CopySecret and CopyEnvironmentSecrets are authorized for
// the source's project only. A target environment that does not exist and one
// that lives in another project must get the same refusal; before the fix the
// first said "environment N not found" (or a raw storage not-found) and the second
// "must be in the same project", which told the caller which environment IDs
// exist in projects they cannot see.
func TestCopy_ForeignAndMissingTargetEnvironmentAnswerAlike(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	staging, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	foreign, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p1.ID}).Error)

	src, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db-url", Value: []byte("postgres://secret"), ProjectID: p1.ID, EnvironmentID: staging.ID,
		Type: "connection-string", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)
	const missing = uint(999999)

	_, errForeign := c.CopySecret(ctx, src.ID, foreign.ID, "x", "owner", 1, "", "")
	_, errMissing := c.CopySecret(ctx, src.ID, missing, "x", "owner", 1, "", "")
	require.Error(t, errForeign)
	require.Error(t, errMissing)
	assert.ErrorIs(t, errForeign, ErrSecretTargetInvalid)
	assert.ErrorIs(t, errMissing, ErrSecretTargetInvalid)
	assert.Equal(t, normalizeEnvID(errMissing.Error(), missing), normalizeEnvID(errForeign.Error(), foreign.ID),
		"CopySecret: a foreign target environment must answer like a missing one")

	_, _, errForeign = c.CopyEnvironmentSecrets(ctx, p1.ID, staging.ID, foreign.ID, "owner", 1, "", "")
	_, _, errMissing = c.CopyEnvironmentSecrets(ctx, p1.ID, staging.ID, missing, "owner", 1, "", "")
	require.Error(t, errForeign)
	require.Error(t, errMissing)
	assert.Equal(t, errMissing.Error(), errForeign.Error(),
		"CopyEnvironmentSecrets: a foreign target environment must answer like a missing one")
}

// normalizeEnvID drops the echoed environment ID (the caller's own input) so two
// refusals compare on everything else.
func normalizeEnvID(msg string, id uint) string {
	return strings.ReplaceAll(msg, strconv.FormatUint(uint64(id), 10), "<env>")
}
