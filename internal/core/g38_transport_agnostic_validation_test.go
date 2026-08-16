// g38_transport_agnostic_validation_test.go — regression coverage for G38:
// several input-validation and business-rule guards were previously enforced
// only in the HTTP JSON-decoding layer (server/validation's `validate:"..."`
// struct tags), so the gRPC service layer and CLI embedded-mode path — which
// construct a request directly and never route through that HTTP-specific
// validator — silently accepted input the HTTP path would reject. These
// tests call the CORE layer directly (the single choke point every
// transport, including gRPC and CLI embedded mode, ultimately funnels
// through), proving the guard now applies regardless of transport.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newG38TestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.Group{}, &models.AuditEvent{},
		&models.User{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// TestCreateProject_RejectsHomographCharset pins member 1+2 (identifier
// guard / project-name anti-spoofing charset): a project name containing a
// character outside [a-zA-Z0-9 _-] — the exact charset the HTTP validator's
// `identifier` rule enforces — must be refused at the core layer, not just
// when a caller happens to route through the HTTP JSON decoder.
func TestCreateProject_RejectsHomographCharset(t *testing.T) {
	c, _ := newG38TestCore(t)
	ctx := context.Background()

	for _, name := range []string{
		"аdmin",    // Cyrillic "а" (U+0430) homograph of Latin "a"
		"proj™",    // trademark symbol
		"a/b",      // path separator
		"a\u200bb", // zero-width space
	} {
		_, err := c.CreateProject(ctx, name, "")
		require.Errorf(t, err, "name %q should have been rejected", name)
		assert.Contains(t, err.Error(), "letters, digits, spaces, - or _")
	}

	// A legitimate name (letters, digits, spaces, hyphen, underscore) is accepted.
	_, err := c.CreateProject(ctx, "my-project_2", "")
	require.NoError(t, err)
}

// TestUpdateProject_RejectsHomographCharset: same guard, update path.
func TestUpdateProject_RejectsHomographCharset(t *testing.T) {
	c, _ := newG38TestCore(t)
	ctx := context.Background()

	p, err := c.CreateProject(ctx, "legit", "")
	require.NoError(t, err)

	_, err = c.UpdateProject(ctx, p.ID, "аdmin", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "letters, digits, spaces, - or _")
}

// TestCreateProjectWithEnvs_RejectsHomographCharset: same guard, the
// --envs-overriding create path.
func TestCreateProjectWithEnvs_RejectsHomographCharset(t *testing.T) {
	c, _ := newG38TestCore(t)
	ctx := context.Background()

	_, err := c.CreateProjectWithEnvs(ctx, "proj™", "", []string{"dev"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "letters, digits, spaces, - or _")
}

// TestCreateEnvironment_RefusesDeadParentProject pins member 3 ("parent
// project must be live"): CreateEnvironment must refuse to create an
// environment under a soft-deleted project. Before this fix, only the HTTP
// handler's own defense-in-depth check enforced this — a caller reaching
// core.CreateEnvironment directly (gRPC, CLI embedded mode) had no such
// check at all.
func TestCreateEnvironment_RefusesDeadParentProject(t *testing.T) {
	c, db := newG38TestCore(t)
	ctx := context.Background()

	p, err := c.CreateProject(ctx, "to-delete", "")
	require.NoError(t, err)
	require.NoError(t, db.Delete(&models.Project{}, p.ID).Error) // soft-delete (gorm.DeletedAt)

	_, err = c.CreateEnvironment(ctx, p.ID, "orphan-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// A live project still works normally.
	live, err := c.CreateProject(ctx, "still-live", "")
	require.NoError(t, err)
	_, err = c.CreateEnvironment(ctx, live.ID, "real-env")
	require.NoError(t, err)
}

// TestCreateUser_RejectsMalformedEmail pins member 4/5 (CreateUser skips
// HTTP-enforced format validation / CreateUserRequest's dead validate tags):
// a malformed email must be refused at the core layer, matching the HTTP
// path's `validate:"required,email"` rule — not merely documented by a
// struct tag nothing reads.
func TestCreateUser_RejectsMalformedEmail(t *testing.T) {
	c, _ := newG38TestCore(t)
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "gooduser", Email: "not-an-email", DisplayName: "Good User", Password: "StrongPassw0rd!2026x",
	})
	require.Error(t, err)

	// A well-formed request is accepted.
	_, err = c.CreateUser(ctx, &CreateUserRequest{
		Username: "gooduser", Email: "good@example.com", DisplayName: "Good User", Password: "StrongPassw0rd!2026x",
	})
	require.NoError(t, err)
}

// TestCreateUser_RejectsShortUsername pins the username length half of the
// same gap (HTTP: `validate:"required,min=3,max=50"`).
func TestCreateUser_RejectsShortUsername(t *testing.T) {
	c, _ := newG38TestCore(t)
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "ab", Email: "ab@example.com", DisplayName: "Ab", Password: "StrongPassw0rd!2026x",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username")
}

// TestUpdateUser_RejectsMalformedEmail: same guard, update path — an empty
// Email means "leave unchanged" (partial update), so only a NON-empty,
// malformed value should be refused.
func TestUpdateUser_RejectsMalformedEmail(t *testing.T) {
	c, _ := newG38TestCore(t)
	ctx := context.Background()

	u, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "target", Email: "target@example.com", DisplayName: "Target", Password: "StrongPassw0rd!2026x",
	})
	require.NoError(t, err)

	_, err = c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, Email: "not-an-email"})
	require.Error(t, err)

	// Leaving Email blank (no change) still works.
	active := true
	_, err = c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, IsActive: &active})
	require.NoError(t, err)
}
