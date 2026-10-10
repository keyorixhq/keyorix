// project_visibility_test.go — unit tests for #2780's authorization helper.
//
// The handler/router/gRPC tests cover the endpoints; these pin the helper's own
// contract, including the two properties the endpoints depend on but cannot
// demonstrate directly: All means "do not filter at all" (so a project created
// after the call is still visible to a global reader), and an environment-only
// grant yields nothing (because its holder cannot read the parent project by id).
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func visibilityFixture(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	// Two projects, one environment in the first.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "payments-api"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "billing"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "u1", Email: "u1@example.com"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestVisibleProjects_GlobalGrantMeansAllNotAList(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)

	vis, err := c.VisibleProjects(context.Background(), ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.True(t, vis.All, "a global secrets.read holder is authorized at every project scope")
	assert.Empty(t, vis.IDs, "All must not also materialise an ID list")
	assert.False(t, vis.Empty())

	// The reason All is a flag rather than a materialised list: a project created
	// after the authorization call must still be visible, with no re-resolution.
	require.NoError(t, db.Create(&models.Project{ID: 99, Name: "created-later"}).Error)
	assert.True(t, vis.Allows(99), "All must cover a project that did not exist when the answer was computed")
}

func TestVisibleProjects_ProjectScopedGrantYieldsThatProjectOnly(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	vis, err := c.VisibleProjects(context.Background(), ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.False(t, vis.All)
	assert.True(t, vis.Allows(1))
	assert.False(t, vis.Allows(2), "a grant on project 1 must not make project 2 visible")
	assert.False(t, vis.Empty())
}

// TestVisibleProjects_EnvironmentOnlyGrantIsNotProjectVisibility is the sharp edge
// and the reason the helper re-authorizes at the project scope rather than trusting
// GetReadableScopes' raw scope list: GetUserRoleIDsAt matches
// `environment_id = 0 OR environment_id = <asked>`, so a grant at (project 1,
// environment 1) does NOT authorize (project 1, environment 0) — the scope
// GET /api/v1/projects/{id} checks. Listing project 1 for that caller would be new
// disclosure, not a consistency fix.
func TestVisibleProjects_EnvironmentOnlyGrantIsNotProjectVisibility(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1, EnvironmentID: 1}).Error)
	ctx := context.Background()

	// Precondition, so the assertion below is about parity with the per-project read
	// rather than an arbitrary choice.
	allowed, err := c.AuthorizePrincipal(ctx, ActorTypeUser, 1, "secrets.read", Scope{ProjectID: 1})
	require.NoError(t, err)
	require.False(t, allowed, "an environment-only grant does not authorize the project scope")

	vis, err := c.VisibleProjects(ctx, ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.False(t, vis.All)
	assert.True(t, vis.Empty(), "an environment-only grant must not reveal its parent project")
}

func TestVisibleProjects_NoGrantsIsEmptyNotAnError(t *testing.T) {
	t.Parallel()
	c, _ := visibilityFixture(t)

	vis, err := c.VisibleProjects(context.Background(), ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err, "no grants is a legitimate answer, not an error — the caller returns an empty list, not a 403")
	assert.False(t, vis.All)
	assert.True(t, vis.Empty())
	assert.False(t, vis.Allows(1))
}

func TestVisibleProjects_ExpiredGrantIsNotVisibility(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1, ExpiresAt: &past}).Error)

	vis, err := c.VisibleProjects(context.Background(), ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.True(t, vis.Empty(), "a lapsed time-bound grant confers no visibility")
}

func TestVisibleProjects_GroupGrantCounts(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "payments-oncall"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 1}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1, ProjectID: 1}).Error)

	vis, err := c.VisibleProjects(context.Background(), ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.True(t, vis.Allows(1), "a group-inherited project grant confers visibility")
	assert.False(t, vis.Allows(2))
}

// TestVisibleProjects_ProjectRestrictedPATSeesOnlyItsProject is the ADR-042 case,
// and it was a real gap found by the follow-up review's own test request.
//
// A project-restricted PAT whose OWNER is a global reader saw NOTHING, while
// `GET /api/v1/projects/{id}` on that same project succeeded for it — #2780's defect
// one mechanism over. Neither step of the resolution could produce the project:
// the global check is denied for such a token by design, and GetReadableScopes
// enumerates the owner's PROJECT-scoped grants, of which a globally-granted owner has
// none.
func TestVisibleProjects_ProjectRestrictedPATSeesOnlyItsProject(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	// The owner is a GLOBAL reader — so if the restriction were ignored, the answer
	// would be All=true and the token would see every project.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)

	ctx := WithPATRestriction(context.Background(), &PATRestriction{ProjectID: 1})

	// Precondition: the token really can read project 1 by id, and really cannot read
	// project 2 or the global scope. That is what makes the assertion below a
	// consistency claim about the LISTING rather than a guess.
	okA, err := c.AuthorizePrincipal(ctx, ActorTypeUser, 1, "secrets.read", Scope{ProjectID: 1})
	require.NoError(t, err)
	require.True(t, okA, "the restricted token is authorized for its own project")
	okB, err := c.AuthorizePrincipal(ctx, ActorTypeUser, 1, "secrets.read", Scope{ProjectID: 2})
	require.NoError(t, err)
	require.False(t, okB, "and not for any other")
	okGlobal, err := c.AuthorizePrincipal(ctx, ActorTypeUser, 1, "secrets.read", Scope{})
	require.NoError(t, err)
	require.False(t, okGlobal, "nor at global scope — which is why All cannot be the answer")

	vis, err := c.VisibleProjects(ctx, ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.False(t, vis.All, "a restricted token must never resolve to All, however broad its owner is")
	assert.True(t, vis.Allows(1),
		"the listing must serve the project the token can already GET by id — returning nothing here "+
			"is the same listing-vs-item inconsistency #2780 was about")
	assert.False(t, vis.Allows(2), "and nothing else")
}

// TestVisibleProjects_EnvironmentRestrictedPATSeesNoProject is the complementary
// case, and the one that must stay empty: PATRestriction.EnvironmentID denies any
// project-LEVEL check (environment 0), so such a token cannot read the project by id
// either, and the listing must agree. No special handling — the project-scope
// authorization pass does it, which is the point of having that pass.
func TestVisibleProjects_EnvironmentRestrictedPATSeesNoProject(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)

	// Environment 1 belongs to project 1 in this fixture.
	ctx := WithPATRestriction(context.Background(), &PATRestriction{ProjectID: 1, EnvironmentID: 1})

	ok, err := c.AuthorizePrincipal(ctx, ActorTypeUser, 1, "secrets.read", Scope{ProjectID: 1})
	require.NoError(t, err)
	require.False(t, ok,
		"precondition: an environment-restricted token is denied the project-level scope, so it cannot "+
			"GET the project by id")

	vis, err := c.VisibleProjects(ctx, ActorTypeUser, 1, "secrets.read")
	require.NoError(t, err)
	assert.True(t, vis.Empty(),
		"so the listing must not surface the parent project — adding the restriction's project as a "+
			"CANDIDATE is safe precisely because the authorization pass still refuses it here")
}

// TestVisibleProjects_WrongPermissionYieldsNothing pins that the helper answers for
// the permission it was asked about, not "any grant at this scope" — so passing
// secrets.write would not hand back every project a reader can see.
func TestVisibleProjects_WrongPermissionYieldsNothing(t *testing.T) {
	t.Parallel()
	c, db := visibilityFixture(t)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	vis, err := c.VisibleProjects(context.Background(), ActorTypeUser, 1, "secrets.write")
	require.NoError(t, err)
	assert.True(t, vis.Empty(), "the reader role grants secrets.read only, so secrets.write visibility is empty")
}
