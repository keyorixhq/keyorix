package services

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// newMachineTestRig seeds a project + a user (id 1) holding a global role that
// grants users.read + roles.assign (the perms the machine RPCs require), and
// returns the MachineIdentityService over a real core.
func newMachineTestRig(t *testing.T) *MachineIdentityGRPCService {
	svc, _ := newMachineTestRigWithDB(t)
	return svc
}

// newMachineTestRigWithDB is newMachineTestRig plus the underlying db, for
// tests (like the MACH-001 regression below) that need to seed additional
// fixtures — e.g. granting a machine identity an admin-tier role directly,
// which core.AssignMachineRole itself would refuse from a non-admin actor.
func newMachineTestRigWithDB(t *testing.T) (*MachineIdentityGRPCService, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// modernc.org/sqlite gives each pooled connection to ":memory:" its own
	// fresh, unmigrated database unless pinned to a single connection --
	// without this, concurrent queries can intermittently hit a connection
	// that never saw AutoMigrate ("no such table") (ADR-048).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{}, &models.Role{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "machine-admin"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error) // global grant
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	return NewMachineIdentityService(coreService), db
}

func TestMachineIdentityService_Lifecycle(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")

	// Create (with classification).
	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "ci-runner", IdentityType: "ci", Classification: "restricted",
	})
	require.NoError(t, err)
	assert.Equal(t, "active", m.GetState())
	assert.Equal(t, "restricted", m.GetClassification())

	// List.
	list, err := svc.ListMachineIdentities(ctx, &pb.ListMachineIdentitiesRequest{ProjectId: 1})
	require.NoError(t, err)
	require.Len(t, list.GetMachineIdentities(), 1)

	// Reclassify.
	mc, err := svc.ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{
		ProjectId: 1, MachineId: m.GetId(), Classification: "confidential",
	})
	require.NoError(t, err)
	assert.Equal(t, "confidential", mc.GetClassification())

	// Issue a token — raw token returned once with the kx_machine_ prefix.
	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "deploy", Classification: "confidential",
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(issued.GetToken(), "kx_machine_"))
	assert.Equal(t, "confidential", issued.GetClassification())

	// List tokens; reclassify + revoke it.
	toks, err := svc.ListMachineTokens(ctx, &pb.ListMachineTokensRequest{ProjectId: 1, MachineId: m.GetId()})
	require.NoError(t, err)
	require.Len(t, toks.GetTokens(), 1)
	tokenID := toks.GetTokens()[0].GetId()

	rc, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), TokenId: tokenID, Classification: "restricted",
	})
	require.NoError(t, err)
	assert.Equal(t, "restricted", rc.GetClassification())

	_, err = svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), TokenId: tokenID,
	})
	require.NoError(t, err)

	// Suspend the identity.
	sm, err := svc.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: m.GetId(), Action: "suspend",
	})
	require.NoError(t, err)
	assert.Equal(t, "suspended", sm.GetState())
}

func TestMachineIdentityService_AuthzAndValidation(t *testing.T) {
	svc := newMachineTestRig(t)

	// Unauthenticated.
	_, err := svc.ListMachineIdentities(context.Background(), &pb.ListMachineIdentitiesRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// No grants → permission denied.
	nobody := authCtx(999, "nobody")
	_, err = svc.CreateMachineIdentity(nobody, &pb.CreateMachineIdentityRequest{ProjectId: 1, Name: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Invalid action.
	admin := authCtx(1, "admin")
	_, err = svc.TransitionMachineIdentity(admin, &pb.TransitionMachineIdentityRequest{ProjectId: 1, MachineId: 1, Action: "explode"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestMachineIdentityService_IssueMachineToken_PrivilegeCeilingDeniedIsPermissionDenied
// guards MACH-001's gRPC classification: a non-global-admin actor with
// roles.assign (so they pass the RPC's own authz gate) who tries to issue a
// token for a machine identity holding an admin-tier role must be rejected
// with codes.PermissionDenied — the caller (user 1) has roles.assign via the
// "machine-admin" role seeded by newMachineTestRig, but that role name is not
// in adminRoleNames, so IsGlobalAdmin(1) is false and
// requireMachinePrivilegeCeiling (MACH-001) refuses. Before mapMachineError
// learned to check core.ErrMachinePrivilegeCeilingDenied via errors.Is, this
// denial's message ("...requires administrative authority") matched none of
// mapMachineError's substrings and fell through to codes.Internal instead.
func TestMachineIdentityService_IssueMachineToken_PrivilegeCeilingDeniedIsPermissionDenied(t *testing.T) {
	svc, db := newMachineTestRigWithDB(t)
	ctx := authCtx(1, "admin")

	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "admin-bot", IdentityType: "ci",
	})
	require.NoError(t, err)

	// Grant the machine identity an admin-tier role (a name recognized by
	// adminRoleNames — see internal/core/authz.go), so a token issued for it
	// would inherit admin authority. User 1's own "machine-admin" role (seeded
	// by newMachineTestRig) is NOT in adminRoleNames, so IsGlobalAdmin(1) is
	// false and requireMachinePrivilegeCeiling (MACH-001) must refuse.
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: uint(m.GetId()), RoleID: 2,
	}).Error)

	_, err = svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "escalate",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
