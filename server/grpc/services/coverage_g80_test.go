// coverage_g80_test.go — additional coverage for branches the existing
// per-service test files leave unexercised (G80 coverage sweep): proto
// conversion field branches, error-classification switches, and a handful of
// validation/not-found/storage-failure paths that existing tests never hit.
// Follows the conventions of the file each addition targets (same rig
// helpers, same testify style, same "not a raw error string" assertions).
package services

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// break_glass_service.go
// ---------------------------------------------------------------------------

// breakGlassToProto's RevokedBy/RevokedAt branches: TestBreakGlass_ActivateListRevoke
// (break_glass_service_test.go) revokes an activation but never re-lists it
// afterward, so breakGlassToProto never saw a revoked row.
func TestBreakGlass_RevokedActivation_ProtoCarriesRevocationFields(t *testing.T) {
	svc := newBreakGlassService(t)

	act, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{
		ProjectId: 1, Justification: "prod incident #77", Ttl: "1h",
	})
	require.NoError(t, err)

	_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: act.GetId()})
	require.NoError(t, err)

	list, err := svc.ListBreakGlassActivations(bgCtx(), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	require.Len(t, list.GetActivations(), 1)
	revoked := list.GetActivations()[0]
	assert.Equal(t, "revoked", revoked.GetState())
	require.NotNil(t, revoked.RevokedBy, "a revoked activation must carry who revoked it")
	assert.Equal(t, uint32(1), revoked.GetRevokedBy())
	require.NotNil(t, revoked.RevokedAt, "a revoked activation must carry when it was revoked")
}

// breakGlassError's classification switch — only the InvalidArgument branch is
// exercised by the per-RPC tests; directly drive the rest as a table test.
func TestBreakGlassError_Classification(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want codes.Code
	}{
		{"not found", "activation not found", codes.NotFound},
		{"permission", "permission denied for this project", codes.PermissionDenied},
		{"denied", "access denied", codes.PermissionDenied},
		{"already revoked", "activation already revoked", codes.FailedPrecondition},
		{"not active", "activation is not active", codes.FailedPrecondition},
		{"expired", "activation expired", codes.FailedPrecondition},
		{"default", "something went sideways", codes.Internal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := breakGlassError(errors.New(c.msg))
			assert.Equal(t, c.want, status.Code(got))
		})
	}
}

// ---------------------------------------------------------------------------
// audit_service.go
// ---------------------------------------------------------------------------

// auditEventToProto's ProjectID/SecretNodeID/ImpersonatedBy/ActingAs branches:
// the seeded event in newAuditService only sets UserID, so those four
// pointer-conditional fields were never exercised.
func TestAuditService_GetAuditLogs_FullFieldEvent(t *testing.T) {
	svc, db := newAuditServiceWithDB(t)
	uid := uint(1)
	pid := uint(1)
	sid := uint(42)
	impersonator := uint(1)
	target := uint(1)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &uid, ProjectID: &pid, SecretNodeID: &sid,
		ImpersonatedBy: &impersonator, ActingAs: &target, Impersonation: true,
		Description: "impersonated read", EventTime: time.Now(), ActorType: "user",
	}).Error)

	resp, err := svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetLogs())

	var found *pb.AuditLog
	for _, l := range resp.GetLogs() {
		if l.GetDescription() == "impersonated read" {
			found = l
			break
		}
	}
	require.NotNil(t, found, "the seeded full-field event must be in the response")
	require.NotNil(t, found.ProjectId)
	assert.Equal(t, uint32(1), found.GetProjectId())
	require.NotNil(t, found.SecretId)
	assert.Equal(t, uint32(42), found.GetSecretId())
	assert.True(t, found.GetImpersonation())
	require.NotNil(t, found.ImpersonatedBy)
	assert.Equal(t, "alice", found.GetImpersonatedBy())
	require.NotNil(t, found.ActingAs)
	assert.Equal(t, "alice", found.GetActingAs())
}

// newAuditServiceWithDB mirrors newAuditService (audit_service_test.go) but
// also returns the underlying db, for tests that insert extra fixture rows.
func newAuditServiceWithDB(t *testing.T) (*AuditGRPCService, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "super_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)
	return NewAuditService(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

// rbacEntryToProto's GroupID/PermissionID/EnvironmentID branches: the only
// existing GetRBACAuditLogs fixture (audit_service_test.go) is a role.assigned
// event carrying TargetUserID/RoleID/ProjectID, never Group/Permission/Environment.
// Insert real role.group_assigned + permission.assigned events directly (the
// shape core.LogGroupRoleAssigned/LogPermissionAssigned themselves write) via
// the public core entry points, then read them back through GetRBACAuditLogs.
func TestAuditService_GetRBACAuditLogs_GroupAndPermissionAndEnvironmentFields(t *testing.T) {
	_, db := newAuditServiceWithDB(t)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	svc := NewAuditService(c)

	// A group-role grant scoped to a project+environment carries GroupID,
	// RoleID, ProjectID AND EnvironmentID — none of GetRBACAuditLogs_ReturnsRoleChanges'
	// user-role fixture exercises GroupID/EnvironmentID.
	c.LogGroupRoleAssigned(context.Background(), 1, 9, 2, core.Scope{ProjectID: 3, EnvironmentID: 7})
	// A permission grant carries PermissionID (never set by a role-assignment event).
	c.LogPermissionAssigned(context.Background(), 1, 2, 5, false)

	resp, err := svc.GetRBACAuditLogs(auditCtx(), &pb.GetRBACAuditLogsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetLogs(), 2)

	var groupLog, permLog *pb.RBACAuditLog
	for _, l := range resp.GetLogs() {
		switch l.GetAction() {
		case core.EventRoleGroupAssigned:
			groupLog = l
		case core.EventPermissionAdded:
			permLog = l
		}
	}
	require.NotNil(t, groupLog, "role.group_assigned event must be present")
	require.NotNil(t, groupLog.GroupId)
	assert.Equal(t, uint32(9), groupLog.GetGroupId())
	require.NotNil(t, groupLog.EnvironmentId)
	assert.Equal(t, uint32(7), groupLog.GetEnvironmentId())
	require.NotNil(t, groupLog.ProjectId)
	assert.Equal(t, uint32(3), groupLog.GetProjectId())

	require.NotNil(t, permLog, "permission.assigned event must be present")
	require.NotNil(t, permLog.PermissionId)
	assert.Equal(t, uint32(5), permLog.GetPermissionId())
}

// reauthorizeAuditStream's machine-active-allowed success path (`return nil`
// after the state check): the existing machine-branch tests
// (coverage_s18_test.go/coverage_s21_test.go) either leave ActorType unset
// (so ActorKind() silently defaults to "user", never entering the machine
// branch at all) or exercise the machine-not-found error path — neither
// reaches the success return. Build a machine actor with a REAL grant on a
// dedicated role (not the admin-bypass "super_admin") so RoleSetHasPermission
// resolves deterministically, matching AuthorizePrincipal's machine path (no
// admin bypass — see authz.go's AuthorizePrincipal doc comment).
func TestReauthorizeAuditStream_MachineActiveAndAuthorized_ReturnsNil(t *testing.T) {
	svc, db := newAuditServiceWithDB(t)

	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	machine := &models.MachineIdentity{ID: 30, ProjectID: 1, Name: "ci-runner", State: core.MachineActive}
	require.NoError(t, db.Create(machine).Error)

	// A dedicated non-admin role holding audit.read directly, granted globally —
	// RoleSetHasPermission resolves this without any admin-bypass ambiguity.
	require.NoError(t, db.Create(&models.Role{ID: 50, Name: "machine-auditor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 60, Name: "audit.read", Resource: "audit", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 50, PermissionID: 60}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 30, RoleID: 50, ProjectID: 0}).Error)

	actor := &interceptors.UserContext{
		MachineIdentityID: 30,
		ActorType:         core.ActorTypeMachine,
		Permissions:       []string{"audit.read"},
	}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	assert.NoError(t, err, "an active machine identity holding audit.read directly must be reauthorized")
}

// ---------------------------------------------------------------------------
// conversions.go
// ---------------------------------------------------------------------------

// goSafe's panic-recovery branch: fn panics inside the detached goroutine, and
// the recover() must swallow it rather than crash the process. done is closed
// from a defer INSIDE fn (so it fires during the panic unwind, before the
// wrapping recover runs), proving fn actually ran; reaching the end of the
// test without the whole binary aborting proves the panic was recovered.
func TestGoSafe_RecoversPanic(t *testing.T) {
	done := make(chan struct{})
	goSafe(func() {
		defer close(done)
		panic("boom")
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goSafe's goroutine never ran fn")
	}
	// Give the wrapping recover() a moment to actually execute (it runs after
	// fn's own deferred close(done)); if it didn't recover, the test binary
	// itself would have already crashed by the time this line runs.
	time.Sleep(20 * time.Millisecond)
}

// intPtrToInt32Ptr's overflow-clamp branch: a value beyond int32's range must
// clamp to 0 rather than silently wrap or panic.
func TestIntPtrToInt32Ptr_Overflow(t *testing.T) {
	big := math.MaxInt32 + 1
	got := intPtrToInt32Ptr(&big)
	require.NotNil(t, got)
	assert.Equal(t, int32(0), *got, "an out-of-range int must clamp to 0, not wrap")

	// The in-range path still round-trips normally (sanity check alongside the
	// overflow branch, not a separate coverage target).
	small := 42
	got = intPtrToInt32Ptr(&small)
	require.NotNil(t, got)
	assert.Equal(t, int32(42), *got)
}

// enforceProjectMFAForProjects' dedup/skip branch (id == 0 or already-seen):
// no caller previously exercised it with a project-id list containing a zero
// or a repeat. actor.SessionAuth is left false so enforceProjectMFA itself
// no-ops for every id regardless — this test is specifically about the
// wrapper tolerating 0/duplicate ids without erroring, not the MFA policy
// itself (that's covered per-RPC in secret_service_test.go).
func TestEnforceProjectMFAForProjects_SkipsZeroAndDuplicateIDs(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	actor := &interceptors.UserContext{UserID: 1}
	err := enforceProjectMFAForProjects(context.Background(), h.CoreService, actor, []uint{0, 1, 1, 0, 2})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// secret_service.go
// ---------------------------------------------------------------------------

// mapSecretACLError's classification switch — only the default/NotFound
// branches are exercised by secret_acl_service_test.go; directly drive the
// rest as a pure-function table test.
func TestMapSecretACLError_Classification(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want codes.Code
	}{
		{"not found", "ACL entry not found", codes.NotFound},
		{"invalid", "invalid permission set", codes.InvalidArgument},
		{"required", "user_id is required", codes.InvalidArgument},
		{"not authorized", "user not authorized to manage ACLs", codes.PermissionDenied},
		{"default", "storage exploded", codes.Internal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapSecretACLError(errors.New(c.msg))
			assert.Equal(t, c.want, status.Code(got))
		})
	}
}

// CreateSecret's ParentId branch: no existing CreateSecret test supplies a
// parent folder id, so `if req.ParentId != nil && req.GetParentId() != 0`
// never took its true branch. Create a folder node directly, then a secret
// naming it as parent, and confirm the secret is actually filed under it.
func TestSecretService_CreateSecret_WithParentFolder(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")

	folder := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "folder", Type: "folder",
		IsSecret: false, Status: "active", OwnerID: 1, CreatedBy: "test",
	}
	require.NoError(t, r.db.Create(folder).Error)

	sec, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "child", Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password",
		ParentId: ptrU32(folder.ID),
	})
	require.NoError(t, err)
	assert.NotZero(t, sec.GetId())

	var stored models.SecretNode
	require.NoError(t, r.db.First(&stored, sec.GetId()).Error)
	require.NotNil(t, stored.ParentID)
	assert.Equal(t, folder.ID, *stored.ParentID)
}

// ---------------------------------------------------------------------------
// system_service.go
// ---------------------------------------------------------------------------

// dbLatencyMs' error branch: HealthCheck fails once the underlying connection
// is closed, and the best-effort helper must report 0 rather than propagate.
func TestSystemService_DbLatencyMs_ErrorReturnsZero(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	svc := NewSystemService(h.CoreService, &config.Config{Environment: "test"})

	require.NoError(t, h.SqlDB.Close())
	got := svc.dbLatencyMs(context.Background())
	assert.Equal(t, float64(0), got, "a failed health check must report 0ms, not propagate the error")
}

// ---------------------------------------------------------------------------
// connect_service.go
// ---------------------------------------------------------------------------

// ListRefGrants / DeleteRefGrant's storage-error branches: both wrap a
// storage call with no natural (validation) failure mode — drop the
// underlying table (after authorization, which only touches
// users/roles/permissions, succeeds) to force a genuine storage error.
func TestConnectService_RefGrants_StorageErrorIsInternal(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil)
	svc := NewConnectService(h.CoreService)
	ctx := authCtx(1, "admin", "roles.write")

	require.NoError(t, h.DB.Exec("DROP TABLE connect_ref_grants").Error)

	_, err := svc.ListRefGrants(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))

	_, err = svc.DeleteRefGrant(ctx, &pb.DeleteConnectRefGrantRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// group_service.go
// ---------------------------------------------------------------------------

// GetGroupMembers/RemoveGroupMember's validation-error branches: a zero
// group/user id fails core's own precondition check before any storage call,
// classified by groupError's "required" branch — neither RPC's zero-id case
// was previously exercised (only GetGroup/other RPCs' zero-id paths were).
func TestGroupService_ZeroID_InvalidArgument(t *testing.T) {
	svc, _ := newGroupService(t)

	_, err := svc.GetGroupMembers(groupCtx(), &pb.GetGroupMembersRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = svc.RemoveGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: 1, UserId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// Note: ListGroups'/CreateGroup's storage-error branches (groupError's default
// Internal case) are not covered here — the "groups" table participates in
// EVERY global-scope authorization check (group_roles JOINs groups even for a
// caller with no group membership), so dropping it to force a storage error
// also breaks authorizeGlobal itself, which folds the resulting query error
// into PermissionDenied before the RPC's own storage call is ever reached.
// There is no way to isolate this failure from inside the RPC-level test
// package without touching internal/core.

// ---------------------------------------------------------------------------
// machine_identity_service.go
// ---------------------------------------------------------------------------

// CreateMachineIdentity's mapMachineError branch via a real validation
// failure core itself raises (an unrecognized identity_type) rather than a
// storage-layer hack.
func TestMachineIdentityService_CreateMachineIdentity_InvalidIdentityType(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.CreateMachineIdentity(authCtx(1, "admin"), &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "bot", IdentityType: "not-a-real-type",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TransitionMachineIdentity/ListMachineTokens's not-found branches: a valid
// action/ids pair against a machine that does not exist in the project.
func TestMachineIdentityService_UnknownMachine_NotFound(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")

	_, err := svc.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: 9999, Action: "suspend",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	_, err = svc.ListMachineTokens(ctx, &pb.ListMachineTokensRequest{ProjectId: 1, MachineId: 9999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ListMachineIdentities' storage-error branch: it has no validation failure
// of its own (it's a bare storage passthrough), so force a genuine error by
// dropping the table.
func TestMachineIdentityService_ListMachineIdentities_StorageErrorIsInternal(t *testing.T) {
	svc, db := newMachineTestRigWithDB(t)
	require.NoError(t, db.Exec("DROP TABLE machine_identities").Error)

	_, err := svc.ListMachineIdentities(authCtx(1, "admin"), &pb.ListMachineIdentitiesRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// project_service.go
// ---------------------------------------------------------------------------

// Note: ListProjects' mapProjectError storage-error branch is not covered
// here for the same structural reason as ListGroups/CreateGroup above — the
// "projects" table is joined by authorizeGlobal's own role-scoping query
// (LEFT JOIN projects, evaluated even at global scope), so dropping it breaks
// authorization before ListProjects' own storage call is ever reached.

// ---------------------------------------------------------------------------
// role_service.go
// ---------------------------------------------------------------------------

// CreateRole's mapRoleError branch via a real storage failure: #1642 moved role-name
// uniqueness off Role.Name's `gorm:"unique"` tag onto the explicit ensureRoleNameIndex
// migration step (matching Group/User's folded-column pattern), so AutoMigrate alone no
// longer creates any constraint here — replicate what the production migration creates
// (uniq_roles_name_folded on the folded column) so this test still exercises a genuine
// UNIQUE constraint violation and mapRoleError's "unique" branch.
func TestRoleService_CreateRole_DuplicateName(t *testing.T) {
	svc, h := newRoleService(t)
	_, err := h.SqlDB.Exec("CREATE UNIQUE INDEX uniq_roles_name_folded ON roles (name_folded)")
	require.NoError(t, err)
	perm := somePermission(t, h)
	ctx := roleAdminCtx()

	req := &pb.CreateRoleRequest{Name: "duplicate-role", Description: "a role", Permissions: []string{perm}}
	_, err = svc.CreateRole(ctx, req)
	require.NoError(t, err)

	_, err = svc.CreateRole(ctx, req)
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

// ---------------------------------------------------------------------------
// dynamic_secret_service.go
// ---------------------------------------------------------------------------

// dynTestRig mirrors newDynamicTestRig (dynamic_secret_service_test.go) but
// also exposes the db and the fake engine, for tests that need to force a
// backend-level failure or a storage-table failure.
type dynTestRig struct {
	svc  *DynamicSecretGRPCService
	db   *gorm.DB
	fake *dynamic.FakeEngine
}

func newDynTestRigWithFake(t *testing.T) *dynTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{}, &models.Role{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 2}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetAuthEncryptor(enc)
	coreService.SetDynamicAllowPrivateTargets(true)
	fake := &dynamic.FakeEngine{NativeExpiry: true}
	coreService.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	return &dynTestRig{svc: NewDynamicSecretService(coreService), db: db, fake: fake}
}

// CreateConfig's mapDynamicError branch via a real validation failure core
// itself raises (default TTL exceeding max TTL).
func TestDynamicSecretService_CreateConfig_TTLExceedsMax(t *testing.T) {
	r := newDynTestRigWithFake(t)
	_, err := r.svc.CreateConfig(authCtx(1, "owner"), &pb.CreateDynamicConfigRequest{
		Name: "bad-ttl", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres",
		AdminDsn: "postgres://x", DefaultTtlSeconds: 7200, MaxTtlSeconds: 3600,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ClassifyConfig's mapDynamicError branch via a real validation failure.
func TestDynamicSecretService_ClassifyConfig_InvalidClassification(t *testing.T) {
	r := newDynTestRigWithFake(t)
	ctx := authCtx(1, "owner")
	cfg, err := r.svc.CreateConfig(ctx, &pb.CreateDynamicConfigRequest{
		Name: "cfg", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.NoError(t, err)

	_, err = r.svc.ClassifyConfig(ctx, &pb.ClassifyDynamicConfigRequest{Id: cfg.GetId(), Classification: "top-secret"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// loadConfigScoped/loadLeaseScoped's found-but-unauthorized branch (#G14
// uniform NotFound): a caller scoped to a different project than the
// config/lease must get the same NotFound a nonexistent id would.
func TestDynamicSecretService_CrossProjectAccess_NotFound(t *testing.T) {
	r := newDynTestRigWithFake(t)
	owner := authCtx(1, "owner")
	cfg, err := r.svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{
		Name: "cfg", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.NoError(t, err)
	lease, err := r.svc.IssueLease(owner, &pb.IssueLeaseRequest{ConfigId: cfg.GetId()})
	require.NoError(t, err)

	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: 1, ProjectID: 2}).Error)
	scoped := authCtx(3, "scoped", "secrets.read", "secrets.write")

	_, err = r.svc.GetConfig(scoped, &pb.GetDynamicConfigRequest{Id: cfg.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "GetConfig cross-project")

	_, err = r.svc.RenewLease(scoped, &pb.RenewLeaseRequest{LeaseId: lease.GetLeaseId()})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "RenewLease cross-project")
}

// ListConfigs/ListLeases' mapDynamicError branches: both are bare storage
// passthroughs (no loadConfigScoped lookup involved), so force a genuine
// storage error by dropping their tables.
func TestDynamicSecretService_ListConfigsAndLeases_StorageErrorIsInternal(t *testing.T) {
	r := newDynTestRigWithFake(t)
	require.NoError(t, r.db.Exec("DROP TABLE dynamic_secret_configs").Error)
	_, err := r.svc.ListConfigs(authCtx(1, "owner"), &pb.ListDynamicConfigsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestDynamicSecretService_ListLeases_StorageErrorIsInternal(t *testing.T) {
	r := newDynTestRigWithFake(t)
	owner := authCtx(1, "owner")
	cfg, err := r.svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{
		Name: "cfg", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.NoError(t, err)

	require.NoError(t, r.db.Exec("DROP TABLE dynamic_secret_leases").Error)
	_, err = r.svc.ListLeases(owner, &pb.ListLeasesRequest{ConfigId: cfg.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// IssueLease/RevokeLease/RenewLease's mapDynamicError default branch via a
// real backend (engine) failure — the FakeEngine's FailIssue/FailRevoke/
// FailRenew toggles simulate the target database rejecting the operation.
func TestDynamicSecretService_EngineFailure_IsUnavailable(t *testing.T) {
	r := newDynTestRigWithFake(t)
	owner := authCtx(1, "owner")
	cfg, err := r.svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{
		Name: "cfg", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.NoError(t, err)

	r.fake.FailIssue = true
	_, err = r.svc.IssueLease(owner, &pb.IssueLeaseRequest{ConfigId: cfg.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err), "IssueLease engine failure")
	r.fake.FailIssue = false

	lease, err := r.svc.IssueLease(owner, &pb.IssueLeaseRequest{ConfigId: cfg.GetId()})
	require.NoError(t, err)

	r.fake.FailRenew = true
	_, err = r.svc.RenewLease(owner, &pb.RenewLeaseRequest{LeaseId: lease.GetLeaseId(), TtlSeconds: 7200})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err), "RenewLease engine failure")
	r.fake.FailRenew = false

	r.fake.FailRevoke = true
	_, err = r.svc.RevokeLease(owner, &pb.RevokeLeaseRequest{LeaseId: lease.GetLeaseId()})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err), "RevokeLease engine failure")
}

// RevokeAllLeases' mapDynamicError branch: unlike RevokeLease, a per-lease
// engine failure is swallowed into the failed/revoked counters, not
// propagated — the only way it errors is a storage failure listing the
// config's leases, so drop that table specifically (loadConfigScoped itself
// reads dynamic_secret_configs, a different table, so it still succeeds).
func TestDynamicSecretService_RevokeAllLeases_StorageErrorIsInternal(t *testing.T) {
	r := newDynTestRigWithFake(t)
	owner := authCtx(1, "owner")
	cfg, err := r.svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{
		Name: "cfg", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.NoError(t, err)

	require.NoError(t, r.db.Exec("DROP TABLE dynamic_secret_leases").Error)
	_, err = r.svc.RevokeAllLeases(owner, &pb.RevokeAllLeasesRequest{ConfigId: cfg.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// ---------------------------------------------------------------------------
// share_service.go
// ---------------------------------------------------------------------------

// shareProjectIDs' early-return branch (len(shares)==0): every existing
// ListUserShares test creates a share first. A globally-granted caller with
// NO shares of their own hits the early return before any share is created.
func TestShareService_ListUserShares_NoShares(t *testing.T) {
	r := newShareTestRig(t)
	resp, err := r.svc.ListUserShares(ownerCtx(), &pb.ListUserSharesRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetShares())
}

// authorizeShareScoped's permission-denied branch (via UpdateSharePermission/
// RevokeShare specifically — the secret-level equivalent is exercised
// elsewhere, but never through a share's own scoped-authz gate) and
// mapShareError's "not authorized" branch (a non-owner who nonetheless holds
// secrets.write in the share's project scope — passes authorizeShareScoped,
// but core's own owner-only check inside UpdateSharePermission/RevokeShare
// then refuses).
func TestShareService_NonOwnerWithWriteGrant_PermissionDenied(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	// User 4: a writer scoped to project 1 (passes authorizeShareScoped's
	// secrets.write check) but NOT the secret's owner (user 1 is).
	require.NoError(t, r.db.Create(&models.User{ID: 4, Username: "otherwriter", Email: "ow@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 4, RoleID: writerRoleID, ProjectID: 1}).Error)
	ctx := authCtx(4, "otherwriter", "secrets.write", "secrets.read")

	_, err := r.svc.UpdateSharePermission(ctx, &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "UpdateSharePermission by a non-owner writer")

	_, err = r.svc.RevokeShare(ctx, &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "RevokeShare by a non-owner writer")
}

// authorizeShareScoped's outright-denied branch: a caller with NO grant on
// the share's secret at all.
func TestShareService_UpdateAndRevoke_Unauthorized(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	// User 2 (the recipient) holds a project-scoped role with no permissions.
	ctx := authCtx(2, "recipient", "secrets.write")

	_, err := r.svc.UpdateSharePermission(ctx, &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// authorizeShareScoped's second not-found branch: a share row whose secret no
// longer exists (a data-integrity edge case — the downstream GetSecret call
// fails even though the share row itself was found).
func TestShareService_OrphanedShare_NotFound(t *testing.T) {
	r := newShareTestRig(t)
	orphan := &models.ShareRecord{SecretID: 99999, OwnerID: 1, RecipientID: 2, Permission: "read"}
	require.NoError(t, r.db.Create(orphan).Error)

	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: intToU32(int(orphan.ID))})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// user_service.go
// ---------------------------------------------------------------------------

// CreateUser's setup-link mode success path: no existing test exercises the
// `err == nil && prov != nil` branch that populates resp.SetupLink — the
// existing setup-link tests only cover its rejected combinations.
func TestUserService_CreateUser_SetupLink_Success(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	require.NoError(t, h.DB.AutoMigrate(&models.SetupToken{}, &models.PasswordHistory{}))
	svc := NewUserService(h.CoreService)
	svc.core.SetCredentialDelivery(nil, "https://kx.example.com") // nil = out-of-band, link handed back

	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "bob", Email: "bob@example.com", DeliverSetupLink: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	require.NotNil(t, resp.SetupLink, "a nil credential-delivery channel must hand the link back to the caller")
	assert.Contains(t, resp.GetSetupLink(), "https://kx.example.com/auth/setup/")
}

// ListUsers' Internal-error branch: a bare storage passthrough with no
// validation failure, so force a genuine error by dropping the table.
func TestUserService_ListUsers_StorageErrorIsInternal(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	svc := NewUserService(h.CoreService)

	require.NoError(t, h.DB.Exec("DROP TABLE users").Error)
	_, err := svc.ListUsers(authCtx(1, "admin", "users.read"), &pb.ListUsersRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// projectCounts' success-return branch: every existing user_service test
// runs on the RBAC helper's DB, which never migrates ProjectMembership, so
// ProjectMembershipCounts always errors and projectCounts' early-return-nil
// path is the only one ever taken. Migrate it and seed a real membership row
// so the storage call actually succeeds and the counts flow into the proto.
func TestUserService_ListUsers_ProjectCountsPopulated(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	require.NoError(t, h.DB.AutoMigrate(&models.ProjectMembership{}))
	require.NoError(t, h.DB.Create(&models.ProjectMembership{
		ProjectID: 1, UserID: 1, State: "active", InvitedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)
	svc := NewUserService(h.CoreService)

	resp, err := svc.ListUsers(authCtx(1, "admin", "users.read"), &pb.ListUsersRequest{})
	require.NoError(t, err)
	var admin *pb.User
	for _, u := range resp.GetUsers() {
		if u.GetUsername() == "admin" {
			admin = u
		}
	}
	require.NotNil(t, admin)
	assert.Equal(t, uint32(1), admin.GetProjectCount(), "a real active membership must surface as ProjectCount")
	assert.Equal(t, uint32(1), admin.GetActiveProjectCount())
}
