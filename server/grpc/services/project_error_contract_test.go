package services

// REVFIX-3790-1: the typed mappers (CORE-GRPC-TAILS-1) only see what core really
// returns, so these tests drive core end to end instead of feeding a hand-made
// sentinel. A duplicate project name reaches the transport as core's translated
// validation error, and the two race windows below reach it as core's own
// not-found errors; each must keep the status the old text match gave it.

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// projectNameIndexSQL is the partial unique index ensureProjectNameIndex
// (internal/storage/factory.go) creates; the gRPC rig's AutoMigrate omits it.
const projectNameIndexSQL = "CREATE UNIQUE INDEX IF NOT EXISTS uniq_projects_name_active " +
	"ON projects (LOWER(name)) WHERE deleted_at IS NULL AND name <> ''"

func TestProjectService_DuplicateName_AlreadyExists(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	require.NoError(t, db.Exec(projectNameIndexSQL).Error)
	ctx := authCtx(1, "owner")

	_, err := svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: "payments"})
	require.NoError(t, err)

	_, err = svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: "Payments"})
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "create dup: %v", err)
	assert.Equal(t, "a project with this name already exists", status.Convert(err).Message())

	// Rename the seeded "default" project onto the taken name.
	_, err = svc.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 1, Name: "payments"})
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "update dup: %v", err)
	assert.Equal(t, "a project with this name already exists", status.Convert(err).Message())
}

// softDeleteProjectDuring registers a one-shot GORM callback that soft-deletes
// project id inside the statement's own transaction, around the first statement
// of kind op on table (before an update, after a create): the deterministic form
// of a concurrent DeleteProject landing between core's pre-read and its
// liveness-checked write.
func softDeleteProjectDuring(t *testing.T, db *gorm.DB, op, table string, id uint) {
	t.Helper()
	var once sync.Once
	fn := func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		once.Do(func() {
			require.NoError(t, tx.Session(&gorm.Session{NewDB: true}).
				Exec("UPDATE projects SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", id).Error)
		})
	}
	switch op {
	case "update":
		require.NoError(t, db.Callback().Update().Before("gorm:update").Register("revfix3790:"+table, fn))
	case "create":
		require.NoError(t, db.Callback().Create().After("gorm:create").Register("revfix3790:"+table, fn))
	default:
		t.Fatalf("unknown op %q", op)
	}
}

func TestProjectService_UpdateProject_DeletedMidUpdate_NotFound(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	ctx := authCtx(1, "owner")
	softDeleteProjectDuring(t, db, "update", "projects", 1)

	_, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 1, Name: "renamed"})
	assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
}

func TestSecretService_CreateSecret_ProjectDeletedMidCreate_NotFound(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	softDeleteProjectDuring(t, r.db, "create", "secret_nodes", 1)

	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "late", Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
}

// REVFIX-3790-3: CreateSecret's target-environment checks (core secrets.go
// pre-check and withEnvironmentSecretGuard's in-lock re-check) return
// core.ErrSecretTargetInvalid, not storage.ErrEnvironmentNotFound. The old text
// match answered NotFound for "environment N not found"; the typed mapper must
// too, and the cross-project text ("does not belong to project") answers the same
// code so a caller cannot tell a foreign environment from a missing one.
func TestSecretService_CreateSecret_BadTargetEnvironment_NotFound(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.Exec("INSERT INTO projects (id, name) VALUES (2, 'other')").Error)
	require.NoError(t, r.db.Exec("INSERT INTO environments (id, project_id, name) VALUES (2, 2, 'staging')").Error)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	for name, envID := range map[string]uint32{"missing environment": 777, "environment of another project": 2} {
		_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
			Name: "orphan", Value: "v", ProjectId: 1, EnvironmentId: envID, Type: "password",
		})
		assert.Equal(t, codes.NotFound, status.Code(err), "%s: %v", name, err)
		assert.Equal(t, "secret not found", status.Convert(err).Message(), name)
	}
}
