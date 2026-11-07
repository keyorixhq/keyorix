package services

// ShareService.RevokeShare is allowed to the secret's owner and to an administrator of
// the secret's scope; UpdateSharePermission stays owner-only. A project member who only
// holds secrets.write is refused on both.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestShareService_RevokeShare_AdminAndMember(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	// User 3: holds secrets.manage (plus write/read) in project 1, not the owner.
	// User 4: write-tier member of project 1 without secrets.manage, not the owner.
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "padmin", Email: "padmin@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.Permission{ID: 4, Name: "secrets.manage", Resource: "secrets", Action: "manage"}).Error)
	require.NoError(t, r.db.Create(&models.Role{ID: 98, Name: "secret-manager"}).Error)
	for _, pid := range []uint{1, 2, 4} {
		require.NoError(t, r.db.Create(&models.RolePermission{RoleID: 98, PermissionID: pid}).Error)
	}
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: 98, ProjectID: 1}).Error)
	require.NoError(t, r.db.Create(&models.User{ID: 4, Username: "member", Email: "member@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 4, RoleID: writerRoleID, ProjectID: 1}).Error)
	adminCtx := authCtx(3, "padmin", "secrets.write", "secrets.read", "secrets.manage")
	memberCtx := authCtx(4, "member", "secrets.write", "secrets.read")

	// The member is refused on revoke and update, and nothing changes.
	_, err := r.svc.RevokeShare(memberCtx, &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)
	_, err = r.svc.UpdateSharePermission(memberCtx, &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)

	// The administrator is refused on update, allowed on revoke.
	_, err = r.svc.UpdateSharePermission(adminCtx, &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)
	_, err = r.core.Storage().GetShareRecord(adminCtx, uint(rec.GetId()))
	require.NoError(t, err, "a refused update/revoke leaves the share in place")

	_, err = r.svc.RevokeShare(adminCtx, &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.NoError(t, err)
	_, err = r.core.Storage().GetShareRecord(adminCtx, uint(rec.GetId()))
	assert.Error(t, err, "the share is gone")
}

func TestShareService_RevokeShare_Owner(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.NoError(t, err)
}
