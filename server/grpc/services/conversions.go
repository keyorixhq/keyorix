// conversions.go — helpers shared across the gRPC service implementations
// (ADR Phase-2 split): caller identity, permission checks, proto<->model
// conversion, and the pagination defaults the paginated list RPCs share. These
// were previously scattered through secret_service.go / share_service.go; they
// live here so each service file holds only its own RPC methods.
package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/utils/safeconv"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Identity & authorization ---

func requireUser(ctx context.Context) (*interceptors.UserContext, error) {
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}
	return user, nil
}

// hasPermission reports flat membership in the caller's permission union. Use it
// ONLY for self-scoped reads (a caller listing their OWN shares), where the result
// set is already filtered to the caller and no cross-tenant access is possible. For
// anything that reads or mutates another tenant's / global state, use
// authorizeScoped / authorizeGlobal instead (see the bug-class note below).
func hasPermission(permissions []string, required string) bool {
	for _, p := range permissions {
		if p == required {
			return true
		}
	}
	return false
}

// authorizeScoped enforces perm at the given scope via core.Authorize — the same
// scope-aware path HTTP uses. This is the ONLY authorization primitive the services
// use: an earlier flat `hasPermission(user.Permissions, …)` check treated a
// permission held only at one project's scope as if held everywhere, because
// UserContext.Permissions is the FLAT union of the caller's grants across every
// scope (the #53/#54/#88/#90 flat-vs-scoped bug class). Routing through
// core.Authorize fixes that and future-proofs the PAT/machine paths.
func authorizeScoped(ctx context.Context, cs *core.KeyorixCore, userID uint, perm string, scope core.Scope) error {
	if allowed, err := cs.Authorize(ctx, userID, perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions")
	}
	return nil
}

// authorizeGlobal enforces perm at global scope (project 0) — for install-wide
// operations (user/role/system/audit management) that HTTP gates with
// RequirePermission. A grant held only at a project scope does NOT satisfy it.
func authorizeGlobal(ctx context.Context, cs *core.KeyorixCore, userID uint, perm string) error {
	return authorizeScoped(ctx, cs, userID, perm, core.Scope{})
}

// --- Pagination ---

// normalizePage applies the standard page (>=1) / page_size (1..100, default 20)
// defaults shared by the paginated list RPCs.
func normalizePage(page, pageSize uint32) (int, int) {
	p := int(page)
	if p < 1 {
		p = 1
	}
	ps := int(pageSize)
	if ps < 1 || ps > 100 {
		ps = 20
	}
	return p, ps
}

func totalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	return (total + pageSize - 1) / pageSize
}

// --- Proto <-> model conversion ---

func secretNodeToProto(n *models.SecretNode) *pb.Secret {
	return &pb.Secret{
		Id:            intToU32(int(n.ID)),
		Name:          n.Name,
		ProjectId:     intToU32(int(n.ProjectID)),
		EnvironmentId: intToU32(int(n.EnvironmentID)),
		Type:          n.Type,
		MaxReads:      intPtrToInt32Ptr(n.MaxReads),
		Expiration:    timePtrToTs(n.Expiration),
		Metadata:      metadataToMap(n.Metadata),
		Tags:          []string{}, // tags are not stored on the secret node
		Status:        n.Status,
		CreatedBy:     n.CreatedBy,
		OwnerId:       intToU32(int(n.OwnerID)),
		CreatedAt:     timestamppb.New(n.CreatedAt),
		UpdatedAt:     timestamppb.New(n.UpdatedAt),
		IsShared:      n.IsShared,
	}
}

func sharingInfoToProto(s *models.SecretWithSharingInfo) *pb.Secret {
	out := secretNodeToProto(s.SecretNode)
	out.ProjectName = s.ProjectName
	out.EnvironmentName = s.EnvironmentName
	out.IsShared = s.IsShared
	out.IsOwnedByUser = s.IsOwnedByUser
	out.UserPermission = s.UserPermission
	out.ShareCount = intToU32(s.ShareCount)
	return out
}

func metadataToMap(raw models.JSON) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	m := map[string]string{}
	_ = json.Unmarshal(raw, &m) // best-effort; non-string maps yield empty
	return m
}

// --- Numeric / time / optional conversions ---
// Overflow is unrealistic for IDs/counts; clamp on the off chance rather than
// failing the RPC.

func intToU32(v int) uint32 {
	x, err := safeconv.UintToUint32(uint(v))
	if err != nil || v < 0 {
		return 0
	}
	return x
}

func i64ToU32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	return intToU32(int(v))
}

func intPtrToInt32Ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v, err := safeconv.IntToInt32(*p)
	if err != nil {
		v = 0
	}
	return &v
}

func int32PtrToIntPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

func tsToTimePtr(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func timePtrToTs(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optString(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

func optUint(p *uint32) *uint {
	if p == nil || *p == 0 {
		return nil
	}
	v := uint(*p)
	return &v
}
