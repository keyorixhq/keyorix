package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)


// SecretGRPCService implements pb.SecretServiceServer, backing each RPC with the
// shared core service. Authentication/identity is established by the auth
// interceptor (see interceptors.AuthInterceptor) and read from the context.
type SecretGRPCService struct {
	pb.UnimplementedSecretServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.SecretServiceServer = (*SecretGRPCService)(nil)

const errSecretIDRequired = "secret_id is required" // #nosec G101 -- error message string, not a hardcoded credential

// NewSecretService creates a secret gRPC service backed by the shared core.
func NewSecretService(coreService *core.KeyorixCore) *SecretGRPCService {
	return &SecretGRPCService{core: coreService}
}

// CreateSecret creates a new secret.
func (s *SecretGRPCService) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" || req.GetValue() == "" || req.GetProjectId() == 0 || req.GetEnvironmentId() == 0 || req.GetType() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, value, project_id, environment_id and type are required")
	}
	// Authorize secrets.write AT THE TARGET project/environment, not the flat
	// global permission set — a project-scoped writer must not create in another
	// project. Mirrors the HTTP CreateSecret handler (scope from the body).
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if allowed, err := s.core.AuthorizePrincipal(ctx, user.ActorKind(), user.PrincipalID(), permSecretsWrite, scope); err != nil || !allowed {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to create secrets in this project")
	}
	if err := enforceProjectMFA(ctx, s.core, user, scope.ProjectID); err != nil {
		return nil, err
	}

	coreReq := &core.CreateSecretRequest{
		Name:          req.GetName(),
		Value:         []byte(req.GetValue()),
		ProjectID:     uint(req.GetProjectId()),
		EnvironmentID: uint(req.GetEnvironmentId()),
		Type:          req.GetType(),
		MaxReads:      int32PtrToIntPtr(req.MaxReads),
		Expiration:    tsToTimePtr(req.GetExpiration()),
		Metadata:      req.GetMetadata(),
		Tags:          req.GetTags(),
		CreatedBy:     user.Username,
		OwnerID:       user.UserID,
	}
	if req.ParentId != nil && req.GetParentId() != 0 {
		pID := uint(req.GetParentId())
		coreReq.ParentID = &pID
	}
	secret, err := s.core.CreateSecret(ctx, coreReq)
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the create the same way the HTTP handler does — the core method does not
	// audit internally, so without this a secret created over gRPC left no audit
	// trail. Detached + async (see GetSecretValue).
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretCreatedWithProject(auditCtx, user.UserID, secret.ID, secret.ProjectID, user.Username, secret.Name, ip, ua)
	}) // #nosec G118
	return secretNodeToProto(secret), nil
}

// GetSecret returns a secret's metadata (subject to ownership/share checks).
func (s *SecretGRPCService) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	secret, err := s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretNodeToProto(secret), nil
}

// ListSecretDependencies returns a secret's direct dependencies and dependents
// (ADR-052). Requires scoped secrets.read on the secret's project/environment.
func (s *SecretGRPCService) ListSecretDependencies(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretDependencies, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	deps, err := s.core.ListSecretDependencies(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretDependenciesToProto(deps), nil
}

// GetSecretImpact returns the blast radius of rotating a secret — its transitive
// dependents (ADR-052). Requires scoped secrets.read.
func (s *SecretGRPCService) GetSecretImpact(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretImpact, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	impact, err := s.core.GetSecretImpact(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretImpactToProto(impact), nil
}

// GetSecretValue returns a secret's decrypted value (counts toward max_reads).
// version_number/read_count are not populated here — use GetSecretVersions for
// version history.
func (s *SecretGRPCService) GetSecretValue(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretValue, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	// Resolve the name first (metadata read, no read-count side effect).
	secret, err := s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	value, err := s.core.GetSecretValueWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Record the read in the audit trail and secret-access log — the same call the
	// HTTP reveal handler fires. Without it, a secret read over gRPC left no
	// secret.read event and no access-log row, so the anomaly detector never saw it:
	// secrets could be exfiltrated over gRPC invisibly to both the audit trail and
	// anomaly detection. Detached + async like HTTP, so it neither blocks the RPC nor
	// dies on its cancellation; DetachedAuditContext preserves the actor-type and
	// impersonation tags the interceptor set.
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretReadWithProject(auditCtx, user.UserID, uint(req.GetId()), secret.ProjectID, user.Username, secret.Name, ip, ua)
	}) // #nosec G118
	return &pb.SecretValue{
		Id:    req.GetId(),
		Name:  secret.Name,
		Value: string(value),
	}, nil
}

// UpdateSecret updates a secret; a non-empty value rotates it to a new version.
func (s *SecretGRPCService) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsWrite); err != nil {
		return nil, err
	}

	updateReq := &core.UpdateSecretRequest{
		ID:         uint(req.GetId()),
		MaxReads:   int32PtrToIntPtr(req.MaxReads),
		Expiration: tsToTimePtr(req.GetExpiration()),
		Metadata:   req.GetMetadata(),
		Tags:       req.GetTags(),
		UpdatedBy:  user.Username,
		UserID:     user.UserID,
	}
	if v := req.GetValue(); v != "" {
		updateReq.Value = []byte(v)
	}

	// Capture pre-update metadata for the audit diff (raw fetch, no read-count side
	// effect). Best-effort: a miss just yields an empty diff — same as the HTTP path.
	oldSecret, _ := s.core.Storage().GetSecret(ctx, uint(req.GetId()))

	secret, err := s.core.UpdateSecretWithPermissionCheck(ctx, updateReq)
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the update with a before/after diff, mirroring the HTTP handler — the
	// core method does not audit internally. Detached + async (see GetSecretValue).
	diff := core.BuildSecretUpdateDiff(oldSecret, updateReq, req.GetValue() != "")
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretUpdatedWithDiff(auditCtx, user.UserID, uint(req.GetId()), secret.ProjectID, user.Username, secret.Name, ip, ua, diff)
	}) // #nosec G118
	return secretNodeToProto(secret), nil
}

// DeleteSecret deletes a secret (owner-only, enforced by core).
func (s *SecretGRPCService) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.delete"); err != nil {
		return nil, err
	}
	// Pre-fetch name + project for the audit log before the record is gone, mirroring
	// the HTTP handler. Best-effort: a miss falls back to the id.
	secretName := fmt.Sprintf("id=%d", req.GetId())
	var secretProjectID uint
	if sec, err := s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID); err == nil {
		secretName = sec.Name
		secretProjectID = sec.ProjectID
	}
	if err := s.core.DeleteSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID); err != nil {
		return nil, mapSecretError(err)
	}
	// Audit the delete the same way the HTTP handler does — the core method does not
	// audit internally. Detached + async (see GetSecretValue).
	auditCtx := core.DetachedAuditContext(ctx)
	ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
	goSafe(func() {
		s.core.LogSecretDeletedWithProject(auditCtx, user.UserID, uint(req.GetId()), secretProjectID, user.Username, secretName, ip, ua)
	}) // #nosec G118
	return &emptypb.Empty{}, nil
}

// SetSecretAutoRotate enables/disables automated rotation for a secret and sets its
// generated-value shape (ADR-046). Scoped secrets.write, mirroring the HTTP endpoint.
func (s *SecretGRPCService) SetSecretAutoRotate(ctx context.Context, req *pb.SetSecretAutoRotateRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsWrite); err != nil {
		return nil, err
	}
	if err := s.core.SetSecretAutoRotate(ctx, uint(req.GetId()), core.AutoRotateSpec{
		Enabled: req.GetEnabled(), Length: int(req.GetLength()), Charset: req.GetCharset(),
		Backend: req.GetBackend(), Ref: req.GetRef(),
	}, user.PrincipalID()); err != nil {
		return nil, mapSecretError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListSecrets lists secrets visible to the caller with sharing context.
func (s *SecretGRPCService) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	// Authorize at the requested project/environment scope (mirrors the HTTP list
	// route's ScopeFromQuery); 0/0 means global. ListSecretsWithSharingInfo then
	// filters the results to what the caller may actually see.
	listScope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if allowed, err := s.core.AuthorizePrincipal(ctx, user.ActorKind(), user.PrincipalID(), permSecretsRead, listScope); err != nil || !allowed {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to list secrets")
	}
	if err := enforceProjectMFA(ctx, s.core, user, listScope.ProjectID); err != nil {
		return nil, err
	}

	page := int(req.GetPage())
	if page < 1 {
		page = 1
	}
	pageSize := int(req.GetPageSize())
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	filter := &models.SecretListFilter{
		Search:         optString(req.Search),
		ProjectID:      optUint(req.ProjectId),
		EnvironmentID:  optUint(req.EnvironmentId),
		Type:           optString(req.Type),
		Permission:     req.GetPermission(),
		ShowOwnedOnly:  req.GetShowOwnedOnly(),
		ShowSharedOnly: req.GetShowSharedOnly(),
		Page:           page,
		PageSize:       pageSize,
		ParentID:       optUint(req.ParentId),
		FolderOnly:     req.GetFolderOnly(),
	}

	resp, err := s.core.ListSecretsWithSharingInfo(ctx, user.UserID, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list secrets")
	}

	secrets := make([]*pb.Secret, 0, len(resp.Secrets))
	for _, sec := range resp.Secrets {
		secrets = append(secrets, sharingInfoToProto(sec))
	}
	return &pb.ListSecretsResponse{
		Secrets:     secrets,
		Total:       i64ToU32(resp.Total),
		Page:        intToU32(resp.Page),
		PageSize:    intToU32(resp.PageSize),
		TotalPages:  intToU32(resp.TotalPages),
		OwnedCount:  intToU32(resp.OwnedCount),
		SharedCount: intToU32(resp.SharedCount),
	}, nil
}

// GetSecretVersions returns a secret's version history (subject to access checks).
func (s *SecretGRPCService) GetSecretVersions(ctx context.Context, req *pb.GetSecretVersionsRequest) (*pb.GetSecretVersionsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), permSecretsRead); err != nil {
		return nil, err
	}
	versions, err := s.core.GetSecretVersionsWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	// Audit as a secret read, mirroring the HTTP handler (secrets_versions.go) —
	// without this, listing version history over gRPC left no secret.read event,
	// an HTTP<->gRPC audit-parity gap invisible to anomaly detection (#168).
	// Best-effort metadata fetch, same as HTTP: a miss just skips the audit call.
	if secret, sErr := s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID); sErr == nil && secret != nil {
		auditCtx := core.DetachedAuditContext(ctx)
		ip, ua := interceptors.PeerIP(ctx), interceptors.ClientUserAgent(ctx)
		goSafe(func() {
			s.core.LogSecretReadWithProject(auditCtx, user.UserID, uint(req.GetId()), secret.ProjectID, user.Username, secret.Name, ip, ua)
		}) // #nosec G118
	}
	out := make([]*pb.SecretVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, &pb.SecretVersion{
			VersionNumber: intToU32(v.VersionNumber),
			CreatedAt:     timestamppb.New(v.CreatedAt),
			ReadCount:     intToU32(v.ReadCount),
		})
	}
	return &pb.GetSecretVersionsResponse{Versions: out}, nil
}

// GrantSecretACL grants (or updates) a per-secret ACL for a user.
// Requires secrets.manage at the secret's project scope.
func (s *SecretGRPCService) GrantSecretACL(ctx context.Context, req *pb.GrantSecretACLRequest) (*pb.SecretACLEntry, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errSecretIDRequired)
	}
	if req.GetUserId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if len(req.GetPermissions()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one permission is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsManage); err != nil {
		return nil, err
	}
	if err := s.core.GrantSecretACL(ctx, user.UserID, uint(req.GetSecretId()), uint(req.GetUserId()), req.GetPermissions()); err != nil {
		return nil, mapSecretACLError(err)
	}
	// Re-fetch so we can return the created/updated row with its ID and timestamps.
	acls, err := s.core.ListSecretACLs(ctx, uint(req.GetSecretId()))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to retrieve created ACL")
	}
	for _, a := range acls {
		if a.UserID == uint(req.GetUserId()) {
			return secretACLToProto(a), nil
		}
	}
	return nil, status.Error(codes.Internal, "ACL created but not found on re-fetch")
}

// RevokeSecretACL removes a per-secret ACL entry by its ID.
// Requires secrets.manage at the secret's project scope.
func (s *SecretGRPCService) RevokeSecretACL(ctx context.Context, req *pb.RevokeSecretACLRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errSecretIDRequired)
	}
	if req.GetAclId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "acl_id is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsManage); err != nil {
		return nil, err
	}
	if err := s.core.RevokeSecretACL(ctx, user.UserID, uint(req.GetSecretId()), uint(req.GetAclId())); err != nil {
		return nil, mapSecretACLError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListSecretACLs returns all ACL grants for a secret.
// Requires secrets.manage at the secret's project scope.
func (s *SecretGRPCService) ListSecretACLs(ctx context.Context, req *pb.ListSecretACLsRequest) (*pb.ListSecretACLsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errSecretIDRequired)
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetSecretId()), permSecretsManage); err != nil {
		return nil, err
	}
	acls, err := s.core.ListSecretACLs(ctx, uint(req.GetSecretId()))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list ACLs")
	}
	entries := make([]*pb.SecretACLEntry, 0, len(acls))
	for _, a := range acls {
		entries = append(entries, secretACLToProto(a))
	}
	return &pb.ListSecretACLsResponse{Acls: entries}, nil
}

// secretACLToProto converts a models.SecretACL to its proto representation.
func secretACLToProto(a *models.SecretACL) *pb.SecretACLEntry {
	perms := core.DecodeSecretACLPerms(a.Permissions)
	return &pb.SecretACLEntry{
		Id:          uint64(a.ID),
		SecretId:    uint64(a.SecretID),
		UserId:      uint64(a.UserID),
		Permissions: perms,
		GrantedBy:   uint64(a.GrantedBy),
		CreatedAt:   a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// mapSecretACLError translates core ACL errors into gRPC status codes.
func mapSecretACLError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "ACL or secret not found")
	case strings.Contains(msg, "invalid"), strings.Contains(msg, "required"):
		return status.Error(codes.InvalidArgument, msg)
	case strings.Contains(msg, "not authorized"):
		return status.Error(codes.PermissionDenied, msg)
	default:
		return status.Error(codes.Internal, "ACL operation failed")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// requireUser returns the authenticated user from the context or an
// Unauthenticated error. The auth interceptor populates this on every
// non-public RPC.
// authorizeSecretScoped resolves a secret's project/environment and checks the
// permission AT that scope — mirroring the HTTP RequireScopedPermission gate, so
// gRPC enforces the same scoped-RBAC model as HTTP rather than the flat, global
// permission set. A missing secret yields NotFound (not PermissionDenied) to
// avoid leaking existence; the downstream *WithPermissionCheck core calls still
// enforce ownership/share on top of this.
func authorizeSecretScoped(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, secretID uint, perm string) error {
	secret, err := cs.Storage().GetSecret(ctx, secretID)
	if err != nil {
		return status.Error(codes.NotFound, "secret not found")
	}
	scope := core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	if allowed, err := cs.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions for this secret")
	}
	return enforceProjectMFA(ctx, cs, actor, scope.ProjectID)
}

// mapSecretError translates core errors into gRPC status codes.
func mapSecretError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "secret not found")
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "access denied"):
		return status.Error(codes.PermissionDenied, "access denied to this secret")
	case strings.Contains(msg, "already exists"):
		return status.Error(codes.AlreadyExists, "secret with this name already exists")
	case strings.Contains(msg, "unknown rotation charset"), strings.Contains(msg, "out of range"),
		strings.Contains(msg, "must be set together"), strings.Contains(msg, "unknown rotation backend"),
		strings.Contains(msg, "no rotation backends"), strings.Contains(msg, "exceeds"):
		return status.Error(codes.InvalidArgument, msg)
	default:
		return status.Error(codes.Internal, "secret operation failed")
	}
}

// Shared proto-conversion, pagination, and identity helpers live in conversions.go.
