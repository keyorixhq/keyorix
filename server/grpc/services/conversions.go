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

// authorizeScoped enforces perm at the given scope via core.Authorize — the same
// scope-aware path HTTP uses. This is the ONLY authorization primitive the services
// use: an earlier flat `hasPermission(user.Permissions, …)` check treated a
// permission held only at one project's scope as if held everywhere, because
// UserContext.Permissions is the FLAT union of the caller's grants across every
// scope (the #53/#54/#88/#90 flat-vs-scoped bug class). Routing through
// core.Authorize fixes that and future-proofs the PAT/machine paths.
func authorizeScoped(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, perm string, scope core.Scope) error {
	// AuthorizePrincipal is actor-aware: for a user it is identical to Authorize
	// (PAT restriction + roles + admin bypass); for a machine identity it resolves
	// machine roles with NO admin bypass. This is what makes machine tokens work
	// over gRPC (ADR-030) with the same primitive HTTP uses.
	if allowed, err := cs.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions")
	}
	return enforceProjectMFA(ctx, cs, actor, scope.ProjectID)
}

// enforceProjectMFA applies the per-project MFA policy (ADR-037) over gRPC: an
// interactive session WITHOUT a second factor is denied access to a project that
// requires MFA. It mirrors the HTTP ProjectMFABlocked gate so the policy is not
// bypassable by switching transport. Non-interactive callers (PAT / machine) are
// exempt — SessionAuth is false for them — and a global-scoped operation (project
// 0) is never gated. Called after the permission check at every project-scoped
// authorization chokepoint. Fails closed only on a positive requirement; a lookup
// error leaves the prior permission decision in force (matching HTTP).
func enforceProjectMFA(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, projectID uint) error {
	if projectID == 0 || cs == nil || actor == nil {
		return nil
	}
	if !actor.SessionAuth || actor.MFAEnabled {
		return nil
	}
	if required, err := cs.ProjectRequiresMFA(ctx, projectID); err == nil && required {
		return status.Error(codes.PermissionDenied,
			"this project requires multi-factor authentication; enrol a second factor to access it")
	}
	return nil
}

// authorizeGlobal enforces perm at global scope (project 0) — for install-wide
// operations (user/role/system/audit management) that HTTP gates with
// RequirePermission. A grant held only at a project scope does NOT satisfy it.
func authorizeGlobal(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, perm string) error {
	return authorizeScoped(ctx, cs, actor, perm, core.Scope{})
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

// --- Secret dependency graph (ADR-052) ---

func dependencyEdgeToProto(e core.DependencyEdge) *pb.DependencyEdge {
	return &pb.DependencyEdge{
		Id:         intToU32(int(e.ID)),
		SecretId:   intToU32(int(e.SecretID)),
		SecretName: e.SecretName,
		Note:       e.Note,
	}
}

func secretDependenciesToProto(d *core.SecretDependencies) *pb.SecretDependencies {
	out := &pb.SecretDependencies{SecretId: intToU32(int(d.SecretID))}
	for _, e := range d.DependsOn {
		out.DependsOn = append(out.DependsOn, dependencyEdgeToProto(e))
	}
	for _, e := range d.Dependents {
		out.Dependents = append(out.Dependents, dependencyEdgeToProto(e))
	}
	return out
}

func secretImpactToProto(im *core.SecretImpact) *pb.SecretImpact {
	out := &pb.SecretImpact{SecretId: intToU32(int(im.SecretID)), SecretName: im.SecretName}
	for _, a := range im.Affected {
		out.Affected = append(out.Affected, &pb.ImpactedSecret{
			SecretId:   intToU32(int(a.SecretID)),
			SecretName: a.SecretName,
			Depth:      intToI32(a.Depth), // depth is a small non-negative hop count
		})
	}
	return out
}

func rotationPlanToProto(p *core.RotationPlan) *pb.RotationPlan {
	out := &pb.RotationPlan{
		ProjectId:    intToU32(int(p.ProjectID)),
		TotalSecrets: intToI32(p.TotalSecrets),
		OverdueCount: intToI32(p.OverdueCount),
		DueSoonCount: intToI32(p.DueSoonCount),
	}
	for _, w := range p.Waves {
		pw := &pb.RotationWave{Index: intToI32(w.Index)}
		for _, s := range w.Secrets {
			after := make([]uint32, 0, len(s.AfterSecretIDs))
			for _, id := range s.AfterSecretIDs {
				after = append(after, intToU32(int(id)))
			}
			pw.Secrets = append(pw.Secrets, &pb.PlannedRotation{
				SecretId:       intToU32(int(s.SecretID)),
				SecretName:     s.SecretName,
				Status:         s.Status,
				DaysOverdue:    intToI32(s.DaysOverdue),
				RiskScore:      intToI32(s.RiskScore),
				RiskBand:       s.RiskBand,
				Urgency:        intToI32(s.Urgency),
				AutoRotate:     s.AutoRotate,
				AfterSecretIds: after,
				Reasons:        s.Reasons,
			})
		}
		out.Waves = append(out.Waves, pw)
	}
	return out
}

func rotationOrderToProto(o *core.RotationOrder) *pb.RotationOrder {
	out := &pb.RotationOrder{ProjectId: intToU32(int(o.ProjectID))}
	for _, s := range o.Order {
		out.Order = append(out.Order, &pb.RotationStep{SecretId: intToU32(int(s.SecretID)), SecretName: s.SecretName})
	}
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

// intToI32 safely narrows int → int32 (gosec G115), clamping on overflow.
func intToI32(v int) int32 {
	x, err := safeconv.IntToInt32(v)
	if err != nil {
		return 0
	}
	return x
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

func projectToProto(p *models.Project) *pb.Project {
	return &pb.Project{
		Id:          intToU32(int(p.ID)),
		Name:        p.Name,
		Description: p.Description,
		RequireMfa:  p.RequireMFA,
		CreatedAt:   timestamppb.New(p.CreatedAt),
		UpdatedAt:   timestamppb.New(p.UpdatedAt),
	}
}

func environmentToProto(e *models.Environment) *pb.Environment {
	return &pb.Environment{
		Id:        intToU32(int(e.ID)),
		ProjectId: intToU32(int(e.ProjectID)),
		Name:      e.Name,
		CreatedAt: timestamppb.New(e.CreatedAt),
		UpdatedAt: timestamppb.New(e.UpdatedAt),
	}
}

func machineIdentityToProto(m *models.MachineIdentity) *pb.MachineIdentity {
	return &pb.MachineIdentity{
		Id:             intToU32(int(m.ID)),
		ProjectId:      intToU32(int(m.ProjectID)),
		Name:           m.Name,
		IdentityType:   m.IdentityType,
		State:          m.State,
		Description:    m.Description,
		Classification: m.Classification,
		CreatedBy:      intToU32(int(m.CreatedBy)),
		CreatedAt:      timestamppb.New(m.CreatedAt),
		UpdatedAt:      timestamppb.New(m.UpdatedAt),
		LastSeenAt:     timePtrToTs(m.LastSeenAt),
		RevokedAt:      timePtrToTs(m.RevokedAt),
	}
}

func dynamicConfigToProto(c *models.DynamicSecretConfig) *pb.DynamicSecretConfig {
	return &pb.DynamicSecretConfig{
		Id:                intToU32(int(c.ID)),
		Name:              c.Name,
		ProjectId:         intToU32(int(c.ProjectID)),
		EnvironmentId:     intToU32(int(c.EnvironmentID)),
		BackendType:       c.BackendType,
		CreationTemplate:  c.CreationTemplate,
		DefaultTtlSeconds: intToI32(c.DefaultTTLSeconds),
		MaxTtlSeconds:     intToI32(c.MaxTTLSeconds),
		Classification:    c.Classification,
		CreatedBy:         c.CreatedBy,
		CreatedAt:         timestamppb.New(c.CreatedAt),
	}
}

func dynamicLeaseToProto(l *models.DynamicSecretLease) *pb.DynamicSecretLease {
	return &pb.DynamicSecretLease{
		LeaseId:      l.LeaseID,
		ConfigId:     intToU32(int(l.ConfigID)),
		RoleName:     l.RoleName,
		Status:       l.Status,
		RevokeReason: l.RevokeReason,
		RevokeError:  l.RevokeError,
		IssuedAt:     timestamppb.New(l.IssuedAt),
		ExpiresAt:    timestamppb.New(l.ExpiresAt),
		RevokedAt:    timePtrToTs(l.RevokedAt),
	}
}

func machineTokenToProto(c *models.MachineIdentityCredential) *pb.MachineToken {
	return &pb.MachineToken{
		Id:             intToU32(int(c.ID)),
		Name:           c.Name,
		Prefix:         c.TokenPrefix,
		LastUsedAt:     timePtrToTs(c.LastUsedAt),
		ExpiresAt:      timePtrToTs(c.ExpiresAt),
		Revoked:        c.Revoked,
		Classification: c.Classification,
		CreatedAt:      timestamppb.New(c.CreatedAt),
	}
}
