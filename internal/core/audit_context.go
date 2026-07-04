// audit_context.go — propagation of impersonation attribution through context.
//
// When an admin acts inside an impersonation session, every audit event written
// during that session must record who really acted. The auth middleware tags the
// request context with the initiating admin's ID; writeAuditEventFull reads it
// and stamps ImpersonatedBy/ActingAs/Impersonation on the row. Because audit
// writes happen in detached goroutines (context.Background()), handlers use
// DetachedAuditContext to carry the tag past request cancellation.
package core

import (
	"context"
	"log"
)

// Actor types stamped on every audit event (ADR-023). They distinguish a human
// user from a non-human machine identity so the audit view can segment and
// filter the two.
const (
	ActorTypeUser    = "user"
	ActorTypeMachine = "machine_identity"
	ActorTypeSystem  = "system"
)

type impersonationKey struct{}

type actorTypeKey struct{}

// WithActorType tags ctx with the principal kind for the current request
// (ActorTypeUser/ActorTypeMachine/ActorTypeSystem). The auth middleware sets it
// per request; writeAuditEvent* reads it and stamps ActorType on the row. An
// empty actorType is treated as "no tag" (the writer defaults to user).
func WithActorType(ctx context.Context, actorType string) context.Context {
	if actorType == "" {
		return ctx
	}
	return context.WithValue(ctx, actorTypeKey{}, actorType)
}

// actorTypeFromContext returns the tagged actor type, defaulting to
// ActorTypeUser when the context carries no tag.
func actorTypeFromContext(ctx context.Context) string {
	if t, ok := ctx.Value(actorTypeKey{}).(string); ok && t != "" {
		return t
	}
	return ActorTypeUser
}

// WithImpersonation tags ctx with the admin user ID that initiated the current
// impersonation session. A zero adminID is treated as "no impersonation".
func WithImpersonation(ctx context.Context, adminID uint) context.Context {
	if adminID == 0 {
		return ctx
	}
	return context.WithValue(ctx, impersonationKey{}, adminID)
}

// impersonatorFromContext returns the initiating admin ID and whether the
// current context is an impersonation context.
func impersonatorFromContext(ctx context.Context) (uint, bool) {
	adminID, ok := ctx.Value(impersonationKey{}).(uint)
	return adminID, ok && adminID != 0
}

// DetachedAuditContext returns a background-rooted context that preserves any
// impersonation tag from parent. Audit writes run in goroutines that must
// outlive the request, but still need to record the impersonating admin.
func DetachedAuditContext(parent context.Context) context.Context {
	ctx := context.Background()
	if adminID, ok := impersonatorFromContext(parent); ok {
		ctx = WithImpersonation(ctx, adminID)
	}
	if t, ok := parent.Value(actorTypeKey{}).(string); ok && t != "" {
		ctx = WithActorType(ctx, t)
	}
	return ctx
}

// goSafe runs fn in a detached goroutine with panic recovery. Several core
// methods spawn "fire and forget" goroutines for post-response side effects
// (audit logging of secret reads/writes, password-reset link provisioning)
// so the caller isn't blocked on that I/O — but those goroutines run on the
// hottest request paths (every secret read/write, and — for
// RequestPasswordReset — even an unauthenticated one) and are NOT covered by
// the HTTP server's per-request recovery middleware, which only guards the
// goroutine actually serving the request. A panic in a bare `go
// c.LogSecret...(...)` here (a future nil-deref, malformed diff content,
// etc.) would crash the entire process for every connected tenant (backlog
// #481, an unrecovered-coverage gap in the #243 fix). goSafe closes that gap:
// any panic in fn is recovered and logged instead of taking the server down.
// This mirrors server/http/handlers' goSafe, duplicated here because that
// package cannot be imported from internal/core.
func goSafe(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("recovered from panic in background goroutine: %v", r)
			}
		}()
		fn()
	}()
}
