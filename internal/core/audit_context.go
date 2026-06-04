// audit_context.go — propagation of impersonation attribution through context.
//
// When an admin acts inside an impersonation session, every audit event written
// during that session must record who really acted. The auth middleware tags the
// request context with the initiating admin's ID; writeAuditEventFull reads it
// and stamps ImpersonatedBy/ActingAs/Impersonation on the row. Because audit
// writes happen in detached goroutines (context.Background()), handlers use
// DetachedAuditContext to carry the tag past request cancellation.
package core

import "context"

type impersonationKey struct{}

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
	if adminID, ok := impersonatorFromContext(parent); ok {
		return WithImpersonation(context.Background(), adminID)
	}
	return context.Background()
}
