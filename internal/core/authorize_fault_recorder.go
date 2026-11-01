package core

import (
	"context"
	"sync"
)

type authorizeFaultRecorderKey struct{}

// AuthorizeFaultRecorder remembers the first TRANSIENT storage failure of an
// authorization lookup that a core secret operation folded into its fail-closed
// "insufficient permissions" refusal (checkSecretPermission's RBAC fallback). The
// refusal itself is unchanged and stays the core's answer; a transport that has
// installed a recorder (WithAuthorizeFaultRecorder) can tell the outage from a
// verdict and answer retry (gRPC Unavailable) instead of PermissionDenied. Without a
// recorder in the context nothing is recorded and no caller changes behaviour.
type AuthorizeFaultRecorder struct {
	mu  sync.Mutex
	err error
}

// WithAuthorizeFaultRecorder returns ctx carrying a fresh recorder.
func WithAuthorizeFaultRecorder(ctx context.Context) (context.Context, *AuthorizeFaultRecorder) {
	rec := &AuthorizeFaultRecorder{}
	return context.WithValue(ctx, authorizeFaultRecorderKey{}, rec), rec
}

// Err is the recorded transient lookup failure, or nil.
func (r *AuthorizeFaultRecorder) Err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// noteAuthorizeLookupFault records err when ctx carries a recorder and err is a
// transient storage failure (IsAuthorizeTransient); anything else stays a plain,
// fail-closed denial.
func noteAuthorizeLookupFault(ctx context.Context, err error) {
	rec, _ := ctx.Value(authorizeFaultRecorderKey{}).(*AuthorizeFaultRecorder)
	if rec == nil || !IsAuthorizeTransient(ctx, err) {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.err == nil {
		rec.err = err
	}
}
