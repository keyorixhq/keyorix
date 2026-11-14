package dynamic

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// ErrEngineClientPanic is what a contained client-library panic looks like to the
// caller: errors.Is(err, ErrEngineClientPanic). The third-party DB/cloud clients behind
// the dynamic-secret engines and rotation executors parse bytes from an
// operator-configured (so possibly hostile) target; a malformed reply can panic inside
// the client. Without containment that panic unwinds through core code holding a lease
// row or an uncommitted audit step.
var ErrEngineClientPanic = errors.New("backend client library failed unexpectedly")

// EngineClientPanicError carries WHERE the panic happened and nothing it said: the
// panic value can embed target data or the admin DSN, so it goes to the (redacted)
// server log only, never into this error, which reaches audit rows and API replies.
type EngineClientPanicError struct {
	Component string // "dynamic-secret engine" or "rotation executor"
	Name      string // backend type or executor name
	Op        string // Issue, Revoke, Renew, Rotate, GenerateUpstream, ...
}

func (e *EngineClientPanicError) Error() string {
	return fmt.Sprintf("%s %q: %s: client library failed unexpectedly (panic contained; see server log)", e.Component, e.Name, e.Op)
}

func (e *EngineClientPanicError) Is(target error) bool { return target == ErrEngineClientPanic }

// RecoverClientPanic is the shared containment primitive. Call it directly as a
// deferred call (recover only works there) in a function with a named error result:
//
//	func (w *wrapper) Op(...) (err error) {
//	    defer dynamic.RecoverClientPanic("rotation executor", w.Name(), "Rotate", &err)()
//
// It is the same shape as besteffort.RunRecover: one security-prefixed, one-line,
// quoted log line (a panic text from the target cannot forge a second line), but it
// converts to an error instead of swallowing, because the caller needs the failure.
// The panic text and the stack go through ports.RedactSensitive, so a DSN in either
// is masked.
func RecoverClientPanic(component, name, op string, errp *error) func() {
	return func() {
		r := recover()
		if r == nil {
			return
		}
		msg := ports.RedactSensitive(fmt.Sprint(r))
		stack := ports.RedactSensitive(string(debug.Stack()))
		log.Printf("SECURITY: %s %q panicked in %s (contained, reported as a typed error): %s\n%s",
			component, name, op, strconv.Quote(msg), stack)
		*errp = &EngineClientPanicError{Component: component, Name: name, Op: op}
	}
}

// containedEngine decorates a CredentialEngine so a client-library panic in Issue,
// Revoke or Renew comes back as *EngineClientPanicError. Apply it with Contain; New
// already does.
type containedEngine struct {
	inner CredentialEngine
}

// Contain wraps e (idempotent). A nil engine is returned as is.
func Contain(e CredentialEngine) CredentialEngine {
	if e == nil {
		return nil
	}
	if _, ok := e.(*containedEngine); ok {
		return e
	}
	return &containedEngine{inner: e}
}

const engineComponent = "dynamic-secret engine"

func (c *containedEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (cred Credential, roleName string, err error) {
	defer RecoverClientPanic(engineComponent, c.inner.BackendType(), "Issue", &err)()
	cred, roleName, err = c.inner.Issue(ctx, adminDSN, creationTemplate, ttl)
	return cred, roleName, err
}

func (c *containedEngine) Revoke(ctx context.Context, adminDSN, roleName string) (err error) {
	defer RecoverClientPanic(engineComponent, c.inner.BackendType(), "Revoke", &err)()
	return c.inner.Revoke(ctx, adminDSN, roleName)
}

func (c *containedEngine) Renew(ctx context.Context, adminDSN, roleName string, expiresAt time.Time) (err error) {
	defer RecoverClientPanic(engineComponent, c.inner.BackendType(), "Renew", &err)()
	return c.inner.Renew(ctx, adminDSN, roleName, expiresAt)
}

func (c *containedEngine) SupportsNativeExpiry() bool { return c.inner.SupportsNativeExpiry() }
func (c *containedEngine) BackendType() string        { return c.inner.BackendType() }
func (c *containedEngine) IsEphemeralBackend() bool   { return c.inner.IsEphemeralBackend() }

// RevokeInvalidatesCredential parses the DSN in some engines; a panic there answers
// false (the conservative audit wording: do not claim the provider credential died).
func (c *containedEngine) RevokeInvalidatesCredential(adminDSN string) (ok bool) {
	var err error
	defer func() {
		if err != nil {
			ok = false
		}
	}()
	defer RecoverClientPanic(engineComponent, c.inner.BackendType(), "RevokeInvalidatesCredential", &err)()
	return c.inner.RevokeInvalidatesCredential(adminDSN)
}
