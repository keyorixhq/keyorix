package errclass

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// TestClassTablesAgree: the two rendering tables are the two renderings of the SAME
// closed set. Every class renders on both transports, a 4xx/5xx REST class is never a
// non-error gRPC code, Internal is the only 500, the two 503 classes are the only
// Unavailable, and the two 409 classes are told apart over gRPC on purpose.
func TestClassTablesAgree(t *testing.T) {
	seenHTTP := map[int][]Class{}
	for _, c := range All() {
		st, code := HTTPStatus(c), GRPCCode(c)
		require.NotEqual(t, codes.OK, code, "%s renders as a gRPC success", c)
		require.GreaterOrEqual(t, st, 400, "%s renders as a REST success", c)
		seenHTTP[st] = append(seenHTTP[st], c)
		assert.Equal(t, st == 500, code == codes.Internal, "%s: 500 <=> Internal", c)
		assert.Equal(t, st == 503, code == codes.Unavailable, "%s: 503 <=> Unavailable", c)
		assert.Equal(t, st == 403, code == codes.PermissionDenied, "%s: 403 <=> PermissionDenied", c)
		assert.Equal(t, st == 404, code == codes.NotFound, "%s: 404 <=> NotFound", c)
		assert.Equal(t, st == 400, code == codes.InvalidArgument, "%s: 400 <=> InvalidArgument", c)
		assert.NotEqual(t, "class(?)", c.String())
	}
	assert.ElementsMatch(t, []Class{Conflict, Precondition}, seenHTTP[409])
	assert.ElementsMatch(t, []Class{Unavailable, AuditUnavailable}, seenHTTP[503])
	assert.Equal(t, []Class{Internal}, seenHTTP[500])
	assert.Equal(t, 500, HTTPStatus(Class(99)), "an unknown class is an internal error, never a success")
	assert.Equal(t, codes.Internal, GRPCCode(Class(99)))
}

// TestOf_EverySentinelClassifiesWrapped: each table row classifies as its class when
// the sentinel is wrapped the way core and storage wrap it (a translated prefix and
// %w), and the table has no duplicate sentinel.
func TestOf_EverySentinelClassifiesWrapped(t *testing.T) {
	seen := map[error]string{}
	for _, s := range Sentinels() {
		if prev, dup := seen[s.Err]; dup {
			t.Errorf("%s and %s are the same sentinel", prev, s.Name)
		}
		seen[s.Err] = s.Name
		wrapped := fmt.Errorf("Operación fallida: %w", s.Err)
		assert.Equal(t, s.Class, Of(wrapped), s.Name)
		assert.Equal(t, s.Class, Of(fmt.Errorf("outer: %w", wrapped)), "%s two levels deep", s.Name)
	}
	require.Greater(t, len(seen), 60, "the table lost rows")
}

// TestOf_TextIsNotAClass: an error that merely SAYS not found / permission denied /
// already exists / validation (an OS error, a driver message, an untyped literal) is
// Internal. This is the half of the contract the old text switches got wrong.
func TestOf_TextIsNotAClass(t *testing.T) {
	for _, txt := range []string{
		"record not found",
		"user not found",
		"open /etc/x: permission denied",
		"insufficient permissions",
		"already exists",
		"UNIQUE constraint failed: roles.name",
		"Validation error: name is required",
		"storage temporarily unavailable, please retry",
		"audit log unavailable",
		"role not assigned",
	} {
		assert.Equal(t, Internal, Of(errors.New(txt)), txt)
	}
	assert.Equal(t, Internal, Of(nil))
}

// TestOf_Priority: a storage read fault whose wrapper says "not found" is a retry
// answer, not a not-found; an audit outage beats everything; a permission refusal
// that also names a missing target is a refusal (no existence oracle); a refusal that
// also carries an input sentinel is a refusal.
func TestOf_Priority(t *testing.T) {
	fault := core.ReadFault(errors.New("driver: connection refused"))
	require.NotNil(t, fault)
	assert.Equal(t, Unavailable, Of(fmt.Errorf("secret not found: %w", fault)))
	assert.Equal(t, Unavailable, Of(fmt.Errorf("%w: %w", storage.ErrSecretNotFound, fault)))
	assert.Equal(t, AuditUnavailable, Of(fmt.Errorf("%w: %w", fault, core.ErrMutationAuditUnavailable)))
	assert.Equal(t, PermissionDenied, Of(fmt.Errorf("%w: %w", storage.ErrSecretNotFound, core.ErrPermissionDenied)))
	assert.Equal(t, PermissionDenied, Of(fmt.Errorf("%w: %w", core.ErrValidation, core.ErrPermissionDenied)))
	assert.Equal(t, NotFound, Of(fmt.Errorf("%w: %w", core.ErrValidation, storage.ErrProjectNotFound)), "not found beats invalid input")
	// The specific permission sentinels match ErrPermissionDenied (INV-CORE-authz-refusal-matches-err-permission-denied).
	assert.Equal(t, PermissionDenied, Of(fmt.Errorf("x: %w", core.ErrBuiltinRole)))
	assert.Equal(t, PermissionDenied, Of(fmt.Errorf("x: %w", core.ErrMachinePrivilegeCeilingDenied)))
	assert.Equal(t, PermissionDenied, Of(fmt.Errorf("x: %w", core.ErrActorLacksPermission)))
}

// TestOfMutation: a permission refusal reached through a recorded transient lookup
// fault is Unavailable; without a recorded fault it stays PermissionDenied; an error
// that is itself an authorize outage is Unavailable; an unrecognised error stays
// Internal; a verdict is never upgraded by a fault that was recorded elsewhere.
func TestOfMutation(t *testing.T) {
	ctx := context.Background()
	denied := fmt.Errorf("access denied: %w", core.ErrPermissionDenied)
	assert.Equal(t, PermissionDenied, OfMutation(ctx, denied, nil))
	_, rec := core.WithAuthorizeFaultRecorder(ctx)
	assert.Equal(t, PermissionDenied, OfMutation(ctx, denied, rec), "an empty recorder changes nothing")
	assert.Nil(t, LookupFault(rec))
	assert.Nil(t, LookupFault(nil))

	outage := fmt.Errorf("resolve permission: dial tcp: %w", syscall.ECONNREFUSED)
	assert.Equal(t, Unavailable, OfMutation(ctx, outage, nil))
	assert.Equal(t, Internal, OfMutation(ctx, errors.New("boom"), rec))
	assert.Equal(t, NotFound, OfMutation(ctx, fmt.Errorf("x: %w", storage.ErrSecretNotFound), rec))

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	assert.Equal(t, Unavailable, OfMutation(canceled, errors.New("boom"), nil), "a canceled request is not a server fault")
	assert.Equal(t, PermissionDenied, OfMutation(canceled, denied, nil), "a verdict stays a verdict")
}
