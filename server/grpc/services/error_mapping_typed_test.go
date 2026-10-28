package services

// CORE-GRPC-TAILS-1 item 2: the per-service error mappers classify core/storage
// errors by sentinel (errors.Is / errors.As), not by matching err.Error(). One
// table per mapper. Each "text only" row is the other half of the contract: an
// error that merely SAYS "not found" / "permission denied" (an OS error, another
// layer's raw message) is a server fault, not a caller error.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
)

type typedMapCase struct {
	name string
	err  error
	code codes.Code
}

func runTypedMapCases(t *testing.T, mapper func(error) error, cases []typedMapCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapper(tc.err)
			assert.Equal(t, tc.code, status.Code(got), got.Error())
		})
	}
}

func TestMapProjectError_ClassifiesBySentinel(t *testing.T) {
	runTypedMapCases(t, mapProjectError, []typedMapCase{
		{"missing project", fmt.Errorf("get project: %w", storage.ErrProjectNotFound), codes.NotFound},
		{"duplicate name", fmt.Errorf("create: %w", storage.ErrDuplicateProjectName), codes.AlreadyExists},
		{"authz refusal", fmt.Errorf("delete: %w", core.ErrPermissionDenied), codes.PermissionDenied},
		// The one storage message not typed yet (lockProjectRowForCascade): exact text only.
		{"untyped cascade-lock not found", errors.New("project not found"), codes.NotFound},
		{"text only: wrapped not found", errors.New("project 7 not found in cache"), codes.Internal},
		{"text only: already exists", errors.New("project already exists"), codes.Internal},
		{"text only: permission", errors.New("open /etc/x: permission denied"), codes.Internal},
	})
}

func TestMapRoleError_ClassifiesBySentinel(t *testing.T) {
	runTypedMapCases(t, mapRoleError, []typedMapCase{
		{"missing role", fmt.Errorf("get role: %w", storage.ErrRoleNotFound), codes.NotFound},
		{"reserved name", fmt.Errorf("create role: %w", core.ErrRoleNameReserved), codes.AlreadyExists},
		{"built-in role", fmt.Errorf("permission denied: cannot update %w: x", core.ErrBuiltinRole), codes.FailedPrecondition},
		{"validation", fmt.Errorf("create role: %w", core.ErrRoleValidation), codes.InvalidArgument},
		// Not yet typed: the raw unique-index error from the roles table.
		{"untyped roles unique index", errors.New("UNIQUE constraint failed: roles.name_folded"), codes.AlreadyExists},
		{"text only: not found", errors.New("record not found"), codes.Internal},
		{"text only: reserved", errors.New("name is reserved by the OS"), codes.Internal},
		{"text only: built-in", errors.New("built-in module missing"), codes.Internal},
		{"text only: duplicate of another table", errors.New("duplicate key value violates unique constraint \"idx_users_email\""), codes.Internal},
	})
}

func TestMapUserError_ClassifiesBySentinel(t *testing.T) {
	runTypedMapCases(t, mapUserError, []typedMapCase{
		{"missing user", fmt.Errorf("get user: %w", storage.ErrUserNotFound), codes.NotFound},
		{"user exists", fmt.Errorf("create user: %w", core.ErrUserAlreadyExists), codes.AlreadyExists},
		{"email in use", fmt.Errorf("update user: %w", core.ErrEmailInUse), codes.AlreadyExists},
		{"duplicate email (storage)", fmt.Errorf("create user: %w", storage.ErrDuplicateEmail), codes.AlreadyExists},
		{"invalid input", fmt.Errorf("update user: %w", core.ErrInvalidInput), codes.InvalidArgument},
		{"empty identity name", fmt.Errorf("validation: %w", identity.ErrEmpty), codes.InvalidArgument},
		// Not yet typed: the core/users.go validation wording and the roles.assign ceiling.
		{"untyped validation", errors.New("validation failed: email is required"), codes.InvalidArgument},
		{"untyped role ceiling", errors.New("cannot grant this role: you do not hold permission \"roles.assign\" yourself"), codes.PermissionDenied},
		{"text only: not found", errors.New("record not found"), codes.Internal},
		{"text only: already exists", errors.New("file already exists"), codes.Internal},
		{"text only: duplicate", errors.New("duplicate key value violates unique constraint \"idx_x\""), codes.Internal},
	})
}

func TestMapShareError_ClassifiesBySentinel(t *testing.T) {
	runTypedMapCases(t, mapShareError, []typedMapCase{
		{"missing share", fmt.Errorf("revoke: %w", storage.ErrShareNotFound), codes.NotFound},
		{"missing secret", fmt.Errorf("share: %w", storage.ErrSecretNotFound), codes.NotFound},
		{"missing recipient", fmt.Errorf("share: %w", storage.ErrUserNotFound), codes.NotFound},
		{"authz refusal", fmt.Errorf("share: %w", core.ErrPermissionDenied), codes.PermissionDenied},
		{"specific share refusal", core.ErrShareActionNotElevated, codes.PermissionDenied},
		// Not yet typed: the expiry refusal (three fmt.Errorf sites in core/sharing*.go).
		{"untyped expiry", errors.New("validation failed: share expiry must be in the future"), codes.InvalidArgument},
		{"text only: not found", errors.New("record not found"), codes.Internal},
		{"text only: not authorized", errors.New("not authorized to do that"), codes.Internal},
		{"text only: permission denied", errors.New("open x: permission denied"), codes.Internal},
	})
}

func TestMapSecretACLError_ClassifiesBySentinel(t *testing.T) {
	runTypedMapCases(t, mapSecretACLError, []typedMapCase{
		{"missing ACL", fmt.Errorf("revoke: %w", storage.ErrSecretACLNotFound), codes.NotFound},
		{"missing secret", fmt.Errorf("grant: %w", storage.ErrSecretNotFound), codes.NotFound},
		{"authz refusal", fmt.Errorf("grant: %w", core.ErrPermissionDenied), codes.PermissionDenied},
		// Not yet typed: GrantSecretACL's own validation.
		{"untyped invalid", errors.New("invalid permission set"), codes.InvalidArgument},
		{"untyped required", errors.New("user_id is required"), codes.InvalidArgument},
		{"text only: not found", errors.New("ACL entry not found"), codes.Internal},
		{"text only: not authorized", errors.New("user not authorized to manage ACLs"), codes.Internal},
	})
}

func TestMapSecretError_ClassifiesBySentinel(t *testing.T) {
	runTypedMapCases(t, mapSecretError, []typedMapCase{
		{"missing secret", fmt.Errorf("get: %w", storage.ErrSecretNotFound), codes.NotFound},
		{"authz refusal", fmt.Errorf("update: %w", core.ErrPermissionDenied), codes.PermissionDenied},
		{"secret exists", fmt.Errorf("create: %w", core.ErrSecretAlreadyExists), codes.AlreadyExists},
		// Not yet typed: rotation validation (rotation_executor.go).
		{"untyped rotation", errors.New("rotation length out of range"), codes.InvalidArgument},
		{"text only: not found", errors.New("record not found"), codes.Internal},
		{"text only: access denied", errors.New("access denied to resource"), codes.Internal},
		{"text only: already exists", errors.New("secret already exists in this project"), codes.Internal},
	})
}
