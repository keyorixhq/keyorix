package services

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- mapDynamicError ---

func TestMapDynamicError_NotFound(t *testing.T) {
	err := mapDynamicError(errors.New("config not found in database"))
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

func TestMapDynamicError_InvalidArgument_CannotExceed(t *testing.T) {
	err := mapDynamicError(errors.New("cannot exceed the allowed limit"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapDynamicError_InvalidArgument_Required(t *testing.T) {
	err := mapDynamicError(errors.New("name is required"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapDynamicError_InvalidArgument_ClassificationMust(t *testing.T) {
	err := mapDynamicError(errors.New("classification must be one of: restricted, confidential"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapDynamicError_PermissionDenied(t *testing.T) {
	err := mapDynamicError(errors.New("permission denied for this config"))
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestMapDynamicError_Denied(t *testing.T) {
	err := mapDynamicError(errors.New("access denied by policy"))
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestMapDynamicError_Default_Unavailable(t *testing.T) {
	err := mapDynamicError(errors.New("connection reset by peer"))
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("expected Unavailable, got %v", st.Code())
	}
}

// --- mapMachineError ---

func TestMapMachineError_NotFound(t *testing.T) {
	err := mapMachineError(errors.New("machine identity not found"))
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

func TestMapMachineError_CannotTransition(t *testing.T) {
	err := mapMachineError(errors.New("cannot transition from active to active"))
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", st.Code())
	}
}

func TestMapMachineError_MustBeActive(t *testing.T) {
	err := mapMachineError(errors.New("must be active to issue a token"))
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", st.Code())
	}
}

func TestMapMachineError_InvalidArgument(t *testing.T) {
	err := mapMachineError(errors.New("invalid machine identity name"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapMachineError_ClassificationMust(t *testing.T) {
	err := mapMachineError(errors.New("classification must be one of: restricted"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapMachineError_Required(t *testing.T) {
	err := mapMachineError(errors.New("name is required"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapMachineError_PermissionDenied(t *testing.T) {
	err := mapMachineError(errors.New("permission denied"))
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestMapMachineError_Denied(t *testing.T) {
	err := mapMachineError(errors.New("access denied by RBAC"))
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestMapMachineError_Default_Internal(t *testing.T) {
	err := mapMachineError(errors.New("unexpected storage failure"))
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %v", st.Code())
	}
}

// TestMapMachineError_PrivilegeCeilingDenied guards against the MACH-001
// misclassification: requireMachinePrivilegeCeiling's message ("...requires
// administrative authority") contains none of the switch's fixed substrings
// ("permission", "denied", "required", etc — note "requires" != "required"),
// so before the errors.Is(core.ErrMachinePrivilegeCeilingDenied) check was added
// it fell through to the default codes.Internal bucket instead of
// codes.PermissionDenied, even though the request was correctly denied.
func TestMapMachineError_PrivilegeCeilingDenied(t *testing.T) {
	err := mapMachineError(fmt.Errorf("%w: issuing a token for a machine identity that holds administrative roles requires administrative authority", core.ErrMachinePrivilegeCeilingDenied))
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

// --- mapRoleError ---

func TestMapRoleError_NotFound(t *testing.T) {
	err := mapRoleError(errors.New("role not found"))
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

func TestMapRoleError_AlreadyExists(t *testing.T) {
	err := mapRoleError(errors.New("role already exists in the system"))
	st, _ := status.FromError(err)
	if st.Code() != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got %v", st.Code())
	}
}

func TestMapRoleError_Duplicate(t *testing.T) {
	err := mapRoleError(errors.New("duplicate role name"))
	st, _ := status.FromError(err)
	if st.Code() != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got %v", st.Code())
	}
}

func TestMapRoleError_Default(t *testing.T) {
	err := mapRoleError(errors.New("something unexpected went wrong"))
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %v", st.Code())
	}
}

// --- breakGlassError ---

func TestBreakGlassError_NotFound(t *testing.T) {
	err := breakGlassError(errors.New("activation not found"))
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

func TestBreakGlassError_Justification(t *testing.T) {
	err := breakGlassError(errors.New("justification is required"))
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestBreakGlassError_PermissionDenied(t *testing.T) {
	err := breakGlassError(errors.New("permission denied to activate break-glass"))
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestBreakGlassError_AlreadyRevoked(t *testing.T) {
	err := breakGlassError(errors.New("already revoked"))
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", st.Code())
	}
}

func TestBreakGlassError_Default(t *testing.T) {
	err := breakGlassError(errors.New("unexpected backend error"))
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %v", st.Code())
	}
}

// --- resolveActor ---

func TestResolveActor_NilUserIDSystemType(t *testing.T) {
	e := &models.AuditEvent{ActorType: "system"}
	got := resolveActor(e, nil)
	if got != "system" {
		t.Errorf("resolveActor with system actor = %q, want %q", got, "system")
	}
}

func TestResolveActor_NilUserIDUnknownType(t *testing.T) {
	e := &models.AuditEvent{ActorType: "job"}
	got := resolveActor(e, nil)
	if got != "unknown" {
		t.Errorf("resolveActor with non-system actor = %q, want %q", got, "unknown")
	}
}

func TestResolveActor_UserIDInMap(t *testing.T) {
	uid := uint(5)
	e := &models.AuditEvent{UserID: &uid}
	got := resolveActor(e, map[uint]string{5: "alice"})
	if got != "alice" {
		t.Errorf("resolveActor with known user = %q, want %q", got, "alice")
	}
}

func TestResolveActor_UserIDNotInMap(t *testing.T) {
	uid := uint(99)
	e := &models.AuditEvent{UserID: &uid}
	got := resolveActor(e, map[uint]string{})
	if got != "unknown" {
		t.Errorf("resolveActor with unknown user = %q, want %q", got, "unknown")
	}
}

// --- machineActionToState ---

func TestMachineActionToState_Activate(t *testing.T) {
	state, ok := machineActionToState("activate")
	if !ok || state == "" {
		t.Errorf("activate: ok=%v state=%q", ok, state)
	}
}

func TestMachineActionToState_Suspend(t *testing.T) {
	state, ok := machineActionToState("suspend")
	if !ok || state == "" {
		t.Errorf("suspend: ok=%v state=%q", ok, state)
	}
}

func TestMachineActionToState_Revoke(t *testing.T) {
	state, ok := machineActionToState("revoke")
	if !ok || state == "" {
		t.Errorf("revoke: ok=%v state=%q", ok, state)
	}
}

func TestMachineActionToState_Unknown(t *testing.T) {
	_, ok := machineActionToState("unknown-action")
	if ok {
		t.Error("expected ok=false for unknown action")
	}
}
