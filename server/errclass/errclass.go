// Package errclass is the ONE place that turns a core or storage error into the small,
// closed set of answer classes the transports know how to render. Core types every
// refusal with a sentinel (internal/core/errors*.go, internal/core/storage/errors*.go);
// this package maps those sentinels to a Class, and the REST adapter
// (server/http/handlers/core_error_answer.go) and the gRPC adapter
// (server/grpc/services/core_error_status.go) render a Class as a status. Neither
// adapter, and no handler, classifies an error by its message text: the text is
// translated (de/es/fr/ru) and carries prefixes core adds to any storage error
// (INV-HTTP-classify-errors-by-sentinel-not-text).
//
// Why one table (FIX-ERRMAP-STRUCT-1, #4132 #3979 #4020 #3873 #3911): before it, about
// fourteen gRPC family mappers and sixty REST text switches each re-derived the class, so
// the same refusal was a 500 on one route, a 403 on its sibling and Internal over gRPC,
// and a new sentinel had to be wired into every one of them. With one table, REST and
// gRPC agree by construction (TestClassTablesAgree) and a sentinel is classified once.
//
// Classes are deliberately few. A refusal the table does not know is Internal: the
// operation was refused either way, and an unknown error must never be reported as a
// verdict on the target (a "not found") or on the caller (a "forbidden").
package errclass

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// Class is the answer class of a core or storage error. The set is closed: every
// transport renders every class (TestClassTablesAgree), so adding one here means
// adding its rendering to both adapters.
type Class int

const (
	// Internal: unexpected. The cause is logged; the client gets a fixed text.
	// REST 500, gRPC Internal.
	Internal Class = iota
	// InvalidInput: the request is malformed or violates a field rule. REST 400,
	// gRPC InvalidArgument.
	InvalidInput
	// NotFound: the named target positively does not exist (or is outside the
	// caller's project, reported the same way so there is no existence oracle).
	// REST 404, gRPC NotFound. Never a storage read FAULT: that is Unavailable.
	NotFound
	// Conflict: the thing already exists or the grant is already held. REST 409,
	// gRPC AlreadyExists.
	Conflict
	// Precondition: the target's state refuses the operation (not deleted, not
	// active, disabled, built-in, last admin). REST 409, gRPC FailedPrecondition.
	Precondition
	// PermissionDenied: an authorization refusal (core.ErrPermissionDenied and the
	// specific refusal sentinels that match it). REST 403, gRPC PermissionDenied.
	PermissionDenied
	// Unavailable: a storage READ the operation depends on failed, or the permission
	// lookup behind a refusal hit a storage outage: nothing was applied, the caller
	// was not judged, a retry is right. REST 503 + Retry-After, gRPC Unavailable.
	Unavailable
	// AuditUnavailable: the mutation's audit row could not be written, so its
	// transaction rolled back. REST 503 + Retry-After (code audit_unavailable),
	// gRPC Unavailable. A core.PartialMutationError also classifies here; the REST
	// adapter renders it through sendPartialMutation (body says which half applied).
	AuditUnavailable
)

var classNames = [...]string{
	Internal:         "internal",
	InvalidInput:     "invalid_input",
	NotFound:         "not_found",
	Conflict:         "conflict",
	Precondition:     "precondition",
	PermissionDenied: "permission_denied",
	Unavailable:      "unavailable",
	AuditUnavailable: "audit_unavailable",
}

// String is the class's stable name (logs, tests).
func (c Class) String() string {
	if int(c) < len(classNames) {
		return classNames[c]
	}
	return "class(?)"
}

// All lists every class once, in rendering-table order.
func All() []Class {
	return []Class{Internal, InvalidInput, NotFound, Conflict, Precondition, PermissionDenied, Unavailable, AuditUnavailable}
}

// HTTPStatus is the REST status of a class. Both 409 classes exist because gRPC
// clients already see AlreadyExists and FailedPrecondition apart.
func HTTPStatus(c Class) int {
	switch c {
	case InvalidInput:
		return 400
	case NotFound:
		return 404
	case Conflict, Precondition:
		return 409
	case PermissionDenied:
		return 403
	case Unavailable, AuditUnavailable:
		return 503
	default:
		return 500
	}
}

// GRPCCode is the gRPC status code of a class.
func GRPCCode(c Class) codes.Code {
	switch c {
	case InvalidInput:
		return codes.InvalidArgument
	case NotFound:
		return codes.NotFound
	case Conflict:
		return codes.AlreadyExists
	case Precondition:
		return codes.FailedPrecondition
	case PermissionDenied:
		return codes.PermissionDenied
	case Unavailable, AuditUnavailable:
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

// Sentinel is one row of the classification table: a core or storage sentinel and
// the class every error that matches it (errors.Is) belongs to.
type Sentinel struct {
	Name  string
	Err   error
	Class Class
}

// sentinelTable is consulted in order after the two outage classes and the
// permission class (see Of). Within a class the order does not matter; between
// classes it does: a not-found that also carries an input sentinel is a not-found.
var sentinelTable = []Sentinel{
	// NotFound: the per-entity storage sentinels (internal/core/storage) and core's
	// typed not-found refusals. storage.ErrRoleNotAssigned is a not-found (DELETE
	// /user-roles 404, gRPC RemoveRole NotFound, #4020), not a conflict.
	{"storage.ErrUserNotFound", storage.ErrUserNotFound, NotFound},
	{"storage.ErrGroupNotFound", storage.ErrGroupNotFound, NotFound},
	{"storage.ErrRoleNotFound", storage.ErrRoleNotFound, NotFound},
	{"storage.ErrProjectNotFound", storage.ErrProjectNotFound, NotFound},
	{"storage.ErrEnvironmentNotFound", storage.ErrEnvironmentNotFound, NotFound},
	{"storage.ErrSecretNotFound", storage.ErrSecretNotFound, NotFound},
	{"storage.ErrSecretVersionNotFound", storage.ErrSecretVersionNotFound, NotFound},
	{"storage.ErrSessionNotFound", storage.ErrSessionNotFound, NotFound},
	{"storage.ErrShareNotFound", storage.ErrShareNotFound, NotFound},
	{"storage.ErrSecretTemplateNotFound", storage.ErrSecretTemplateNotFound, NotFound},
	{"storage.ErrRotationPolicyNotFound", storage.ErrRotationPolicyNotFound, NotFound},
	{"storage.ErrNotificationChannelNotFound", storage.ErrNotificationChannelNotFound, NotFound},
	{"storage.ErrNotificationNotFound", storage.ErrNotificationNotFound, NotFound},
	{"storage.ErrAlertEscalationNotFound", storage.ErrAlertEscalationNotFound, NotFound},
	{"storage.ErrMachineCredentialNotFound", storage.ErrMachineCredentialNotFound, NotFound},
	{"storage.ErrOIDCBindingNotFound", storage.ErrOIDCBindingNotFound, NotFound},
	{"storage.ErrConnectorBindingNotFound", storage.ErrConnectorBindingNotFound, NotFound},
	{"storage.ErrSSOLoginStateNotFound", storage.ErrSSOLoginStateNotFound, NotFound},
	{"storage.ErrPermissionNotFound", storage.ErrPermissionNotFound, NotFound},
	{"storage.ErrRolePermissionNotAssigned", storage.ErrRolePermissionNotAssigned, NotFound},
	{"storage.ErrRoleNotAssigned", storage.ErrRoleNotAssigned, NotFound},
	{"storage.ErrSecretDependencyNotFound", storage.ErrSecretDependencyNotFound, NotFound},
	{"storage.ErrVersionCommentNotFound", storage.ErrVersionCommentNotFound, NotFound},
	{"storage.ErrSoDPolicyNotFound", storage.ErrSoDPolicyNotFound, NotFound},
	{"storage.ErrRiskExceptionNotFound", storage.ErrRiskExceptionNotFound, NotFound},
	{"storage.ErrBreakGlassNotFound", storage.ErrBreakGlassNotFound, NotFound},
	{"storage.ErrSecretACLNotFound", storage.ErrSecretACLNotFound, NotFound},
	{"storage.ErrMFAResetRequestNotFound", storage.ErrMFAResetRequestNotFound, NotFound},
	{"core.ErrMachineIdentityNotFound", core.ErrMachineIdentityNotFound, NotFound},
	{"core.ErrDynamicSecretNotFound", core.ErrDynamicSecretNotFound, NotFound},
	{"core.ErrAccessReviewNotFound", core.ErrAccessReviewNotFound, NotFound},
	{"core.ErrMembershipTargetNotFound", core.ErrMembershipTargetNotFound, NotFound},
	// The environment a request names does not exist or is in another project: the
	// folder and resume routes answer 404 (#4132 OPENAPI-STATEFUL-5). CreateSecret
	// keeps its own 422 for it and does not use this table.
	{"core.ErrSecretTargetInvalid", core.ErrSecretTargetInvalid, NotFound},
	{"core.ErrSoDNotFound", core.ErrSoDNotFound, NotFound},
	{"core.ErrRiskExceptionNotFoundPublic", core.ErrRiskExceptionNotFoundPublic, NotFound},
	{"core.ErrMFAResetTargetNotFound", core.ErrMFAResetTargetNotFound, NotFound},
	{"core.ErrMFAResetRequestNotFound", core.ErrMFAResetRequestNotFound, NotFound},

	// Precondition: the target's state refuses.
	{"core.ErrSecretNotDeleted", core.ErrSecretNotDeleted, Precondition},
	{"core.ErrMachineTransitionInvalid", core.ErrMachineTransitionInvalid, Precondition},
	{"core.ErrMachineIdentityNotActive", core.ErrMachineIdentityNotActive, Precondition},
	{"core.ErrDynamicSecretPrecondition", core.ErrDynamicSecretPrecondition, Precondition},
	{"core.ErrLastAdminDeactivation", core.ErrLastAdminDeactivation, Precondition},
	{"core.ErrLastAdminGroupGuard", core.ErrLastAdminGroupGuard, Precondition},
	{"storage.ErrWouldStrandLastAdmin", storage.ErrWouldStrandLastAdmin, Precondition},
	{"storage.ErrBreakGlassNotActive", storage.ErrBreakGlassNotActive, Precondition},
	{"storage.ErrDynamicSecretConfigDisabled", storage.ErrDynamicSecretConfigDisabled, Precondition},

	// Conflict: already exists / already held.
	{"storage.ErrRoleAlreadyAssigned", storage.ErrRoleAlreadyAssigned, Conflict},
	{"storage.ErrOIDCBindingAlreadyBound", storage.ErrOIDCBindingAlreadyBound, Conflict},
	{"storage.ErrDuplicateEmail", storage.ErrDuplicateEmail, Conflict},
	{"storage.ErrDuplicateUsername", storage.ErrDuplicateUsername, Conflict},
	{"storage.ErrDuplicateProjectName", storage.ErrDuplicateProjectName, Conflict},
	{"storage.ErrDuplicateGroupName", storage.ErrDuplicateGroupName, Conflict},
	{"storage.ErrDuplicateNotificationChannelName", storage.ErrDuplicateNotificationChannelName, Conflict},
	{"storage.ErrDuplicateSecretVersion", storage.ErrDuplicateSecretVersion, Conflict},
	{"storage.ErrDuplicateDynamicSecretConfig", storage.ErrDuplicateDynamicSecretConfig, Conflict},
	{"storage.ErrDuplicateRolePermission", storage.ErrDuplicateRolePermission, Conflict},
	{"storage.ErrDuplicateReminderNotification", storage.ErrDuplicateReminderNotification, Conflict},
	{"storage.ErrDuplicateSecretDependency", storage.ErrDuplicateSecretDependency, Conflict},
	{"storage.ErrDuplicateActiveMembership", storage.ErrDuplicateActiveMembership, Conflict},
	{"storage.ErrLegalHoldAlreadyActive", storage.ErrLegalHoldAlreadyActive, Conflict},
	{"storage.ErrBreakGlassAlreadyActive", storage.ErrBreakGlassAlreadyActive, Conflict},
	{"storage.ErrBreakGlassAlreadyReviewed", storage.ErrBreakGlassAlreadyReviewed, Conflict},
	{"core.ErrUserAlreadyExists", core.ErrUserAlreadyExists, Conflict},
	{"core.ErrEmailInUse", core.ErrEmailInUse, Conflict},
	{"core.ErrSCIMUserExists", core.ErrSCIMUserExists, Conflict},
	{"core.ErrRoleNameReserved", core.ErrRoleNameReserved, Conflict},
	{"core.ErrRiskExceptionAlreadyRevoked", core.ErrRiskExceptionAlreadyRevoked, Conflict},
	{"core.ErrRiskExceptionAlreadyApproved", core.ErrRiskExceptionAlreadyApproved, Conflict},

	// InvalidInput: core's typed validation refusals.
	{"core.ErrValidation", core.ErrValidation, InvalidInput},
	{"core.ErrSecretInvalidInput", core.ErrSecretInvalidInput, InvalidInput},
	{"core.ErrRoleValidation", core.ErrRoleValidation, InvalidInput},
	{"core.ErrInvalidInput", core.ErrInvalidInput, InvalidInput},
	{"core.ErrInvalidAuditRetentionDays", core.ErrInvalidAuditRetentionDays, InvalidInput},
	{"core.ErrRoleScopeInvalid", core.ErrRoleScopeInvalid, InvalidInput},
	{"core.ErrSoDValidation", core.ErrSoDValidation, InvalidInput},
	{"core.ErrMFAResetInput", core.ErrMFAResetInput, InvalidInput},
	{"core.ErrCertificateUnparseable", core.ErrCertificateUnparseable, InvalidInput},
	{"core.ErrBreakGlassInvalidRequest", core.ErrBreakGlassInvalidRequest, InvalidInput},
	{"core.ErrBreakGlassInvalidNote", core.ErrBreakGlassInvalidNote, InvalidInput},
	{"storage.ErrInvalidGroupRequest", storage.ErrInvalidGroupRequest, InvalidInput},
	{"storage.ErrInvalidSecretACLRequest", storage.ErrInvalidSecretACLRequest, InvalidInput},
	{"storage.ErrShareExpiryNotInFuture", storage.ErrShareExpiryNotInFuture, InvalidInput},
}

// Sentinels is the classification table, for the parity and family guards. The two
// outage sentinels and the permission sentinel are listed first because Of consults
// them first.
func Sentinels() []Sentinel {
	out := []Sentinel{
		{"core.ErrMutationAuditUnavailable", core.ErrMutationAuditUnavailable, AuditUnavailable},
		{"core.ErrStorageReadUnavailable", core.ErrStorageReadUnavailable, Unavailable},
		{"core.ErrPermissionDenied", core.ErrPermissionDenied, PermissionDenied},
	}
	return append(out, sentinelTable...)
}

// Of classifies err. Order: audit outage, storage read fault, permission refusal, then
// the sentinel table (not found, precondition, conflict, invalid input), then Internal.
// The two outage classes come first so a fault wrapped in a refusal's text is still a
// retry answer, and a permission refusal that also names a missing target stays a
// refusal (no existence oracle). nil is Internal: a caller never classifies success.
func Of(err error) Class {
	if err == nil {
		return Internal
	}
	if errors.Is(err, core.ErrMutationAuditUnavailable) {
		return AuditUnavailable
	}
	if core.IsStorageReadUnavailable(err) {
		return Unavailable
	}
	if errors.Is(err, core.ErrPermissionDenied) {
		return PermissionDenied
	}
	for _, s := range sentinelTable {
		if errors.Is(err, s.Err) {
			return s.Class
		}
	}
	return Internal
}

// OfMutation is Of for an operation that authorized inside core (INV-MW-authorize-
// lookup-error-is-503, #3873): a permission refusal core reached because the
// permission lookup hit a TRANSIENT storage failure (recorded by faults, installed
// with core.WithAuthorizeFaultRecorder) is Unavailable, not PermissionDenied: the
// caller was not judged and a retry is right. An error that is itself an authorize
// outage (core.IsAuthorizeTransient: canceled context, connection refused, ...) is
// Unavailable too. A verdict, and any non-transient lookup error, keeps its class
// (fail closed). faults may be nil.
func OfMutation(ctx context.Context, err error, faults *core.AuthorizeFaultRecorder) Class {
	c := Of(err)
	switch c {
	case PermissionDenied:
		if faults != nil && faults.Err() != nil {
			return Unavailable
		}
	case Internal:
		if core.IsAuthorizeTransient(ctx, err) {
			return Unavailable
		}
	}
	return c
}

// LookupFault reports the recorded transient permission-lookup failure behind a
// PermissionDenied refusal, or nil. The adapters use it to render Unavailable with
// the authorize-outage text rather than the storage-read one.
func LookupFault(faults *core.AuthorizeFaultRecorder) error {
	if faults == nil {
		return nil
	}
	return faults.Err()
}
