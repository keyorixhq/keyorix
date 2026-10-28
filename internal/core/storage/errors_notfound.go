package storage

import "errors"

// Not-found sentinels for entities whose LocalStorage getters used to return a
// bare, untyped error for gorm.ErrRecordNotFound (an i18n string or a fixed
// English phrase). Handlers then classified those by matching the error TEXT,
// which breaks under a translated locale (the de/es/fr/ru texts do not contain
// "not found"; same class as #2461). Classify with errors.Is on these, never
// by message text.
//
// Each sentinel is returned wrapped, ONLY for a definitive gorm.ErrRecordNotFound
// (never for a driver or connection failure). The rendered text of the returned
// error is unchanged (see NotFound), so any remaining text matcher keeps
// working until it is migrated.
var (
	ErrNotificationChannelNotFound = errors.New("notification channel not found")
	ErrMachineCredentialNotFound   = errors.New("machine credential not found")
	ErrOIDCBindingNotFound         = errors.New("oidc binding not found")
	ErrConnectorBindingNotFound    = errors.New("connector project binding not found")
	ErrSecretTemplateNotFound      = errors.New("secret template not found")
	ErrShareNotFound               = errors.New("share not found")
	ErrSSOLoginStateNotFound       = errors.New("sso login state not found")
	ErrPermissionNotFound          = errors.New("permission not found")
	ErrAlertEscalationNotFound     = errors.New("alert escalation policy not found")
	ErrRotationPolicyNotFound      = errors.New("rotation policy not found")

	// ErrSecretDependencyNotFound: GetSecretDependency / DeleteSecretDependency
	// matched no secret_dependencies row.
	ErrSecretDependencyNotFound = errors.New("secret dependency not found")

	// ErrVersionCommentNotFound: DeleteSecretVersionComment matched no comment of
	// that secret and version.
	ErrVersionCommentNotFound = errors.New("secret version comment not found")

	// ErrRolePermissionNotAssigned: RemovePermissionFromRole matched no
	// role_permissions row (the permission was not bundled into that role).
	ErrRolePermissionNotAssigned = errors.New("permission not assigned to role")
)

// notFoundError carries a caller-visible message (typically a translated i18n
// string) unchanged while unwrapping to a typed sentinel and, when present,
// the underlying driver error.
type notFoundError struct {
	msg      string
	sentinel error
	cause    error
}

func (e *notFoundError) Error() string { return e.msg }

func (e *notFoundError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.sentinel}
	}
	return []error{e.sentinel, e.cause}
}

// NotFound returns an error that renders as msg exactly, matches sentinel under
// errors.Is, and also matches cause (e.g. gorm.ErrRecordNotFound) when non-nil.
func NotFound(sentinel error, msg string, cause error) error {
	return &notFoundError{msg: msg, sentinel: sentinel, cause: cause}
}
