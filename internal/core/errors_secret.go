package core

import (
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ErrAlreadyCurrentVersion: a rollback targeted the version the secret already
// serves. The handler answers 400.
var ErrAlreadyCurrentVersion = errors.New("target version is already the current version")

// ErrSecretAlreadyExists: CreateSecret found a live secret of that name in the
// project and environment. The handler answers 409.
var ErrSecretAlreadyExists = errors.New("secret already exists")

// ErrSecretTargetInvalid: CreateSecret's target environment does not exist or
// does not belong to the requested project. The handler answers 422.
var ErrSecretTargetInvalid = errors.New("secret target environment is invalid")

func errSecretTargetInvalidf(format string, a ...any) error {
	return storage.Typed(ErrSecretTargetInvalid, fmt.Sprintf(format, a...), nil)
}

// ErrSecretNotDeleted: RestoreSecret found the secret live (not soft-deleted), so
// there is nothing to restore (#3737). A state conflict, not a storage failure: the
// handler answers 409; a missing secret stays storage.ErrSecretNotFound (404).
var ErrSecretNotDeleted = errors.New("secret is not deleted")

func errSecretNotDeleted(id uint) error {
	return storage.Typed(ErrSecretNotDeleted, fmt.Sprintf("secret %d is not deleted; nothing to restore", id), nil)
}

// ErrSecretInvalidInput: a request to change a secret's tags, description or
// place in the tree (move, copy) was rejected as invalid: a bound exceeded, a
// folder expected, a cross-project target. The handlers answer 400.
var ErrSecretInvalidInput = errors.New("secret request is invalid")

func errSecretInvalidf(format string, a ...any) error {
	return storage.Typed(ErrSecretInvalidInput, fmt.Sprintf(format, a...), nil)
}

// errSecretValidation wraps a CreateSecret validation failure (request shape,
// value policy, name policy, address name). It renders as before ("Validation
// error: <cause>"), keeps cause in the chain, and matches ErrSecretInvalidInput
// under errors.Is, so callers (create, copy) answer 400 from the kind of failure.
func errSecretValidation(cause error) error {
	return storage.Typed(ErrSecretInvalidInput, fmt.Sprintf("%s: %v", i18n.T("ErrorValidation", nil), cause), cause)
}

// ErrUnsupportedExportFormat: an access-log export asked for a format other than
// csv or json. The handler answers 400.
var ErrUnsupportedExportFormat = errors.New("unsupported export format")

func errUnsupportedExportFormatf(format string) error {
	return storage.Typed(ErrUnsupportedExportFormat, fmt.Sprintf("unsupported export format %q: must be csv or json", format), nil)
}

// errSecretNotFoundText is the not-found refusal for a secret that a write
// matched no row of (it was deleted between the read and the write). It renders
// the translated i18n text exactly as before and matches
// storage.ErrSecretNotFound under errors.Is, so handlers answer 404 from the
// kind of failure, not from the language of the message.
func errSecretNotFoundText() error {
	return storage.NotFound(storage.ErrSecretNotFound, i18n.T("ErrorSecretNotFound", nil), nil)
}

// errVersionNotFoundText is the definitive "this secret has no such version"
// refusal; it matches storage.ErrSecretVersionNotFound.
func errVersionNotFoundText(versionNumber int) error {
	return storage.NotFound(storage.ErrSecretVersionNotFound,
		fmt.Sprintf("%s: version %d not found", i18n.T("ErrorVersionNotFound", nil), versionNumber), nil)
}

// secretLookupError wraps a failed storage GetSecret of a secret the caller
// named. A definitive miss keeps the translated not-found text (and the
// storage.ErrSecretNotFound sentinel through %w); any other failure is a
// retrieval failure that must not read as "no such secret".
func secretLookupError(err error) error {
	if storage.IsSecretNotFound(err) {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
}

// ErrSecretNotOwner: an ownership transfer was refused because the caller is not
// the secret's current owner (and the owner is not gone). It also matches
// ErrPermissionDenied; the handler gives it a fixed message.
var ErrSecretNotOwner = errors.New("caller is not the current owner of the secret")

func errSecretNotOwnerf(format string, a ...any) error {
	return markPermissionDenied(storage.Typed(ErrSecretNotOwner, fmt.Sprintf(format, a...), nil))
}

// newOwnerLookupError wraps a failed storage GetUser of the prospective new
// owner of a secret: a definitive miss is a validation refusal that matches
// storage.ErrUserNotFound, anything else is a retrieval failure.
func newOwnerLookupError(id uint, err error) error {
	if storage.IsUserNotFound(err) {
		return storage.NotFound(storage.ErrUserNotFound,
			fmt.Sprintf("%s: new owner %d not found", i18n.T("ErrorValidation", nil), id), err)
	}
	return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
}

// ErrDependencyInvalid: a secret dependency request was rejected as invalid (a
// self-edge, a target outside the project and environment, a duplicate, a cycle,
// a folder as an endpoint). The handlers answer 400.
var ErrDependencyInvalid = errors.New("secret dependency request is invalid")

func errDependencyInvalidf(format string, a ...any) error {
	return storage.Typed(ErrDependencyInvalid, fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), fmt.Sprintf(format, a...)), nil)
}

// ErrCertificateUnparseable: the secret's value is not a parseable X.509
// certificate (InspectCertificate). The handler answers 400.
var ErrCertificateUnparseable = errors.New("secret value is not a parseable X.509 certificate")

// ErrVersionDiffInvalid: a version diff request was rejected as invalid (missing
// secret, non-positive version numbers, identical versions). The handler answers 400.
var ErrVersionDiffInvalid = errors.New("secret version diff request is invalid")

func errVersionDiffInvalidf(format string, a ...any) error {
	return storage.Typed(ErrVersionDiffInvalid, fmt.Sprintf("%s: %s", i18n.T("ErrorValidation", nil), fmt.Sprintf(format, a...)), nil)
}

// diffVersionLookupError wraps a failed GetSecretVersion of a diff endpoint: a
// definitive miss keeps the version-not-found text and sentinel, anything else
// (a storage failure) stays out of the not-found class.
func diffVersionLookupError(err error) error {
	if storage.IsSecretVersionNotFound(err) {
		return fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}
	return err
}
