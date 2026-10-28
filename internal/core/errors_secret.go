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
