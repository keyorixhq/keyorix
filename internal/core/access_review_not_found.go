package core

import (
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ErrAccessReviewNotFound is matched (errors.Is) by every "the thing this access-review
// call names does not exist" refusal: an unknown or cross-project campaign or item, a
// stale grant being attested, a revoke target (group, secret, share) that is gone. The
// handlers map it to 404 by sentinel, never by message text (the text is the translated
// i18n "ErrorNotFound" and differs per locale). A storage read FAULT is never this error:
// it is ErrStorageReadUnavailable (classifyReadError).
var ErrAccessReviewNotFound = errors.New("access review target not found")

// accessReviewNotFoundError renders exactly as the wrapped error and matches
// ErrAccessReviewNotFound in addition to everything the wrapped error matches.
type accessReviewNotFoundError struct{ err error }

func (e *accessReviewNotFoundError) Error() string { return e.err.Error() }
func (e *accessReviewNotFoundError) Unwrap() []error {
	return []error{ErrAccessReviewNotFound, e.err}
}

// accessReviewNotFound is the i18n "ErrorNotFound" refusal, with detail appended when
// non-empty ("<ErrorNotFound>: <detail>").
func accessReviewNotFound(detail string) error {
	if detail == "" {
		return &accessReviewNotFoundError{err: fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))}
	}
	return &accessReviewNotFoundError{err: fmt.Errorf("%s: %s", i18n.T("ErrorNotFound", nil), detail)}
}

// accessReviewReadError classifies a failed storage read of an access-review target:
// a positive not-found keeps the "<ErrorNotFound>: <cause>" text and matches
// ErrAccessReviewNotFound; anything else is a storage fault (ErrStorageReadUnavailable).
func accessReviewReadError(err error) error {
	if err == nil {
		return nil
	}
	if isPositiveNotFound(err) {
		return &accessReviewNotFoundError{err: fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)}
	}
	return &storageReadFault{cause: err}
}
