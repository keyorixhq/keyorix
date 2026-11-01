package core

import "errors"

// ErrMembershipTargetNotFound is matched (errors.Is) by the "the membership, user or
// project this lifecycle call names does not exist" refusals of the membership
// lifecycle (TransitionMembership, onboarding checks). The handlers map it to 404 by
// sentinel, never by message text. A storage read FAULT is never this error: it is
// ErrStorageReadUnavailable (classifyReadError).
var ErrMembershipTargetNotFound = errors.New("membership target not found")

// membershipNotFoundError renders as its text and matches ErrMembershipTargetNotFound.
type membershipNotFoundError struct{ msg string }

func (e *membershipNotFoundError) Error() string        { return e.msg }
func (e *membershipNotFoundError) Is(target error) bool { return target == ErrMembershipTargetNotFound }

func errMembershipNotFound(msg string) error { return &membershipNotFoundError{msg: msg} }

// membershipReadError is classifyReadError for the membership lifecycle: a positive
// not-found keeps its text and matches ErrMembershipTargetNotFound; anything else is
// a storage fault (ErrStorageReadUnavailable).
func membershipReadError(err error, notFound string) error {
	if err == nil {
		return nil
	}
	if isPositiveNotFound(err) {
		return errMembershipNotFound(notFound)
	}
	return classifyReadError(err, notFound)
}
