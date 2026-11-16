package storage

import (
	"errors"
)

// ErrLegalHoldAlreadyActive is returned by CreateLegalHold when a partial unique
// index (or equivalent constraint) at the storage layer rejects a second concurrent
// placement — the backstop for the TOCTOU race in core.PlaceLegalHold's
// read-then-insert (#305): two concurrent placements can both observe "no active
// hold" and both attempt to insert one, but only the first commits. Callers should
// treat this as a client error ("already active"), not a storage failure.
var ErrLegalHoldAlreadyActive = errors.New("a legal hold is already active")

// ErrLegalHoldAlreadyReleased is returned by core.LiftLegalHold when its
// conditional ReleaseLegalHold matched no row: another lift released the hold
// between this lift's read and its write. The losing lift is refused (and writes
// no audit row) instead of overwriting the first lifter's attribution. Callers
// should treat this as a conflict, not a storage failure.
var ErrLegalHoldAlreadyReleased = errors.New("the legal hold was already released")
