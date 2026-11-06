package core

import "errors"

// classifyTypedRead classifies a failed storage read of a row whose getter types its own
// not-found (LocalStorage wraps a definitive gorm.ErrRecordNotFound with a storage.Err*NotFound
// sentinel). A not-found keeps its text and its sentinel, so a transport answers 404 with
// errors.Is; anything else, whatever words the driver used, is a storage fault
// (ErrStorageReadUnavailable) and a transport answers 503, never "not found".
func classifyTypedRead(err, notFound error) error {
	if err == nil || errors.Is(err, notFound) {
		return err
	}
	return &storageReadFault{cause: err}
}

// invalidInput types a malformed-request refusal core words itself (ErrInvalidInput)
// without changing its text (the refuseAs pattern of errors_typed.go).
func invalidInput(err error) error { return refuseAs(ErrInvalidInput, err) }
