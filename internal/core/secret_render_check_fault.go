package core

import "errors"

// secretRefCheckFault is stageRenderRef's refusal of an EXISTING referenced secret
// whose per-secret permission check failed to evaluate (a storage read fault, or a
// transient failure of the RBAC lookup the check folds into a denial).
//
// It renders as, and matches (errors.Is), ErrSecretRefNotFound and nothing else, so
// every mapper that does not ask for the fault keeps answering it exactly like a
// missing or forbidden reference (#181): the fault happens only for a secret that
// exists, so a distinct generic 503 here would be an existence oracle during a
// partial outage. It deliberately does NOT match ErrStorageReadUnavailable. A
// transport that has already established the caller may tell "missing" from
// "forbidden" (the render handler's global secrets.read holder) asks for the fault
// with SecretRefCheckFault and answers retry instead of a false "no such secret".
type secretRefCheckFault struct {
	fault error // an ErrStorageReadUnavailable that unwraps to the cause
}

func (e *secretRefCheckFault) Error() string { return ErrSecretRefNotFound.Error() }

func (e *secretRefCheckFault) Unwrap() error { return ErrSecretRefNotFound }

// SecretRefCheckFault returns the storage fault (an ErrStorageReadUnavailable, for
// sendStorageUnavailable / StorageReadFaultDetail) behind a render reference refused
// because its permission check could not be evaluated, and nil for any other error,
// including a genuine "missing" or "forbidden" refusal.
func SecretRefCheckFault(err error) error {
	if f, ok := errors.AsType[*secretRefCheckFault](err); ok {
		return f.fault
	}
	return nil
}

// renderRefCheckFault classifies a failed per-secret read check: nil when err is a
// verdict (refused, not found), otherwise the fault as an ErrStorageReadUnavailable.
// recorded is the transient RBAC lookup failure the check folded into its "insufficient
// permissions" refusal (AuthorizeFaultRecorder), which is a fault, not a verdict.
func renderRefCheckFault(err, recorded error) error {
	if fault := SecretReadVerdictFault(err); fault != nil {
		return fault
	}
	if recorded == nil {
		return nil
	}
	if IsStorageReadUnavailable(recorded) {
		return recorded
	}
	return &storageReadFault{cause: recorded}
}
