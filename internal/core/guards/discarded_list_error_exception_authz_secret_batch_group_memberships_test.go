package guards

// ERRLOSS-TAILS-1 item 3: one exception for TestNoDiscardedStorageReadErrorOnDecisionPath.
//
// batchShareStage reads the user's live group memberships to decide whether a group share
// grants access to a secret. A failed read leaves `memberships` empty, which means "no group
// share applies": the decision narrows to deny, the same answer activeShareGrant gives for a
// failed lookup (the comment at the call site says so). The error is dropped on purpose, the
// failure direction is deny, and nothing is revoked or granted on it.
func init() {
	registerDiscardedReadException("authz_secret_batch.go:batchShareStage",
		"a failed group-membership read leaves the set empty, i.e. no group share applies: fails closed (deny), like activeShareGrant")
}
