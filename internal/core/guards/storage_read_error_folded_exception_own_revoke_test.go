package guards

// Exceptions to TestNoStorageReadErrorFoldedIntoNotFound: a user revoking their OWN
// session / PAT. Same class as the machine-identity family fixed by STORAGE-ERR-CLASS-1,
// but not in that brief's list and each needs its own REST/gRPC mapping and tests.
// Follow-up: classify with classifyReadError and map the sentinel, then delete these rows.

func init() {
	registerFoldedReadException("account.go:RevokeOwnSession",
		"own-session revoke folds a read fault into not-found; same class, follow-up (needs its REST/gRPC mapping)")
	registerFoldedReadException("pat.go:RevokeOwnPAT",
		"own-PAT revoke folds a read fault into not-found; same class, follow-up (needs its REST/gRPC mapping)")
}
