package storage

import "errors"

// ErrProjectNotFound is returned (wrapped) by GetProject and GetProjectByName
// for a definitive "no such project row" (gorm.ErrRecordNotFound) only — never
// for a transient retrieval failure, which keeps its own "failed to get
// project" wrapping so a caller can tell a missing project from a storage
// fault. The text stays exactly "project not found" so existing text matchers
// keep working until they migrate to IsProjectNotFound.
//
// ERRLOSS-MFA-1: the per-project MFA gate (ProjectMFABlocked over HTTP,
// enforceProjectMFA over gRPC) used to let a request through whenever the
// GetProject error text contained "not found" — any storage error carrying
// those words skipped MFA. The gates now classify with IsProjectNotFound.
var ErrProjectNotFound = errors.New("project not found")

// ErrEnvironmentNotFound is ErrProjectNotFound's environment counterpart,
// returned (wrapped) by GetEnvironment for gorm.ErrRecordNotFound only. The
// text stays exactly "environment not found".
var ErrEnvironmentNotFound = errors.New("environment not found")

// IsProjectNotFound is true only for a definitive "this project does not
// exist", false for a transient retrieval failure — even one whose text
// happens to contain "not found".
func IsProjectNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrProjectNotFound)
}

// IsEnvironmentNotFound is IsProjectNotFound's environment counterpart.
func IsEnvironmentNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrEnvironmentNotFound)
}
