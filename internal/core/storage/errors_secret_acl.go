package storage

import "errors"

// ErrSecretACLNotFound is returned (wrapped) by GetSecretACL when no ACL row exists
// for the (secret, user) pair, as distinct from a retrieval failure. The per-secret
// authorization check (core aclGrantsPermission) reads only this as "no grant"; every
// other error propagates and denies with an error. Its text is gorm's "record not
// found", so the wrapped message GetSecretACL returned before the sentinel existed is
// unchanged. Match it with errors.Is (IsSecretACLNotFound), never by the i18n text:
// the text differs per locale, which made a storage outage read as "no grant" in
// English and as a 500 in de/es/fr/ru (ERRLOSS-ACL-1).
var ErrSecretACLNotFound = errors.New("record not found")

// IsSecretACLNotFound is IsUserNotFound's secret-ACL counterpart: true only for a
// definitive "no ACL row for this (secret, user) pair" (ErrSecretACLNotFound), false
// for every other error.
func IsSecretACLNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrSecretACLNotFound)
}
