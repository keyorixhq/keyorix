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

// ErrSecretACLGranteeNotMember is returned (wrapped) by CreateOrUpdateSecretACL when,
// at the moment the grant would commit, the grantee holds no live role grant scoped
// to the secret's project (directly or through a group): the upsert rolls back and no
// row is left.
//
// #4533: core.GrantSecretACL checks membership BEFORE the write. A RemoveProjectMember
// committing between that check and the upsert has already run its CWE-284 ACL
// cascade (DeleteSecretACLsByUserAndProject) without seeing the grant, so the grant
// committed for a removed member: inert for authorization (HasSecretACL re-checks
// membership) but still listed to the removed user through the ACL listing source,
// and live again when an admin re-adds them. The storage layer therefore re-asks the
// membership question AFTER the write, inside the write's own transaction, with the
// grantee's direct project grants read FOR SHARE on Postgres — lockLiveParent's
// write-then-check argument applied to a membership parent: RemoveAllProjectRoleGrants
// row-locks those rows before the cascade sweeps the ACLs, so either the cascade sees
// the committed grant and sweeps it, or this grant fails closed. Core maps the sentinel
// to the same invalid-request refusal its pre-check gives for a non-member, so a client
// cannot tell the race from a serial remove-then-grant.
var ErrSecretACLGranteeNotMember = errors.New("grantee is not a member of the secret's project")
