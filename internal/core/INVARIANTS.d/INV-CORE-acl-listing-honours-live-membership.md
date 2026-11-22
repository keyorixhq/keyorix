- **INV-CORE-acl-listing-honours-live-membership** The ACL term of the secret listing
  (`getACLGrantedSecretsWithSharingInfo`, used by `ListSecretsWithSharingInfo` and the
  overlay in `ListSecretsInScopeWithSharingInfo`) lists a `SecretACL` grant only while its
  grantee is a live member of the granted node's project. The share term
  (`sharedSecretRows`, behind `getSharedSecretsWithSharingInfo` and
  `sharedSecretDecorations`) lists a received `ShareRecord` under the same condition, the
  rule `batchShareStage` applies; `RemoveProjectMember` deletes no share rows, so a share
  survives even the normal offboarding path (REVIEW-4628 M1). That is the same rule
  `aclGrantsPermission` (#G13) and `batchACLStage` apply when they authorize. Membership is
  read once per listing through `batchMembership` (`ProjectMembershipsAmong`). A failed
  read fails the listing: it never lists a grant unchecked and never drops one behind a
  success. A folder grant's descendants are behind the same check, because they are
  expanded only after the folder's grant passed. Why: #4623. Only `RemoveProjectMember`
  deletes a user's ACL rows; `RemoveUserRole`, a group removal or a group's role removal
  can end the membership and leave them, and the listing then showed the secrets'
  metadata to the former member. Guard: `secret_acl_listing_member_recheck_test.go`
  (`TestSecretListing_ACLGrantOfRemovedMemberNotListed`,
  `TestSecretListing_FolderACLGrantOfRemovedMemberListsNoDescendant`,
  `TestSecretListing_ACLMembershipReadFaultFailsTheListing`) and
  `secret_share_listing_member_recheck_test.go`
  (`TestSecretListing_ShareOfRemovedMemberNotListed`,
  `TestSecretListing_ShareMembershipReadFaultFailsTheListing`), all default-ci, the
  removed-member cases red before the fix. **Not covered**: the stale rows themselves are
  not deleted when membership ends outside `RemoveProjectMember` (share rows are not
  deleted even by it). They stay inert for authorization and
  listing, and they become live again if the user is re-added to the project (the same
  re-add behaviour #4533 describes).
