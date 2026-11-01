- **INV-CORE-share-list-refused-at-fetch-cap** A share list built from
  `storage.ListSharesByUser` / `ListSharesByOwner` is refused with `ErrShareListOverCap`
  when either fetch comes back at the storage row cap (`shareFetchMayBeTruncated`), never
  returned shortened: storage cuts those lists off silently at `maxUnboundedListRows`, so a
  full-cap result cannot be told from a truncated one, and a short list hides shares from
  whoever is reviewing or revoking them. Applies to `ListUserShareViews` (HTTP, 422
  `ShareListOverCap`), `ListOwnedShareViews`, `ListSharesByUser` (gRPC/CLI; gRPC answers
  `FailedPrecondition`) and the shared-with-me secret listing
  (`getSharedSecretsWithSharingInfo`, behind `ListSecretsWithSharingInfo` and
  `ListSecretsInScopeWithSharingInfo`). A count from such a fetch is a floor:
  `GetDashboardStats` degrades `shared_secrets` / `shared_with_me` instead of presenting
  it as a count. The refusal is decided per fetch, not on the merged length (a fully
  overlapping received+owned pair merges to one fetch's size). Why: REVIEW-3018 — the
  gRPC/CLI merge had no refusal while the HTTP and owner-scoped lists did.
  Guard: `internal/core/guards/share_list_cap_guard_test.go`
  `TestShareListFetchCallersRefuseAtTheCap` (every core family caller of either fetch must
  call `shareFetchMayBeTruncated` or be named in `shareListCapExempt` with a reason; stale
  entries fail), `share_list_by_user_cap_test.go` `TestListSharesByUser_RefusesAFetchAtTheCap`
  / `TestListSharesByUser_ListsBothFetchesUnderTheCap`, `share_list_cap_siblings_test.go`
  (shared-with-me listing and dashboard tiles, each with a positive control), and
  `server/grpc/services` `TestShareService_ListUserShares_OverCapIsFailedPrecondition`.
  **Not covered**: a fetch reached through a wrapper not in `shareListFetches` is invisible
  to the guard; the secret-listing transports (HTTP `GET /api/v1/secrets`, gRPC
  `ListSecrets`) still answer the refusal as a generic 500 / `Internal`, not a typed code.
