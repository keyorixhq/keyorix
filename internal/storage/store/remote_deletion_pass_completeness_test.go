package store

// G80 deletion pass (docs/adr-087-remote-storage-deletion-pass.md): these 13
// methods are issue #1511's full orphaned-wire-call list — every one made a
// real rs.client.<Verb>(...) call to a route that has no matching
// registration in server/http/router.go, confirmed DEAD (every real caller is
// either behind a CLI NewRemoteClient()-family guard, server-only, or has
// zero callers anywhere) and converted from a live-but-permanently-404ing
// wire call to a remoteUnsupported() stub in this pass. See the deletion
// commit and the ADR for the full per-method evidence and the criterion used.
func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"CreateSecretVersion": {statusIntentional,
			"#1511/G80 deletion pass: POST /api/v1/secrets/*/versions has no matching route. Every core caller (storeSecretVersion/storeNextSecretVersion, reached via CreateSecret/UpdateSecret/CopySecret/RotateSecret) is behind a NewRemoteClient() CLI guard or server-only."},
		"CleanupExpiredSessions": {statusIntentional,
			"#1511/G80 deletion pass: POST /api/v1/sessions/cleanup has no matching route, and the core method itself has zero callers in any topology (internal/core/users.go's own doc comment already noted \"implemented but never scheduled\")."},
		"AssignRole": {statusIntentional,
			"#1511/G80 deletion pass: POST /api/v1/rbac/assign-role has no matching route. Dead via two independent barriers on the permanent RBAC stub chain (GetUserRoleIDsAt/GetUserGroupRoleIDsAt/RoleSetHasPermission, ADR-086): request/review.go's own requireReviewAuthority, AND core.ApproveAccessRequestWithExpiry's own requireAuthorityForRole, both fail closed before this method is ever reached — corrects Wave 0's original evidence, which only cited the NewRemoteClient()-guarded call sites and missed this path."},
		"RemoveRole": {statusIntentional,
			"#1511/G80 deletion pass: POST /api/v1/rbac/remove-role has no matching route. Same corrected evidence as AssignRole — dead via the same double barrier on the permanent RBAC stub chain, not merely a NewRemoteClient() guard."},
		"CreateShareRecord": {statusIntentional,
			"#1511/G80 deletion pass: POST /api/v1/shares has no matching route (confirmed real: the /shares group has no POST). Every caller (ShareSecret/ShareSecretWithGroup) is behind share/create.go's NewRemoteClient() guard."},
		"GetShareRecord": {statusIntentional,
			"#1511/G80 deletion pass: GET /api/v1/shares/{id} has no matching route (confirmed real: the /shares group has no GET/{id}). Every caller (UpdateSharePermission, RevokeShare) is behind a NewRemoteClient() guard."},
		"GetStats": {statusIntentional,
			"#1511/G80 deletion pass: GET /api/v1/stats has no matching route (confirmed real: only scoped */stats variants exist). Sole caller GetDashboardStats is server-only — no CLI path at all."},
		"GetLatestSecretVersion": {statusIntentional,
			"#1511/G80 deletion pass: GET /api/v1/secrets/*/versions/latest has no matching route. The one CLI path that looked unguarded (run/run.go) is not: run.go calls common.ResolveRemote() directly (Wave 0c correction), so it never reaches this method under any complete storage.type: remote config. Every other caller is behind a NewRemoteClient() guard or server-only."},
		"IncrementSecretReadCount": {statusIntentional,
			"#1511/G80 deletion pass: POST /api/v1/secret-versions/*/increment-read-count has no matching route and zero callers anywhere in internal/core (distinct from the separate, already-classified TryIncrementSecretReadCount)."},
		"ListSharedSecrets": {statusIntentional,
			"#1511/G80 deletion pass: GET /api/v1/users/*/shared-secrets has no matching route (confirmed real: only GET /shared-secrets, the caller's own, exists). Sole CLI caller (share/shared_secrets.go) is behind a NewRemoteClient() guard."},
		"CheckSharePermission": {statusIntentional,
			"#1511/G80 deletion pass: GET /api/v1/secrets/*/permissions has no matching route, and core.CheckSharePermission itself has zero callers anywhere (no HTTP handler, no gRPC service, no CLI) — orphaned server-side, not just under storage.type: remote."},
	})
}
