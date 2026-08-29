// remote_unsupported_widened_registry_test.go — G80 Wave 1 (#1576): the 96
// RemoteStorage methods that were structurally stub-shaped (never reach
// rs.client, by any path) but invisible to the completeness guard before
// remote_unsupported_completeness_test.go's actualRemoteUnsupportedStubs was
// rewritten from a text-pattern regex to a structural (AST-based, transitive)
// call-graph check.
//
// How the population was established as complete: two independent scans —
// (1) an AST-based call-graph walk following method AND package-level-helper
// delegation to a terminal ".client." reference, and (2) a brace-matched
// TEXT scan checking each method's own source span for the literal substring
// ".client." with NO delegation-following at all. The two agreed on every
// method except a fully-explained set the text scan over-flags because it
// can't see through delegation (TransitionSecretStatus,
// TransitionDynamicSecretConfigDisabled, TransitionProjectMembershipState,
// UpdateUserIfActiveStateMatches, ApproveRiskExceptionIfPending,
// RevokeRiskExceptionIfNotRevoked, HealthCheck, GetSecretsByIDs,
// GetSecretVersions, ListNotifications, CountUnreadNotifications,
// WithSchedulerLock, ListSharesBySecretIDs, LockWebAuthnCredentialForUpdate,
// ListEnvironmentsByProject(IncludingDeleted), the Last*Activity family — all
// confirmed real, spot-checked directly against source). Zero methods were
// flagged by the AST scan and missed by the text scan. A first AST-scan draft
// itself had one bug worth recording: it only scanned remote_*.go files,
// missing entry.go (which defines putConditionalTransition, a real
// client-calling helper several genuine proxy methods delegate to) — caught
// by spot-checking TransitionSecretStatus, which the buggy scanner
// mis-flagged as stub-shaped. Fixed before this registry was populated;
// PurgeDeletedSecretsBefore/PurgeDeletedUsersBefore/PurgeDeletedProjectsBefore/
// PurgeDeletedEnvironmentsBefore had the same false-positive shape (delegate
// to postRetentionBeforeCountResp, a package-level helper, not a method) and
// are correctly NOT in this registry — they are real, working proxy methods.
//
// Status guide: statusIntentional where either (a) the method's own existing
// doc comment already cites a specific, checkable reason (a G80 liveness
// sweep finding, a wire-format/structural impossibility, an architecture
// decision), or (b) this pass independently confirmed zero callers under
// internal/cli via `rg -c '\.MethodName\(' internal/cli --type go -g
// '!*_test.go'`. statusUnverified where classification rests on the existing
// comment's claim plus a single targeted check, not the full individual
// per-caller tracing depth Wave 0 applied to its original 13-method
// partition — the Reason says exactly what's still unverified.
package store

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		// --- G80 liveness sweep: proxy route deleted, no live caller in either
		// topology (docs/g80-remediation-notes.md). Every one of these 22 shares
		// the exact same shape: a server-side proxy handler existed, was found to
		// have zero callers under the forbidden storage.type:remote server
		// topology (ADR-083) AND zero CLI callers, and was deleted; the
		// RemoteStorage stub is the leftover client-side half, returning
		// errUnsupportedRemote. That deletion IS the verification. ---
		"UpdateAccessReviewCampaign":            {statusIntentional, "G80 liveness sweep: proxy route (UpdateAccessReviewCampaignProxy) deleted, no live caller in either topology (docs/g80-remediation-notes.md)."},
		"CreateBreakGlassActivation":            {statusIntentional, "G80 liveness sweep: proxy route (CreateBreakGlassActivationProxy) deleted, no live caller in either topology."},
		"UpdateBreakGlassActivation":            {statusIntentional, "G80 liveness sweep: proxy route (UpdateBreakGlassActivationProxy) deleted, no live caller in either topology."},
		"UpdateDynamicSecretConfig":             {statusIntentional, "G80 liveness sweep: proxy route (UpdateDynamicSecretConfigProxy) deleted, no live caller in either topology."},
		"CreateDynamicSecretConfig":             {statusIntentional, "#1580 liveness sweep: proxy route (CreateDynamicSecretConfigProxy) deleted, no live caller in either topology -- confirms the same G80 158-method classification pass's reachabilityDead verdict this map's UpdateDynamicSecretConfig entry already recorded but was never acted on for this sibling method."},
		"MarkSetupTokenConsumed":                {statusIntentional, "#1579 liveness sweep: proxy route (ConsumeSetupTokenProxy) deleted, no live caller in either topology -- core.ConsumeSetupToken's only caller is the human-facing CompleteSetup route; no CLI command reaches it (completing setup is inherently self-service, unlike admin-driven account-lifecycle CLI operations)."},
		"TransitionDynamicSecretConfigDisabled": {statusIntentional, "G80 liveness sweep: proxy route (TransitionDynamicSecretConfigDisabledProxy) deleted, no live caller in either topology."},
		"CreateDynamicSecretLease":              {statusIntentional, "G80 liveness sweep: proxy route (CreateDynamicSecretLeaseProxy) deleted, no live caller in either topology."},
		"UpdateDynamicSecretLease":              {statusIntentional, "G80 liveness sweep: proxy route (UpdateDynamicSecretLeaseProxy) deleted, no live caller in either topology."},
		"UpsertMFASecret":                       {statusIntentional, "G80 liveness sweep: proxy route (UpsertMFASecretProxy) deleted, no live caller in either topology."},
		"CreateMFAStepUpGrant":                  {statusIntentional, "G80 liveness sweep: proxy route (CreateMFAStepUpGrantProxy) deleted, no live caller in either topology."},
		"CreateConnectRefGrant":                 {statusIntentional, "G80 liveness sweep: proxy route (CreateConnectRefGrantProxy) deleted, no live caller in either topology."},
		"DeleteConnectRefGrant":                 {statusIntentional, "G80 liveness sweep: proxy route (DeleteConnectRefGrantProxy) deleted, no live caller in either topology."},
		"UpdateProject":                         {statusIntentional, "G80 liveness sweep: proxy route (UpdateProjectProxy) deleted, no live caller in either topology."},
		"RestoreProject":                        {statusIntentional, "G80 liveness sweep: proxy route (RestoreProjectProxy) deleted, no live caller in either topology."},
		"RestoreEnvironment":                    {statusIntentional, "G80 liveness sweep: proxy route (RestoreEnvironmentProxy) deleted, no live caller in either topology."},
		"DeleteSecretDependency":                {statusIntentional, "G80 liveness sweep: proxy route (DeleteSecretDependencyProxy) deleted, no live caller in either topology."},
		"DeleteAnomalyAlertsBefore":             {statusIntentional, "G80 liveness sweep: proxy route (DeleteAnomalyAlertsBeforeProxy) deleted, no live caller in either topology."},
		"DeleteClosedAccessReviewsBefore":       {statusIntentional, "G80 liveness sweep: proxy route (DeleteClosedAccessReviewsBeforeProxy) deleted, no live caller in either topology."},
		"DeleteExpiredBreakGlassBefore":         {statusIntentional, "G80 liveness sweep: proxy route (DeleteExpiredBreakGlassBeforeProxy) deleted, no live caller in either topology."},
		"DeleteResolvedAccessRequestsBefore":    {statusIntentional, "G80 liveness sweep: proxy route (DeleteResolvedAccessRequestsBeforeProxy) deleted, no live caller in either topology."},
		"UpdateLoginLockoutState":               {statusIntentional, "G80 liveness sweep: proxy route (UpdateLoginLockoutStateProxy) deleted, no live caller in either topology."},
		"CreateWebAuthnCredential":              {statusIntentional, "G80 liveness sweep: proxy route (CreateWebAuthnCredentialProxy) deleted, no live caller in either topology."},
		"DeleteWebAuthnCredential":              {statusIntentional, "G80 liveness sweep: proxy route (DeleteWebAuthnCredentialProxy) deleted, no live caller in either topology."},
		"SetUserWebAuthnEnabled":                {statusIntentional, "G80 liveness sweep: proxy route (SetUserWebAuthnEnabledProxy) deleted, no live caller in either topology."},

		// --- Audit/anomaly/hygiene analytics: dashboard/reporting aggregates.
		// Existing doc comments assert "runs/aggregates server-side"; this pass
		// independently confirmed zero CLI callers for every one of these (`rg -c
		// '\.MethodName\(' internal/cli --type go -g '!*_test.go'` = 0 files),
		// consistent with Wave 0's established finding that non-CLI-exposed
		// analytics functions are HTTP/gRPC-dashboard-only, hence server-topology-
		// only, hence dead under the ADR-083-forbidden topology. ---
		"CreateSecretAccessLog":         {statusIntentional, "No-op in remote mode (access logging is server-side); zero internal/cli callers confirmed this pass."},
		"CountImpersonatedActions":      {statusIntentional, "Server-side in remote mode (returns 0; impersonation sessions created/ended directly against the server); zero internal/cli callers confirmed this pass."},
		"ListSecretAccessLogs":          {statusIntentional, "Not available in remote mode; server handles access logs. Zero internal/cli callers confirmed this pass."},
		"CountSecretReadsBySecretIDs":   {statusIntentional, "Not available in remote mode; existing doc comment cites its one real caller (#409 rotation-planner risk-scoring batch) already falling back to zero-reads on this exact error — a verified, not assumed, caller check."},
		"PrincipalSecretFirstSeen":      {statusIntentional, "Not available in remote mode; anomaly detection is server-side. Zero internal/cli callers confirmed this pass."},
		"MostAccessedSecrets":           {statusIntentional, "Not available in remote mode; usage analytics aggregate server-side. Zero internal/cli callers confirmed this pass."},
		"UnusedSecrets":                 {statusIntentional, "Not available in remote mode; usage analytics aggregate server-side. The only internal/cli hits for this name are an unrelated JSON struct field (hygiene report display), not a call to this method — zero real callers confirmed this pass."},
		"CountUnusedSecretsByProject":   {statusIntentional, "Not available in remote mode; grouped hygiene-rollup query (#393) runs server-side. Zero internal/cli callers confirmed this pass."},
		"AuditRetentionStats":           {statusIntentional, "Not available in remote mode; retention coverage aggregates server-side. Zero internal/cli callers confirmed this pass."},
		"DeleteAuditLogsBefore":         {statusIntentional, "Not available in remote mode; audit purge runs server-side. Zero internal/cli callers confirmed this pass."},
		"VerifyAuditChain":              {statusIntentional, "Not available in remote mode; chain verification runs server-side. Zero internal/cli callers confirmed this pass."},
		"MigrateAuditChainEncoding":     {statusIntentional, "Existing doc comment: a spoke has no direct access to the hub's audit_events table and this migration needs an exclusive whole-migration lock only the actual DB owner can take — a structural, not just caller-absence, reason."},
		"CreateAuditCheckpoint":         {statusIntentional, "Not available in remote mode; checkpointing is server-side. Zero internal/cli callers confirmed this pass."},
		"LatestAuditCheckpoint":         {statusIntentional, "Not available in remote mode; checkpointing is server-side. Zero internal/cli callers confirmed this pass."},
		"UpdateAuditCheckpointAnchor":   {statusIntentional, "Not available in remote mode; checkpointing is server-side. Zero internal/cli callers confirmed this pass."},
		"AuditEntryHashByID":            {statusIntentional, "Not available in remote mode; chain verification runs server-side. Zero internal/cli callers confirmed this pass."},
		"GetSystemMetadata":             {statusIntentional, "Not available in remote mode; server-managed state is server-side. Zero internal/cli callers confirmed this pass."},
		"SetSystemMetadata":             {statusIntentional, "Not available in remote mode; server-managed state is server-side. Zero internal/cli callers confirmed this pass."},
		"CreateAnomalyAlert":            {statusIntentional, "Not available in remote mode; anomaly detection is server-side. Zero internal/cli callers confirmed this pass."},
		"ListAnomalyAlerts":             {statusIntentional, "Not available in remote mode. Zero internal/cli callers confirmed this pass."},
		"AcknowledgeAnomalyAlert":       {statusIntentional, "Not available in remote mode. Zero internal/cli callers confirmed this pass."},
		"ListUnalertedAnomalyAlerts":    {statusIntentional, "No doc comment in source; zero internal/cli callers confirmed this pass — same shape as its ListAnomalyAlerts/AcknowledgeAnomalyAlert siblings, which are documented."},
		"MarkAnomalyAlertAlerted":       {statusIntentional, "No doc comment in source; zero internal/cli callers confirmed this pass — same shape as its anomaly-alert siblings."},
		"GetDistinctActiveUserIDs":      {statusIntentional, "Not available in remote mode. Zero internal/cli callers confirmed this pass."},
		"ListProjectSecretsForDrift":    {statusIntentional, "Not available in remote mode; drift detection aggregates server-side. Zero internal/cli callers confirmed this pass."},
		"ListOrphanedSecrets":           {statusIntentional, "Not available in remote mode; the orphaned-owner JOIN runs server-side. Zero internal/cli callers confirmed this pass."},
		"CountOrphanedSecretsByProject": {statusIntentional, "Not available in remote mode; grouped hygiene-rollup query (#393) runs server-side. Zero internal/cli callers confirmed this pass."},
		"CountExpiringSecretsByProject": {statusIntentional, "Not available in remote mode; grouped hygiene-rollup query (#393) runs server-side. Zero internal/cli callers confirmed this pass."},
		"ListLiveSecretNamesByProject":  {statusIntentional, "Not available in remote mode; grouped deployment-wide name-conformance scan (#416) runs server-side. Zero internal/cli callers confirmed this pass."},
		"GetSecretTags":                 {statusIntentional, "Not available in remote mode; tag storage is server-side. Zero internal/cli callers confirmed this pass."},
		"SetSecretTags":                 {statusIntentional, "Not available in remote mode; tag storage is server-side. Zero internal/cli callers confirmed this pass."},
		"GetPreviousStatsSnapshot":      {statusIntentional, "Not supported in remote mode; stats snapshots run server-side (mirrors GetDashboardStats/GetStats, already Wave-0-confirmed HTTP-handler-only). Zero internal/cli callers confirmed this pass."},
		"SaveStatsSnapshot":             {statusIntentional, "No-op in remote mode; snapshots are managed server-side. Zero internal/cli callers confirmed this pass."},

		// --- Structural/architectural reasons that hold regardless of caller
		// tracing — the wire format or the mechanism itself makes these
		// impossible or unnecessary, not just "nobody calls it today." ---
		"SetAccountState":                 {statusIntentional, "Existing doc comment (#454): account_state has no field in the wire format UpdateUser sends — there is no way to persist this upstream at all. Failing loud (not silently no-oping) is the whole point of the method."},
		"SetPasswordHash":                 {statusIntentional, "Existing doc comment (#484): password_hash is tagged json:\"-\" on models.User, so it never reaches the wire — there is no way to persist a password change through the remote API. Failing loud is the whole point."},
		"UpdateLastLogin":                 {statusIntentional, "Not available in remote mode; last_login_at is stamped server-side inside the login handler, which always runs against LocalStorage — a structural reason, not caller-absence."},
		"WithTransaction":                 {statusIntentional, "Architectural no-op: there is no client-side transaction to open over HTTP; each remote API call is already atomic server-side. Documented in-source; not a caller-reachability question."},
		"TryIncrementSecretNodeReadCount": {statusIntentional, "G80 Wave 0/round-119: mirrors TryIncrementSecretReadCount — enforcement runs server-side, never on the remote-client hot path; fails loud rather than silently reporting success."},

		// --- Password history (ADR-025): processed server-side in remote mode. ---
		"AddPasswordHistory":   {statusIntentional, "Password changes are processed server-side in remote mode, so history is recorded there (existing doc comment). Zero internal/cli callers confirmed this pass."},
		"RecentPasswordHashes": {statusIntentional, "Same password-history subsystem as AddPasswordHistory; zero internal/cli callers confirmed this pass."},
		"PrunePasswordHistory": {statusIntentional, "Same password-history subsystem as AddPasswordHistory; zero internal/cli callers confirmed this pass."},

		// --- Session/PAT lifecycle primitives (remote_auth.go). CreateSession's
		// own extensive doc comment establishes the architecture: session
		// issuance under storage.type: remote happens atomically via
		// VerifyLoginCredentials, never through mintSession/CreateSession, for a
		// RemoteStorage-backed core. Its siblings share the same
		// errUnsupportedRemote mechanism and subsystem. `keyorix pat` — the one
		// CLI surface adjacent to the PAT half of this family — is
		// NewRemoteClient()-guarded (Mechanism A, confirmed this pass), matching
		// the pattern Wave 0 established for the rest of the CLI. Individual
		// per-method internal/core caller tracing (matching Wave 0's depth for
		// its original 13) was NOT repeated for each of these — statusUnverified. ---
		"CreateSession":                  {statusIntentional, "Deliberately no working remote implementation, and never will: existing doc comment traces the confused-deputy/privilege-escalation risk (#508) a generic remote session-mint primitive would create, and the real session-issuance path (VerifyLoginCredentials, atomic with login) that bypasses this entirely under storage.type: remote."},
		"GetSessionByID":                 {statusUnverified, "Session-lifecycle primitive, errUnsupportedRemote, same subsystem as CreateSession. No individual internal/core caller trace done this pass — inherits CreateSession's architecture claim, not independently re-verified for this specific method."},
		"GetSessionAny":                  {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"RotateSession":                  {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"ListSessionTokenHashesByFamily": {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"DeleteSessionsByFamily":         {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"ListSessionsByUser":             {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"ListSessionTokenHashesForUser":  {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"EnforceSessionLimit":            {statusUnverified, "Same as GetSessionByID — inherited, not independently re-verified."},
		"TouchSession":                   {statusUnverified, "Best-effort no-op (documented in-source), same session subsystem — inherited, not independently re-verified."},
		"CreatePersonalAccessToken":      {statusUnverified, "`keyorix pat` is NewRemoteClient()-guarded (confirmed this pass) — consistent with the DEAD-in-practice pattern Wave 0 established elsewhere, but this specific method's internal/core caller was not individually traced against all Mechanism-B CLI files this pass."},
		"ListPersonalAccessTokensByUser": {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},
		"ListActivePersonalAccessTokens": {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},
		"GetPersonalAccessTokenByID":     {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},
		"GetPersonalAccessTokenByHash":   {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},
		"RevokePersonalAccessToken":      {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},
		"TouchPersonalAccessToken":       {statusUnverified, "Best-effort no-op (documented in-source), same PAT subsystem — inherited, not independently re-verified."},
		"ListExpiredPATsByUser":          {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},
		"BulkRevokeExpiredPATsByUser":    {statusUnverified, "Same as CreatePersonalAccessToken — inherited, not independently re-verified."},

		// --- RBAC/project-catalog family: carried forward directly from G80
		// Wave 0's own per-method partition (docs/g80-wave0-remote-storage-
		// partition.md), which DID do full individual verification for exactly
		// this set. Status here matches that partition's verdict, not a fresh
		// classification. ---
		"GetUserRoleIDsAt":        {statusIntentional, "G80 Wave 0 / ADR-086: LIVE (called directly by core.Authorize, reached by 11 CLI commands — #1575). Kept as an unconditional stub deliberately: implementing it over the wire would be a fat-client authorization anti-pattern; the real fix is hub-side authorization (Wave 2). Do not delete, do not implement."},
		"GetUserGroupRoleIDsAt":   {statusIntentional, "G80 Wave 0 / ADR-086: same as GetUserRoleIDsAt — LIVE via core.Authorize, kept deliberately, see ADR-086."},
		"RoleSetHasPermission":    {statusIntentional, "G80 Wave 0 / ADR-086: same as GetUserRoleIDsAt — LIVE via core.Authorize (final step), kept deliberately, see ADR-086."},
		"GetUserRoleIDsExact":     {statusUnverified, "G80 Wave 0: reached from internal/core/project_members.go (add/remove project member); no CLI caller found in the time available for that pass, not confirmed HTTP-only either. Carried forward as-is, not re-investigated this pass."},
		"GetUserRoleScopes":       {statusUnverified, "G80 Wave 0: evidence leans LIVE via the Keyorix Connect CLI subtree (internal/cli/connect), not fully traced. Carried forward as-is, not re-investigated this pass."},
		"GetMachineRoleScopes":    {statusUnverified, "G80 Wave 0: mirrors GetUserRoleScopes, same Connect-subtree evidence gap. Carried forward as-is, not re-investigated this pass."},
		"GetUserGroupPermissions": {statusIntentional, "G80 Wave 0: not supported in remote storage. SoD conflict detection (its only caller, internal/core/sod.go) runs server-side against LocalStorage — a verified caller check, not an assumption."},
		"AssignPermissionToRole":  {statusUnverified, "G80 Wave 0: evidence leans DEAD (reached only from server/http and server/grpc handlers, plus boot-time-only bootstrap/reconcile callers); no CLI caller found. Carried forward as-is, not re-investigated this pass."},
		"IsProjectMember":         {statusIntentional, "G80 Wave 0/0c: settled and #1512 closed on this exact verdict — not live. Both plausible CLI call chains (share create, secret bulk-delete) sit behind the NewRemoteClient() guard; every other caller is HTTP/gRPC-only."},
		"IsGroupProjectScoped":    {statusIntentional, "Same verdict and citation as IsProjectMember (#1512) — sole caller ShareSecretWithGroup, same guarded path."},
		"CreatePermission":        {statusIntentional, "G80 Wave 0: DEAD — only callers are bootstrap-time seeding (auth_bootstrap.go, rbac_reconcile.go), both server-boot-only, no CLI path."},
		"CreateProject":           {statusIntentional, "G80 Wave 0: DEAD-in-practice (guarded) — internal/cli/project/create.go checks NewRemoteClient() first and posts directly to /api/v1/projects; the svc.CreateProject fallback only runs in embedded/local mode."},
		"CreateEnvironment":       {statusIntentional, "G80 Wave 0: same guarded shape as CreateProject, in project/env.go."},
	})
}
