package http

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/webui"
)

const (
	cacheNoCache = "no-cache" // NOSONAR -- cognitive complexity 20, suppress go:S3776
	hdrCacheControl = "Cache-Control"
	hdrContentType = "Content-Type"
	pathEnvironmentsID = "/environments/{id}"
	pathGroups = "/groups"
	pathGroupsID = "/groups/{id}"
	pathIDPermissions = "/{id}/permissions"
	pathIDRestore = "/{id}/restore"
	pathIDRoles = "/{id}/roles"
	pathInvitations = "/invitations"
	pathLegalHold = "/legal-hold"
	pathMetrics = "/metrics"
	pathProjectEnvs = "/projects/{id}/environments"
	pathProjectMembers = "/projects/{id}/members"
	pathProjects = "/projects"
	pathProjectsID = "/projects/{id}"
	pathRiskExceptions = "/risk-exceptions"
	pathRiskExceptionsID = "/risk-exceptions/{id}"
	pathSCIMGroupsID = "/Groups/{id}"
	pathSCIMUsersID = "/Users/{id}"
	pathStatus = "/status"
	permAuditRead = "audit.read"
	permRolesAssign = "roles.assign"
	permRolesRead = "roles.read"
	permRolesWrite = "roles.write"
	permSecretsDelete = "secrets.delete"
	permSecretsManage = "secrets.manage"
	permSecretsRead = "secrets.read"
	permSecretsWrite = "secrets.write"
	permSystemRead = "system.read"
	permSystemWrite = "system.write"
	permUsersRead = "users.read"
	permUsersWrite = "users.write"
)

// NewRouter creates and configures the HTTP router
func NewRouter(cfg *config.Config, coreService *core.KeyorixCore) (http.Handler, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	r := chi.NewRouter()

	// Apply middleware. Recovery is registered FIRST so it is the OUTERMOST handler in
	// the chain (chi wraps middleware in registration order: the first Use() call wraps
	// everything registered after it). A panic in any later-registered middleware —
	// RequestID, ClientIP, Logger, or anything below — must still be caught and turned
	// into a clean 500 rather than propagating out to net/http's own bare panic
	// recovery (which just logs and drops the connection, with none of Recovery's
	// structured JSON response or panic-context logging). Recovery itself only reads
	// the raw request (header, context — best-effort, nil-safe) so it has no ordering
	// dependency on anything registered after it.
	r.Use(customMiddleware.Recovery())
	r.Use(middleware.RequestID)
	// Trusted-proxy-aware client IP: honor X-Forwarded-For / X-Real-IP ONLY when the TCP
	// peer is a configured trusted proxy, otherwise use the real peer. chi's RealIP trusts
	// the header unconditionally, which lets any client spoof its source IP and defeat the
	// per-IP login/MFA brute-force rate limiter.
	r.Use(customMiddleware.ClientIP(cfg.Server.HTTP.TrustedProxies))
	r.Use(customMiddleware.Logger())
	r.Use(customMiddleware.SecurityHeaders(cfg.Server.HTTP.TLS.Enabled))
	// Global default: no-store on every response (#433). This is a secrets manager — a
	// browser or intermediate proxy must never be allowed to cache anything by default,
	// including routes registered outside the auth/SCIM/API groups (health/status/metrics,
	// the OpenAPI spec, swagger docs, the web UI shell) or any route added here later.
	// Registered early (before per-route handlers/middleware further down the chain) so it
	// merely sets the header first: a handler that deliberately wants different caching
	// (the health/readiness checks' own cacheNoCache, the status pages' own cacheNoCache, and
	// the web UI's hashed static assets via setCacheHeaders) calls w.Header().Set on the
	// same key afterward and wins, since Set replaces rather than appends. Routes with no
	// opinion of their own keep the safe no-store default instead of silently having none.
	r.Use(customMiddleware.NoStore)
	r.Use(customMiddleware.PrometheusMiddleware)
	r.Use(customMiddleware.MaxBodyBytes(cfg.Server.HTTP.EffectiveMaxRequestBodyBytes()))
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration - updated for web dashboard. AllowCredentials is
	// deliberately NOT set: this API is bearer-token-only (Authorization header),
	// never cookie-based, so there is no credentialed cross-origin request to allow.
	// Leaving it unset (defaults false) means a future cookie-based auth addition
	// must explicitly opt back in here — and get re-reviewed — rather than silently
	// inheriting a permissive flag that predates it.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: getAllowedOrigins(cfg),
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders: []string{"Accept", "Authorization", hdrContentType, "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders: []string{"Link", "X-Total-Count", "X-Page-Count"},
		MaxAge:         300,
	}))

	// Initialize handlers
	userHandler, groupHandler, err := handlers.InitCoreHandlers(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to init core HTTP handlers: %w", err)
	}

	authHandler := handlers.NewAuthHandler(coreService, cfg.Server.HTTP.TLS.Enabled)
	patHandler := handlers.NewPATHandler(coreService)
	impersonationHandler := handlers.NewImpersonationHandler(coreService, cfg.Server.HTTP.TLS.Enabled)

	secretHandler, err := handlers.NewSecretHandler(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret handler: %w", err)
	}

	shareHandler, err := handlers.NewShareHandler(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to create share handler: %w", err)
	}

	catalogHandler := handlers.NewCatalogHandler(coreService)
	dashboardHandler := handlers.NewDashboardHandler(coreService)
	adminUsageHandler := handlers.NewAdminUsageHandler(coreService)
	auditHandler := handlers.NewAuditHandler(coreService)
	licenseHandler := handlers.NewLicenseHandler(coreService)
	rotationPolicyHandler := handlers.NewRotationPolicyHandler(coreService)
	dynamicSecretHandler := handlers.NewDynamicSecretHandler(coreService)
	rbacHandler := handlers.NewRBACHandler(coreService)
	usersRolesHandler := handlers.NewUsersRolesHandler(coreService)
	notificationHandler := handlers.NewNotificationHandler(coreService)
	connectHandler := handlers.NewConnectHandler(coreService)
	adminJobsHandler := handlers.NewAdminJobsHandler(coreService)
	folderHandler := handlers.NewFolderHandler(coreService)

	// Auth endpoints (no authentication middleware). Several of these mint or hand back a
	// session token (login, refresh, MFA/WebAuthn verify, the SSO/SAML callbacks) or
	// bootstrap/setup credentials (system/init, setup consume) — a browser or intermediate
	// cache must never be allowed to cache that response. Covered by the router's global
	// no-store default (above) rather than a group-local one.
	r.Group(func(r chi.Router) {
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/refresh", authHandler.RefreshToken)
		r.Post("/auth/password-reset", authHandler.PasswordReset)
		// MFA second-step: unauthenticated — the bearer is the single-use challenge
		// issued by /auth/login, not a session.
		r.Post("/auth/mfa/verify", authHandler.VerifyMFA)
		// WebAuthn second-step assertion — also unauthenticated; the bearer is the same
		// single-use challenge from /auth/login plus the ceremony's webauthn_session.
		r.Post("/auth/webauthn/login/begin", authHandler.BeginWebAuthnLogin)
		r.Post("/auth/webauthn/login/finish", authHandler.FinishWebAuthnLogin)
		// Passwordless (usernameless) passkey login — public; a single resident-passkey
		// gesture with user verification mints a session, no password (ADR-036 addendum).
		r.Post("/auth/webauthn/passwordless/begin", authHandler.BeginWebAuthnPasswordlessLogin)
		r.Post("/auth/webauthn/passwordless/finish", authHandler.FinishWebAuthnPasswordlessLogin)
		r.Post("/system/init", authHandler.InitSystem)

		// Credential-delivery setup links (ADR-028) — unauthenticated: the bearer is the
		// single-use setup token in the URL / request body, not a session.
		r.Get("/auth/setup/{token}", authHandler.GetSetupToken)
		r.Post("/auth/setup/consume", authHandler.ConsumeSetup)

		// Human SSO login (OIDC authorization-code flow) — unauthenticated: the IdP is
		// the authenticator. The login redirect, the IdP callback, and the provider list
		// the login page reads. With sso disabled the provider list is empty and BeginSSO
		// 400s on any provider.
		r.Get("/auth/sso/providers", authHandler.ListSSOProviders)
		r.Get("/auth/sso/{provider}/login", authHandler.BeginSSO)
		r.Get("/auth/sso/{provider}/callback", authHandler.CompleteSSO)
		// SAML 2.0 SP endpoints (ADR-063): metadata for the IdP admin, the login redirect
		// (AuthnRequest), and the Assertion Consumer Service. Unauthenticated, like OIDC.
		r.Get("/auth/saml/{provider}/metadata", authHandler.SAMLMetadata)
		r.Get("/auth/saml/{provider}/login", authHandler.BeginSAML)
		r.Post("/auth/saml/{provider}/acs", authHandler.CompleteSAML)
	})

	// Health check endpoint — lightweight liveness signal (does not touch the DB, so a
	// transient DB outage won't get the pod restarted).
	r.Get("/health", handlers.HealthCheck)

	// Readiness probe — verifies the database is reachable before routing traffic to
	// this replica. Unauthenticated, like /health (k8s probes are unauthenticated).
	r.Get("/readyz", handlers.ReadinessCheck(coreService))

	// Prometheus metrics — unauthenticated by design (standard for scraping); keep
	// it inside your perimeter. Exposes HTTP request metrics + Go runtime/process.
	r.Handle(pathMetrics, customMiddleware.MetricsHandler())

	// Status page endpoint - serves stylish status dashboard
	r.Get(pathStatus, func(w http.ResponseWriter, r *http.Request) {
		webDir := getWebAssetsPath(cfg)
		if webDir != "" {
			statusPath := filepath.Join(webDir, "status.html")
			if _, err := os.Stat(statusPath); err == nil {
				w.Header().Set(hdrContentType, "text/html")
				w.Header().Set(hdrCacheControl, cacheNoCache)
				http.ServeFile(w, r, statusPath)
				return
			}
		}
		// Fallback to JSON health check if status.html not found
		handlers.HealthCheck(w, r)
	})

	// Spanish status page endpoint
	r.Get("/status-es", func(w http.ResponseWriter, r *http.Request) {
		webDir := getWebAssetsPath(cfg)
		if webDir != "" {
			statusPath := filepath.Join(webDir, "status-es.html")
			if _, err := os.Stat(statusPath); err == nil {
				w.Header().Set(hdrContentType, "text/html")
				w.Header().Set(hdrCacheControl, cacheNoCache)
				http.ServeFile(w, r, statusPath)
				return
			}
		}
		// Fallback to JSON health check if status-es.html not found
		handlers.HealthCheck(w, r)
	})

	// API v1 routes
	// SCIM 2.0 provisioning (RFC 7644) — opt-in, authenticated by a static bearer
	// token (NOT the session/PAT auth) so an IdP can provision/deprovision users.
	if cfg.SCIM.Enabled {
		// Fail startup on a too-short SCIM bearer token rather than silently serving
		// the provisioning endpoint behind a weak, brute-forceable credential (unlike
		// a PAT/machine token, this one is operator-supplied, not server-generated).
		if err := core.ValidateSCIMTokenStrength(cfg.SCIM.GetToken()); err != nil {
			return nil, fmt.Errorf("scim: %w", err)
		}
		scimHandler := handlers.NewSCIMHandler(coreService)
		r.Route("/scim/v2", func(r chi.Router) {
			// no-store is covered by the router's global default (above).
			r.Use(customMiddleware.SCIMToken(cfg.SCIM.GetToken()))
			r.Get("/ServiceProviderConfig", scimHandler.GetServiceProviderConfig)
			r.Get("/Users", scimHandler.ListUsers)
			r.Post("/Users", scimHandler.CreateUser)
			r.Get(pathSCIMUsersID, scimHandler.GetUser)
			r.Put(pathSCIMUsersID, scimHandler.ReplaceUser)
			r.Patch(pathSCIMUsersID, scimHandler.PatchUser)
			r.Delete(pathSCIMUsersID, scimHandler.DeleteUser)
			r.Get("/Groups", scimHandler.ListGroups)
			r.Post("/Groups", scimHandler.CreateGroup)
			r.Get(pathSCIMGroupsID, scimHandler.GetGroup)
			r.Put(pathSCIMGroupsID, scimHandler.ReplaceGroup)
			r.Patch(pathSCIMGroupsID, scimHandler.PatchGroup)
			r.Delete(pathSCIMGroupsID, scimHandler.DeleteGroup)
		})
	}

	r.Route("/api/v1", func(r chi.Router) {
		// Never let any API response (secret values, tokens, …) be cached by a browser or
		// proxy. Covered by the router's global no-store default (above), which runs
		// before Authentication too, so even a 401 carries it.
		// Authentication middleware for API routes
		r.Use(customMiddleware.Authentication(coreService))
		// General per-principal request budget (#163) — a backstop against one
		// already-authorized principal hammering expensive endpoints (e.g. the
		// deployment-wide compliance-posture/secrets-inventory-export handlers), not
		// an authorization boundary. Runs right after Authentication so the
		// principal is resolved. No-op unless server.http.ratelimit.enabled is set.
		r.Use(customMiddleware.PrincipalRateLimit(cfg.Server.HTTP.RateLimit))
		// Double-submit CSRF check for cookie-authenticated state-changing requests
		// (Phase 1 auth-cookie migration) — no-op for Bearer-only callers (PATs,
		// machine tokens, CI/API clients), see RequireCSRF's doc comment.
		r.Use(customMiddleware.RequireCSRF)
		// Confine restricted (must-change-password) sessions to the password-change
		// allowlist (ADR-025).
		r.Use(customMiddleware.EnforceAccountRestriction)
		// When the deployment mandates MFA, confine interactive sessions without
		// MFA to the enrolment endpoints (security.require_mfa). No-op when off.
		r.Use(customMiddleware.EnforceMFAEnrollment(cfg.Security.RequireMFA))

		// Self-service account endpoints (My Account). Authenticated but not
		// permission-gated — every user manages their own profile, password,
		// sessions, and personal access tokens. ADR-021 / ADR-027.
		r.Get("/auth/profile", authHandler.Profile)
		r.Put("/auth/profile", authHandler.UpdateProfile)
		r.Post("/auth/change-password", authHandler.ChangePassword)
		// MFA self-service (acts on the authenticated caller's own account). The
		// authenticator-lifecycle routes are blocked under impersonation so an admin
		// acting as a user cannot alter the user's MFA / plant a durable credential that
		// outlives the impersonation session.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/enroll", authHandler.EnrollMFA)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/activate", authHandler.ActivateMFA)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/disable", authHandler.DisableMFA)
		r.Get("/auth/mfa/recovery-codes", authHandler.RecoveryCodesStatus)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/recovery-codes/regenerate", authHandler.RegenerateRecoveryCodes)
		// WebAuthn / passkey self-service (acts on the authenticated caller's account).
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/webauthn/register/begin", authHandler.BeginWebAuthnRegistration)
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/webauthn/register/finish", authHandler.FinishWebAuthnRegistration)
		r.Get("/auth/webauthn/credentials", authHandler.ListWebAuthnCredentials)
		// Deleting a passkey disables WebAuthn when it removes the last one — the same
		// durable MFA-downgrade that /auth/mfa/disable is blocked from doing under
		// impersonation. There is no admin API to remove another user's passkey, so without
		// this guard impersonation would be the one path to weaken a user's second factor.
		r.With(customMiddleware.BlockWhenImpersonating).Delete("/auth/webauthn/credentials/{id}", authHandler.DeleteWebAuthnCredential)
		r.Get("/auth/sessions", authHandler.ListSessions)
		r.Delete("/auth/sessions/{id}", authHandler.RevokeSession)
		r.Get("/auth/tokens", patHandler.ListPATs)
		// Minting a PAT under impersonation would create a durable token owned by the
		// target that outlives the session — block it.
		r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/tokens", patHandler.CreatePAT)
		r.Delete("/auth/tokens/{id}", patHandler.RevokePAT)
		// Self-scoped: end the current impersonation session (no permission gate).
		r.Post("/auth/end-impersonation", impersonationHandler.End)

		// In-app notifications (ADR-024) — self-scoped, no permission gate.
		r.Get("/notifications", notificationHandler.List)
		r.Post("/notifications/read-all", notificationHandler.MarkAllRead)
		r.Post("/notifications/{id}/read", notificationHandler.MarkRead)

		// Dashboard endpoints
		// GetStats is the caller's OWN home dashboard (their secret/share counts,
		// their expiring secrets) so it stays reachable by any real principal — but it
		// previously required NO permission at all, not even the universal system_viewer
		// baseline, so a principal holding zero permissions in this system (e.g. a
		// narrowly-scoped machine identity/PAT) could still reach it. Require system.read
		// to close that: every human user holds it from CreateUser (ADR-021), so this is
		// a no-op for the product's normal users and only turns away a principal with no
		// legitimate standing here at all. The deployment-wide aggregate fields the
		// handler also returns (active users, audit-event counts, failed-auth counts) are
		// separately scoped to audit.read INSIDE GetDashboardStats (core/dashboard.go),
		// mirroring the recent-activity scoping already there — a baseline caller gets
		// their own numbers with the org-wide aggregates zeroed, not a 403 on their own
		// home page.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/dashboard/stats", dashboardHandler.GetStats)
		// The full activity feed is org-wide audit data — gate it behind audit.read.
		// (Per-user dashboard stats scope their own recent-activity in core.)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/dashboard/activity", dashboardHandler.GetActivity)

		// Catalog endpoints (projects, environments).
		// List endpoints need global read (browse everything); accessing a
		// specific project/environment is scoped to that project. Creating a
		// project has no parent scope, so it requires global write.
		projectScope := customMiddleware.ScopeFromProjectParam("id")
		// Keyorix Connect (ADR-043): read-through federation to external secret stores.
		// Gated by the dedicated connect.read permission (ADR-044) — distinct from
		// native secrets.read, so external-store access is granted explicitly.
		r.With(customMiddleware.RequirePermission("connect.read")).Get("/connect/connectors", connectHandler.ListConnectors)
		r.With(customMiddleware.RequirePermission("connect.read")).Get("/connect/{name}/secret", connectHandler.GetSecret)
		// Per-reference grant management (ADR-045) — scopes which refs which roles may
		// read. Privileged role-authorization config, so gated by roles.read/roles.write
		// rather than connect.read.
		r.With(customMiddleware.RequirePermission(permRolesRead)).Get("/connect/ref-grants", connectHandler.ListRefGrants)
		r.With(customMiddleware.RequirePermission(permRolesWrite)).Post("/connect/ref-grants", connectHandler.CreateRefGrant)
		r.With(customMiddleware.RequirePermission(permRolesWrite)).Delete("/connect/ref-grants/{id}", connectHandler.DeleteRefGrant)
		r.With(customMiddleware.RequirePermission(permSecretsRead)).Get(pathProjects, catalogHandler.ListProjects)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get(pathProjectsID, catalogHandler.GetProject)
		r.With(customMiddleware.RequirePermission(permSecretsWrite)).Post(pathProjects, catalogHandler.CreateProject)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Put(pathProjectsID, catalogHandler.UpdateProject)
		r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, projectScope)).Delete(pathProjectsID, catalogHandler.DeleteProject)
		// Restore reinstates every role grant the project carried at deletion — the
		// same blast radius as a role grant — so gate on roles.assign (#161), not
		// secrets.write, mirroring the direct-grant paths (matching #147's group fix).
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/restore", catalogHandler.RestoreProject)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/drift", catalogHandler.GetProjectDrift)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/rotation-order", secretHandler.GetProjectRotationOrder)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/rotation-plan", secretHandler.GetProjectRotationPlan)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/health", secretHandler.GetProjectHealth)
		// Deployment-wide rotation plan (ADR-053): aggregates every project. Gated by
		// GLOBAL secrets.read — the same access level as listing all projects — so it
		// reveals no project the caller cannot already see.
		r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/rotation-plan", secretHandler.GetDeploymentRotationPlan)
		// Project membership (ADR-021 two-tier model). Read = project members may
		// view the roster; mutations require roles.assign at the project scope, so
		// a project_admin can manage their own project's members.
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get(pathProjectMembers, catalogHandler.ListProjectMembers)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review", catalogHandler.GetProjectAccessReview)
		// Recertification decisions (ISO 27001 A.5.18): attest is a reviewer action
		// (roles.read); revoke removes the grant and needs roles.assign.
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Post("/projects/{id}/access-review/attest", catalogHandler.AttestProjectAccessReview)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/revoke", catalogHandler.RevokeProjectAccessReview)
		// Access-review campaigns (A.5.18 periodic recertification): reads roles.read,
		// mutations roles.assign, at the project scope.
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review/campaigns", catalogHandler.ListAccessReviewCampaigns)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/campaigns", catalogHandler.OpenAccessReviewCampaign)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review/campaigns/{campaignId}", catalogHandler.GetAccessReviewCampaign)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide", catalogHandler.DecideAccessReviewCampaignItem)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/access-review/campaigns/{campaignId}/close", catalogHandler.CloseAccessReviewCampaign)
		// CSV export of a campaign's items + decisions — the auditor's signed-off
		// recertification record (ISO 27001 A.5.18). Read-only, roles.read (project).
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/access-review/campaigns/{campaignId}/export.csv", catalogHandler.ExportAccessReviewCampaignCSV)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post(pathProjectMembers, catalogHandler.AddProjectMember)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/members/{userId}", catalogHandler.UpdateProjectMember)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/members/{userId}", catalogHandler.RemoveProjectMember)
		// Membership lifecycle (ADR-022): onboarding state machine, separate from
		// the role grant above. List is project-read; mutations need roles.assign.
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/memberships", catalogHandler.ListProjectMemberships)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/memberships", catalogHandler.InviteMember)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/memberships/{membershipId}", catalogHandler.TransitionMembership)
		// Invitations (ADR-024): admin-driven (roles.assign at the project scope).
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/invitations", catalogHandler.ListInvitations)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/invitations", catalogHandler.CreateInvitation)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/invitations/{invitationId}", catalogHandler.RevokeInvitation)
		// Resend the invitation's setup link (ADR-028).
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/invitations/{invitationId}/resend", catalogHandler.ResendInvitation)
		// Global (non-project-scoped) invitation (ADR-024): system role + multi-project
		// assignments applied atomically on accept. A system-admin operation (users.write).
		r.With(customMiddleware.RequirePermission(permUsersWrite)).Post(pathInvitations, catalogHandler.CreateGlobalInvitation)
		// Access requests (ADR-024): requesting + withdrawing are self-service (any
		// authenticated user — they don't have project access yet); listing and
		// approving/rejecting require roles.assign at the project scope.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Get("/projects/{id}/access-requests", catalogHandler.ListAccessRequests)
		r.Post("/projects/{id}/access-requests", catalogHandler.CreateAccessRequest)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/access-requests/{requestId}", catalogHandler.ResolveAccessRequest)
		r.Post("/projects/{id}/access-requests/{requestId}/withdraw", catalogHandler.WithdrawAccessRequest)
		// Break-glass emergency access: activation is self-service (un-gated — the
		// point is access the caller lacks; controlled by config + justification +
		// audit + auto-expiry). Listing/revoking are review actions (roles.read/assign).
		r.Post("/projects/{id}/break-glass", catalogHandler.ActivateBreakGlass)
		r.With(customMiddleware.RequireScopedPermission(permRolesRead, projectScope)).Get("/projects/{id}/break-glass", catalogHandler.ListBreakGlassActivations)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/break-glass/{activationId}/revoke", catalogHandler.RevokeBreakGlass)
		// Machine identities (ADR-023): non-human members, segmented from humans.
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities", catalogHandler.ListMachineIdentities)
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities/stale", catalogHandler.ListStaleMachineIdentities)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities", catalogHandler.CreateMachineIdentity)
		// User→machine migration creates a machine identity (roles.assign, project) AND
		// suspends the source user (users.write, global) — require both.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).
			With(customMiddleware.RequirePermission(permUsersWrite)).
			Post("/projects/{id}/machine-identities/migrate-from-user", catalogHandler.MigrateUserToMachine)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Put("/projects/{id}/machine-identities/{machineId}", catalogHandler.TransitionMachineIdentity)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Patch("/projects/{id}/machine-identities/{machineId}/classification", catalogHandler.ClassifyMachineIdentity)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Patch("/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification", catalogHandler.ClassifyMachineToken)
		// Machine-token credentials + role grants (ADR-030). Issuing a token is blocked
		// while impersonating — like PAT creation — so an admin acting as another user
		// cannot plant a durable (potentially non-expiring) credential that outlives the
		// bounded, audited impersonation session.
		r.With(customMiddleware.BlockWhenImpersonating, customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities/{machineId}/tokens", catalogHandler.IssueMachineToken)
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities/{machineId}/tokens", catalogHandler.ListMachineTokens)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}", catalogHandler.RevokeMachineToken)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities/{machineId}/roles", catalogHandler.GrantMachineRole)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/roles/{roleId}", catalogHandler.RemoveMachineRole)
		// OIDC / Kubernetes-JWT federation bindings (ADR-031).
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Post("/projects/{id}/machine-identities/{machineId}/oidc-bindings", catalogHandler.CreateOIDCBinding)
		r.With(customMiddleware.RequireScopedPermission(permUsersRead, projectScope)).Get("/projects/{id}/machine-identities/{machineId}/oidc-bindings", catalogHandler.ListOIDCBindings)
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}", catalogHandler.DeleteOIDCBinding)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Post("/projects/{id}/secrets/render", secretHandler.RenderTemplate)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/deleted", secretHandler.DeletedSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/orphaned", secretHandler.OrphanedSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/hygiene", secretHandler.ProjectHygiene)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/expiring", secretHandler.ExpiringSecrets)
		// Asset inventory (ISO 27001 A.5.9) — CSV metadata manifest of the project's
		// secrets (no values) for compliance hand-off.
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/inventory.csv", secretHandler.SecretsInventoryCSV)
		// Naming-policy conformance — live secrets whose names violate the current naming
		// policy (enforced only at create, so a tightened policy leaves stragglers).
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get("/projects/{id}/secrets/name-conformance", secretHandler.SecretNameConformance)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/suspend-all", secretHandler.SuspendProjectSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/resume-all", secretHandler.ResumeProjectSecrets)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/reassign-owner", secretHandler.ReassignOwner)
		// Bulk expiry renewal — push out the expiration of every expiring/expired secret.
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/extend-expiring", secretHandler.ExtendExpiringSecrets)
		// Bulk rename toward naming-policy conformance — remediation for name-conformance.
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/bulk-rename", secretHandler.BulkRenameSecrets)
		// Bulk rotation — trigger rotation for multiple secrets at once (incident response).
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/bulk-rotate", secretHandler.BulkRotateSecrets)
		// Bulk delete — remove multiple secrets in one call; same cleanup as single delete.
		r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, projectScope)).Post("/projects/{id}/secrets/bulk-delete", secretHandler.BulkDeleteSecrets)
		// Bulk copy also requires secrets.read on the SOURCE environment (resolved from
		// the envId path param, not attacker-supplied input) — mirroring the single-secret
		// copy route below, which gates secrets.read on the source in addition to
		// secrets.write on the target. Without this leg, a write-only-scoped principal
		// could use the bulk copy to duplicate secret VALUES out of an environment they
		// were deliberately denied read access to, defeating the write-only RBAC role
		// this product's custom-role system is designed to support.
		r.With(
			customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope),
			customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromEnvParam("envId")),
		).Post("/projects/{id}/environments/{envId}/copy-secrets", secretHandler.CopyEnvironmentSecrets)
		// Environment clone: copies all secrets from one environment to another within the same
		// project (staging → production promotion). Requires secrets.write on the project scope
		// (creates in destination) AND secrets.read on the source environment (reads values).
		r.With(
			customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope),
			customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromEnvParam("envId")),
		).Post("/projects/{id}/environments/{envId}/clone", catalogHandler.CloneEnvironment)
		r.With(customMiddleware.RequireScopedPermission(permSecretsRead, projectScope)).Get(pathProjectEnvs, catalogHandler.ListProjectEnvironments)
		r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post(pathProjectEnvs, catalogHandler.CreateProjectEnvironment)
		// Environment restore is nested under the project so the scope resolves
		// from the (live) project ID — the env row is soft-deleted and unloadable.
		// Restore reinstates the environment's role grants, so gate on roles.assign
		// (#161), not secrets.write — same shape as the project-restore fix above.
		r.With(customMiddleware.RequireScopedPermission(permRolesAssign, customMiddleware.ScopeFromProjectParam("projectId"))).Post("/projects/{projectId}/environments/{id}/restore", catalogHandler.RestoreEnvironment)
		r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, customMiddleware.ScopeFromEnvParam("id"))).Delete(pathEnvironmentsID, catalogHandler.DeleteEnvironment)
		r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/environments", catalogHandler.ListEnvironments)

		// Secrets endpoints. Per-secret routes resolve scope from the secret's
		// own project/environment. List authorizes against the project_id/
		// environment_id query filter (a scoped reader must narrow to a project
		// they can read; the same filter then bounds the returned rows). Create
		// authorizes in-handler against the project/environment in the body.
		secretScope := customMiddleware.ScopeFromSecretParam("id")
		r.Route("/secrets", func(r chi.Router) {
			// ListSecrets performs its own authorization inside the handler so that
			// project-scoped readers receive the union of their accessible scopes
			// rather than a 403 on an unfiltered request. See secrets_list.go.
			r.Get("/", secretHandler.ListSecrets)
			// Active create-time policies (naming/value) — any authenticated caller.
			r.Get("/policy", secretHandler.SecretPolicy)
			// Usage analytics (static paths, before /{id}).
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/usage/most-accessed", secretHandler.UsageMostAccessed)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/usage/unused", secretHandler.UsageUnused)
			// Org-wide secret asset inventory (ISO 27001 A.5.9) — CSV manifest of every
			// project's secrets, metadata only (no values), but it DOES disclose every
			// secret's real NAME/classification/owner deployment-wide, so it is gated on
			// audit.read (global), NOT the universal system_viewer baseline system.read —
			// same disclosure-family calibration as /compliance/evidence. Static path,
			// before /{id}.
			r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/inventory.csv", secretHandler.DeploymentSecretsInventoryCSV)
			// Org-wide naming-policy conformance — every project's secrets whose names
			// violate the current (global) policy; discloses the violating secrets' real
			// names deployment-wide, so audit.read (global), not the baseline. Static
			// path, before /{id}.
			r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/name-conformance", secretHandler.DeploymentSecretNameConformance)
			// By-reference value read (ESO etc.): resolve project/environment/name → the
			// secret's value. Scoped to the resolved secret; static path, before /{id}.
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromRefQuery)).Get("/value", secretHandler.GetSecretValueByRef)
			// By-name metadata lookup, scoped by project_id/environment_id query params
			// (same gate/convention as ListSecrets above) — the server-side counterpart
			// RemoteStorage.GetSecretByName (#497) needs; a caller with only a secret's
			// name (not its numeric ID) resolves it here. Static path, before /{id}.
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/by-name", secretHandler.GetSecretByName)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}", secretHandler.GetSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/versions", secretHandler.GetSecretVersions)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/versions/{from}/diff/{to}", secretHandler.DiffSecretVersions)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/risk", secretHandler.GetSecretRisk)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/shares", shareHandler.ListSecretShares)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/access", secretHandler.ListAccessors)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/access-log", secretHandler.AccessHistory)
			// Per-secret read statistics — lifetime total + recent-window summary.
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/stats", secretHandler.GetSecretAccessStats)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/audit", secretHandler.AuditTrail)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/tags", secretHandler.GetTags)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Put("/{id}/tags", secretHandler.SetTags)

			// Secret dependency graph (ADR-052).
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/dependencies", secretHandler.ListSecretDependencies)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/dependencies", secretHandler.AddSecretDependency)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Delete("/{id}/dependencies/{depId}", secretHandler.RemoveSecretDependency)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/impact", secretHandler.GetSecretImpact)

			// Per-secret ACLs (RBAC Phase 3): fine-grained user grants independent of project RBAC.
			r.With(customMiddleware.RequireScopedPermission(permSecretsManage, secretScope)).Get("/{id}/acl", secretHandler.ListSecretACLs)
			r.With(customMiddleware.RequireScopedPermission(permSecretsManage, secretScope)).Post("/{id}/acl", secretHandler.GrantSecretACL)
			r.With(customMiddleware.RequireScopedPermission(permSecretsManage, secretScope)).Delete("/{id}/acl/{aclId}", secretHandler.RevokeSecretACL)

			// Temporal access schedule: restrict a secret's reads to a time window.
			r.With(customMiddleware.RequireScopedPermission(permSecretsManage, secretScope)).Get("/{id}/schedule", secretHandler.GetSecretSchedule)
			r.With(customMiddleware.RequireScopedPermission(permSecretsManage, secretScope)).Put("/{id}/schedule", secretHandler.SetSecretSchedule)
			r.With(customMiddleware.RequireScopedPermission(permSecretsManage, secretScope)).Delete("/{id}/schedule", secretHandler.DeleteSecretSchedule)

			// Certificate inspection (ADR-054) — public X.509 metadata, no value/key.
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Get("/{id}/certificate", secretHandler.GetSecretCertificate)

			// Create: authorized inside the handler (scope comes from the body).
			r.Post("/", secretHandler.CreateSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Put("/{id}", secretHandler.UpdateSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Patch("/{id}/classification", secretHandler.ClassifySecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Patch("/{id}/description", secretHandler.DescribeSecret)
			// Copy into another environment: read the source ({id}); the handler also
			// authorizes secrets.write at the target environment's scope.
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, secretScope)).Post("/{id}/copy", secretHandler.CopySecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Patch("/{id}/auto-rotate", secretHandler.SetAutoRotate)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/rotate", secretHandler.RotateSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/rollback", secretHandler.RollbackSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/transfer-ownership", secretHandler.TransferOwnership)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/move", secretHandler.MoveSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/suspend", secretHandler.SuspendSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/resume", secretHandler.ResumeSecret)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, secretScope)).Post("/{id}/share", shareHandler.ShareSecret)
			// Self-service: a recipient removes their OWN direct share. No scoped
			// permission — the action is on the caller's own grant (core only removes a
			// share whose RecipientID == the caller), so it needs just authentication.
			r.Delete("/{id}/self-share", shareHandler.RemoveSelfFromShare)

			r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, secretScope)).Delete("/{id}", secretHandler.DeleteSecret)
			// Restore resolves scope from the (soft-deleted) secret via the unscoped resolver.
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, customMiddleware.ScopeFromDeletedSecretParam("id"))).Post(pathIDRestore, secretHandler.RestoreSecret)
		})

		// Shares endpoints. The user's own share list stays a global-read op;
		// mutating a specific share is scoped to the shared secret.
		shareScope := customMiddleware.ScopeFromShareParam("id")
		r.Route("/shares", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/", shareHandler.ListShares)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, shareScope)).Put("/{id}", shareHandler.UpdateSharePermission)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, shareScope)).Delete("/{id}", shareHandler.RevokeShare)
		})

		// Shared secrets endpoint (the caller's own shares)
		r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/shared-secrets", shareHandler.ListSharedSecrets)

		// Folder endpoints. Create authorizes in-handler (scope from the body).
		// List scopes via the project_id query param. Delete resolves scope from
		// the folder node's own project/environment.
		folderScope := customMiddleware.ScopeFromSecretParam("id")
		r.Route("/folders", func(r chi.Router) {
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/", folderHandler.ListFolders)
			r.Post("/", folderHandler.CreateFolder)
			r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, folderScope)).Delete("/{id}", folderHandler.DeleteFolder)
		})

		// Rotation policies endpoints. List/evaluate take an optional scope
		// filter; per-policy routes resolve scope from the policy; create
		// authorizes in-handler against the body.
		policyScope := customMiddleware.ScopeFromRotationPolicyParam("id")
		r.Route("/rotation-policies", func(r chi.Router) {
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/", rotationPolicyHandler.List)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get("/evaluate", rotationPolicyHandler.Evaluate)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, customMiddleware.ScopeFromQuery)).Get(pathStatus, rotationPolicyHandler.Status)
			r.With(customMiddleware.RequireScopedPermission(permSecretsRead, policyScope)).Get("/{id}", rotationPolicyHandler.Get)
			r.Post("/", rotationPolicyHandler.Create)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, policyScope)).Put("/{id}", rotationPolicyHandler.Update)
			r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, policyScope)).Delete("/{id}", rotationPolicyHandler.Delete)
		})

		// Dynamic secrets (ADR-035). Authorization is in-handler against each
		// config/lease's project/environment scope (reusing secrets.read/write),
		// so these routes carry no scoped-permission middleware.
		r.Route("/dynamic-secrets", func(r chi.Router) {
			r.Post("/configs", dynamicSecretHandler.CreateConfig)
			r.Get("/configs", dynamicSecretHandler.ListConfigs)
			r.Get("/configs/{id}", dynamicSecretHandler.GetConfig)
			r.Patch("/configs/{id}/classification", dynamicSecretHandler.ClassifyConfig)
			r.Patch("/configs/{id}/enabled", dynamicSecretHandler.SetConfigEnabled)
			r.Post("/configs/{id}/issue", dynamicSecretHandler.IssueLease)
			r.Get("/configs/{id}/leases", dynamicSecretHandler.ListLeases)
			r.Post("/configs/{id}/revoke-all", dynamicSecretHandler.RevokeAllLeases)
			r.Post("/leases/{leaseID}/renew", dynamicSecretHandler.RenewLease)
			r.Post("/leases/{leaseID}/revoke", dynamicSecretHandler.RevokeLease)
		})

		// Users endpoints (RBAC)
		r.Route("/users", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permUsersRead))
			r.Get("/", handlers.ListUsers)
			// CreateUser mutates (and can grant roles via ADR-028 atomic provisioning),
			// so it needs users.write — not just the group-level users.read. Without
			// this gate a global read-only persona (system_auditor holds users.read)
			// could POST a user with role:"system_admin" and escalate to global admin.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/", handlers.CreateUser)
			r.Get("/search", handlers.SearchUsers)
			// Stale-account warnings (ADR-025): static path before /{id}.
			r.Get("/stale", handlers.StaleAccounts)
			// By-email lookup, scoped by the group-wide users.read gate above — the
			// server-side counterpart RemoteStorage.GetUserByEmail (#503) needs, for a
			// caller with only a user's email (not their numeric ID). Deliberately the
			// SAME gate as GetUser-by-id (not a stricter one): users.read already lets a
			// caller enumerate every user (including email) via GET /users with no
			// filter, so this route grants no new capability at that permission level.
			// Static path, before /{id}.
			r.Get("/by-email", handlers.GetUserByEmail)
			// By-username and by-external-id lookups (#505), the server-side
			// counterparts RemoteStorage.GetUserByUsername/GetUserByExternalID need —
			// SAME gate (users.read) and NotFound shape as by-email above, for the
			// identical reason: a caller with users.read can already enumerate every
			// user's username/external_id via GET /users, so these routes grant no
			// new capability at that permission level. Static paths, before /{id}.
			r.Get("/by-username", handlers.GetUserByUsername)
			r.Get("/by-external-id", handlers.GetUserByExternalID)
			// VerifyCredentials (#506) — the upstream half of the storage.type: remote
			// proxy-login mechanism (internal/core/auth.go's RemoteLoginVerifier):
			// checks a plaintext username/password against the real bcrypt hash this
			// server holds and returns only a verdict, never the hash, so a
			// RemoteStorage-backed "spoke" deployment (which never receives the hash
			// at all) can authenticate a password login by proxying the ENTIRE check
			// here rather than reimplementing it. Gated by users.write, the same
			// permission the RemoteStorage service credential already needs for
			// CreateUser/UnlockUser — see the handler's doc for why this is
			// deliberately not a new, separately-provisioned permission. Static path,
			// before /{id}.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/verify-credentials", handlers.VerifyCredentials)
			// VerifyMFACredentials (#509) — the upstream half of the storage.type:
			// remote second-factor login proxy (internal/core/mfa.go's
			// RemoteMFAVerifier): checks a plaintext TOTP/recovery code against the
			// real, decrypted TOTP secret this server holds and returns only a
			// verdict, never the secret. Same gate and reasoning as
			// verify-credentials above. Static path, before /{id}.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/verify-mfa", handlers.VerifyMFACredentials)
			r.Get("/{id}", handlers.GetUser)
			// Mutations need users.write, not the group-wide users.read (which the
			// read-only system_auditor persona holds) — these were the missed
			// siblings of the suspend/reactivate transitions gated below.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Put("/{id}", handlers.UpdateUser)
			// users.delete, not users.write — matches the gRPC UserService.DeleteUser
			// gate (#141). A custom role granted users.write alone (update, not delete)
			// could otherwise delete users via HTTP while gRPC correctly refused it.
			r.With(customMiddleware.RequirePermission("users.delete")).Delete("/{id}", handlers.DeleteUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post(pathIDRestore, handlers.RestoreUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/unlock", handlers.UnlockUser)
			// IssueMFAChallenge (#509) — the upstream half of the storage.type: remote
			// second-factor login proxy (internal/core/mfa.go's RemoteMFAVerifier):
			// mints and persists the short-lived, single-use MFA challenge on this
			// (the hub's) LocalStorage on behalf of a RemoteStorage-backed "spoke"
			// deployment, which has nowhere of its own to persist one. Same gate and
			// reasoning as verify-credentials/verify-mfa above.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/mfa-challenge", handlers.IssueMFAChallenge)
			// GetActiveMFAChallenge/ConsumeMFAChallenge (#522) — the upstream half of
			// the storage.type: remote WebAuthn-as-second-factor login proxy
			// (internal/core/webauthn.go's BeginWebAuthnLogin/FinishWebAuthnLogin):
			// unlike the TOTP path above, these are plain storage.Storage passthroughs
			// on the SAME shared MFAChallenge model, not a verification proxy — a
			// passkey assertion carries no server-held secret the way a TOTP shared
			// secret does, so the ceremony itself still runs entirely in the calling
			// (spoke) server's own core.KeyorixCore, exactly as it does locally. Same
			// gate and reasoning as verify-mfa/mfa-challenge above. Static paths,
			// before /{id}.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-challenge/active", handlers.GetActiveMFAChallenge)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-challenge/consume", handlers.ConsumeMFAChallenge)
			// Admin force-logout: revoke all of a user's sessions (no state change).
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/revoke-sessions", handlers.RevokeSessions)
			// Account state transitions (ADR-025).
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/suspend", handlers.SuspendUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/reactivate", handlers.ReactivateUser)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/require-password-reset", handlers.RequirePasswordReset)
			// Credential-delivery resend (ADR-028): reissue + redeliver a setup link.
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/{id}/resend-setup-link", handlers.ResendSetupLink)
			// roles.read, not the group-wide users.read (#141) — matches the gRPC
			// RoleService.GetUserRoles gate for the same data. users.read is held by
			// nearly every seeded role (project_viewer, editor, …), so gating a user's
			// full role-assignment list on it let any low-privilege project member
			// enumerate an arbitrary OTHER user's roles — reconnaissance for targeted
			// privilege-escalation attempts. roles.read is held by system_admin/
			// system_auditor/project_admin, the personas that actually manage access.
			r.With(customMiddleware.RequirePermission(permRolesRead)).Get(pathIDRoles, usersRolesHandler.GetUserRolesForUser)
			// Effective permission set (union across the user's roles) — a read, gated
			// by the group-wide users.read like the roles view used to be. Not part of
			// #141's scope; left as-is.
			r.Get(pathIDPermissions, usersRolesHandler.GetUserPermissionsForUser)
			// Replacing a user's roles is a privilege grant — gate on roles.assign,
			// not the group-wide users.read (which many non-admin roles hold).
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Put(pathIDRoles, usersRolesHandler.UpdateUserRoles)
			// Per-user project assignments for the detail page (ADR-025).
			r.Get("/{id}/memberships", usersRolesHandler.GetUserMembershipsForUser)
		})

		// Admin impersonation — gated by users.impersonate, which only global
		// admins hold (admin-bypass). Issues a session for the target user.
		r.With(customMiddleware.RequirePermission("users.impersonate")).
			Post("/admin/impersonate", impersonationHandler.Start)

		// Sessions (#508) — the server-side counterparts RemoteStorage.GetSession/
		// DeleteSession need so a storage.type: remote deployment can validate and
		// revoke sessions minted upstream by POST /api/v1/users/verify-credentials
		// (#506/#508's atomic verify+mint). Deliberately NO POST "/" here — there is
		// no generic "create a session" route; see remote_auth.go's CreateSession
		// doc for why that would be a privilege-escalation oracle. Gated by
		// users.write, the SAME permission verify-credentials/CreateUser/UnlockUser
		// already require of the RemoteStorage service credential.
		r.Route("/sessions", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Get("/{token}", handlers.GetSessionByToken)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Delete("/{id}", handlers.DeleteSessionByID)
		})

		// Groups endpoints
		r.Route(pathGroups, func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permUsersRead))
			r.Get("/", groupHandler.ListGroups)
			// Group CRUD mutates identity/membership state — gate on users.write,
			// not the group-wide users.read (held by the read-only system_auditor).
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/", groupHandler.CreateGroup)
			r.Get("/{id}", groupHandler.GetGroup)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Put("/{id}", groupHandler.UpdateGroup)
			r.With(customMiddleware.RequirePermission(permUsersWrite)).Delete("/{id}", groupHandler.DeleteGroup)
			// Restore reinstates every role grant the group carried at deletion — the
			// same blast radius as a role grant — so gate on roles.assign (#147), not
			// users.write, mirroring the direct role-grant path below.
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Post(pathIDRestore, groupHandler.RestoreGroup)
			r.Get("/{id}/members", groupHandler.GetGroupMembers)
			// Secrets a group can reach via shares — reveals secret names, so it needs
			// secrets.read on top of the group-level users.read above.
			r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/{id}/shared-secrets", shareHandler.ListGroupSharedSecrets)
			// Adding/removing a group member confers (or revokes) every role the group
			// holds — the same blast radius as a role grant, so gate on roles.assign
			// (matching the group's role-grant routes below), not users.read.
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Post("/{id}/members", groupHandler.AddGroupMember)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Delete("/{id}/members/{userId}", groupHandler.RemoveGroupMember)
			// Viewing a group's role grants discloses the same privilege-escalation
			// topology as a single user's role list, so gate on roles.read (#262) —
			// not the group-wide users.read (held by nearly every seeded role,
			// including the baseline viewer). This matches GetUserRolesForUser above
			// (#141) and the roles.read gate the /roles route group itself uses for
			// GetRolePermissions; the mutating siblings (AssignRoleToGroup,
			// RemoveRoleFromGroup) already require the more privileged roles.assign.
			r.With(customMiddleware.RequirePermission(permRolesRead)).Get(pathIDRoles, rbacHandler.GetGroupRoles)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Post(pathIDRoles, rbacHandler.AssignRoleToGroup)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Delete("/{id}/roles/{roleId}", rbacHandler.RemoveRoleFromGroup)
		})

		// Roles endpoints (RBAC)
		r.Route("/roles", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permRolesRead))
			r.Get("/", rbacHandler.ListRoles)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Post("/", rbacHandler.CreateRole)
			// By-name lookup, scoped by the group-wide roles.read gate above — the
			// server-side counterpart RemoteStorage.GetRoleByName (#512) needs, for a
			// caller (e.g. InviteToProject resolving an invited role by name) with
			// only a role's name, not its numeric ID. Deliberately the SAME gate as
			// GetRole-by-id (not a stricter one): roles.read already lets a caller
			// enumerate every role (including name) via GET /roles with no filter,
			// so this route grants no new capability at that permission level.
			// Static path, before /{id} — mirrors GetUserByEmail (#503) /
			// GetSecretByName (#497)'s query-param "by-X" convention.
			r.Get("/by-name", rbacHandler.GetRoleByName)
			r.Get("/{id}", rbacHandler.GetRole)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Put("/{id}", rbacHandler.UpdateRole)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Delete("/{id}", rbacHandler.DeleteRole)
			r.Get(pathIDPermissions, rbacHandler.GetRolePermissions)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Post(pathIDPermissions, rbacHandler.AssignPermissionToRole)
			r.With(customMiddleware.RequirePermission(permRolesWrite)).Delete("/{id}/permissions/{permissionId}", rbacHandler.RemovePermissionFromRole)
		})

		// Permissions endpoints
		r.Route("/permissions", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permRolesRead))
			r.Get("/", rbacHandler.ListPermissions)
			// #526: RemoteStorage's storage.type: remote proxy for
			// AssignPermissionToRole's permissionID -> name lookup had no route
			// to call (ListPermissions and GetRolePermissions already had
			// routes to reuse; this was the one gap). Same roles.read gate as
			// the collection route above — no new capability, a caller who can
			// already list every permission can already see this one.
			r.Get("/{id}", rbacHandler.GetPermission)
		})

		// NOTE: the legacy admin-managed "service accounts" (APIClient/APIToken)
		// issuance/management routes were removed here (finding #131): the tokens
		// they minted were never accepted by any authentication path (validateToken
		// in server/middleware/auth.go has no branch for them), making them a dead,
		// unscannable credential type. Machine identities (ADR-030, kx_machine_
		// tokens) are the actual wired, RBAC-integrated non-human-identity
		// credential and are the intended replacement — see docs/adr-030 and
		// docs/adr-027 (which documents this exact gap). The models/DB tables and
		// KEK-rotation sweep code for APIClient/APIToken are left in place for any
		// legacy rows in already-deployed databases.

		// User roles endpoints
		r.Route("/user-roles", func(r chi.Router) {
			// Assign/remove are gated on roles.assign AT THE REQUEST BODY'S TARGET
			// scope (project_id/environment_id, 0 = global) — mirroring
			// RoleGRPCService.AssignRole/RemoveRole, which authorize at the target
			// scope rather than a flat global permission. Before this (#342), these
			// routes used the group-level RequirePermission(permRolesAssign), which
			// always checked the GLOBAL scope regardless of the body's actual
			// target, a parity gap with the gRPC path.
			r.With(customMiddleware.RequireScopedPermission(permRolesAssign, customMiddleware.ScopeFromRoleAssignmentBody)).Post("/", rbacHandler.AssignRole)
			r.With(customMiddleware.RequireScopedPermission(permRolesAssign, customMiddleware.ScopeFromRoleAssignmentBody)).Delete("/", rbacHandler.RemoveRole)
			r.With(customMiddleware.RequirePermission(permRolesAssign)).Get("/user/{userId}", rbacHandler.GetUserRoles)
		})

		// Audit logs endpoints
		r.Route("/audit", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permAuditRead))
			r.Get("/logs", auditHandler.GetAuditLogs)
			r.Get("/export", auditHandler.ExportAuditLogs)
			r.Get("/export.csv", auditHandler.ExportAuditLogsCSV)
			r.Get("/rbac-logs", auditHandler.GetRBACAuditLogs)
			r.Get("/retention", auditHandler.GetAuditRetention)
			r.Get("/verify", auditHandler.VerifyAuditChain)
			// Writing a checkpoint is a privileged integrity-control action — gate it
			// above the group's audit.read with system.write (admin-level).
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/checkpoint", auditHandler.WriteAuditCheckpoint)
			r.Get("/anomalies", handlers.ListAnomalyAlerts)
			// Acknowledging (dismissing) an alert mutates a security-detection record, so
			// gate it above the group's audit.read with system.write — like /checkpoint —
			// rather than letting any read-only auditor silently bury alerts.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/anomalies/{id}/acknowledge", handlers.AcknowledgeAnomalyAlert)
		})

		// System endpoints
		r.Route("/system", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permSystemRead))
			r.Get("/info", handlers.MakeSystemInfoHandler(cfg))
			r.Get(pathMetrics, handlers.GetMetrics)
			// Per-scheduler last-run/last-success timestamps (Prometheus exposition
			// format), deliberately kept off the public, unauthenticated /metrics
			// endpoint — see server/middleware/scheduler_metrics.go — since an exact
			// tick timestamp would let an anonymous caller predict a security-relevant
			// job's next execution to sub-second precision. Gated behind system.read
			// like the rest of this group.
			r.Get("/scheduler-metrics", customMiddleware.SchedulerMetricsHandler().ServeHTTP)

			// Login/password-reset rate-limit counter proxy (#452 follow-up). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049) — a
			// real, shipped deployment mode — persist and query its OWN per-IP
			// rate-limit counters against THIS server's real storage backend, instead
			// of RemoteStorage.CountRecentLoginAttempts/RecordLoginAttempt/
			// PruneLoginAttempts having no server endpoint to call at all (the gap
			// #452/#675 documented but left open: a real proxied endpoint, not just a
			// louder warning). This reuses the exact same login_attempts table and
			// storage.Storage primitives the local /auth/login path already uses
			// (ADR-040) via a thin passthrough — no new policy decision is made here,
			// the caller's own core.KeyorixCore still decides the threshold/window.
			// Read is baseline system.read; the two mutating operations require
			// system.write, matching every other admin-level mutation in this group.
			r.Get("/login-attempts/count", authHandler.CountLoginAttemptsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/login-attempts", authHandler.RecordLoginAttemptProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/login-attempts/prune", authHandler.PruneLoginAttemptsProxy)

			// Project-invitation storage-primitive proxy (#507). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// CreateProjectInvitation/GetProjectInvitation/UpdateProjectInvitation/
			// ListProjectInvitations to THIS server's real storage backend, instead of
			// RemoteStorage's four ProjectInvitation methods having no server endpoint
			// to call at all (setup_consume.go's completeInvitationAccept — and every
			// other invitation flow — was completely non-functional under
			// storage.type: remote). Exactly the same pattern as the login-attempts
			// proxy above: a thin passthrough onto storage.Storage (no invitation
			// POLICY decision made here — the calling server's own core.KeyorixCore
			// still decides that, exactly as it does against a local backend), reusing
			// the SAME system.read/system.write tier rather than the project-scoped
			// roles.assign the human-facing /projects/{id}/invitations routes use,
			// since a RemoteStorage credential already needs system.write for the
			// login-attempts proxy — no new privilege class. Read is baseline
			// system.read; create/update require system.write, matching every other
			// admin-level mutation in this group.
			r.Get("/invitations/{id}", catalogHandler.GetInvitationProxy)
			r.Get(pathInvitations, catalogHandler.ListInvitationsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathInvitations, catalogHandler.CreateInvitationProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/invitations/{id}", catalogHandler.UpdateInvitationProxy)

			// Self-service access-request storage-primitive proxy (#523). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049)
			// proxy CreateAccessRequest/GetAccessRequest/UpdateAccessRequest/
			// ListAccessRequests/CreateAccessRequestApproval/
			// ListAccessRequestApprovals to THIS server's real storage backend,
			// instead of RemoteStorage's six AccessRequest methods having no server
			// endpoint to call at all (the ENTIRE self-service access-request
			// workflow — request/list/approve/reject/withdraw, ADR-024 — was
			// completely non-functional under storage.type: remote). Exactly the
			// same pattern as the invitations proxy above: a thin passthrough onto
			// storage.Storage (no access-request POLICY decision — dual-control
			// threshold, maker-checker, TTL/expiry, the role grant itself, audit
			// writes, notifications — is made here; that stays entirely in the
			// CALLING server's own internal/core.KeyorixCore, exactly as it does
			// against a local backend). Deliberately does NOT reuse the human-facing
			// /projects/{id}/access-requests* routes as the proxy target — those
			// call straight into core.KeyorixCore business logic (audit writes,
			// notifications, actor resolved from THIS server's own request context)
			// which would double-apply and misattribute to the hub's own service
			// credential rather than the real requester/approver; see
			// access_request_proxy.go's package doc. Reuses the SAME
			// system.read/system.write tier as every other proxy in this group — no
			// new privilege class. UpdateAccessRequestProxy inherits
			// local_invitations.go's conditional `WHERE id = ? AND state =
			// 'pending'` write verbatim, and CreateAccessRequestApprovalProxy
			// inherits the DB-level unique-index-backed ON CONFLICT DO NOTHING
			// insert — see remote_invitations.go's package doc for the full
			// atomicity analysis (every method already resolves in one
			// storage.Storage call server-side, so proxying it as one HTTP round
			// trip preserves the #277 approve/reject/withdraw race guarantee
			// unchanged). Read is baseline system.read; create/update require
			// system.write, matching every other admin-level mutation in this
			// group.
			r.Get("/access-requests/{id}", catalogHandler.GetAccessRequestProxy)
			r.Get("/access-requests", catalogHandler.ListAccessRequestsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/access-requests", catalogHandler.CreateAccessRequestProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/access-requests/{id}", catalogHandler.UpdateAccessRequestProxy)
			r.Get("/access-requests/{id}/approvals", catalogHandler.ListAccessRequestApprovalsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/access-requests/{id}/approvals", catalogHandler.CreateAccessRequestApprovalProxy)

			// Dynamic-secrets storage-primitive proxy (round-116 finding). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049)
			// proxy CreateDynamicSecretConfig/GetDynamicSecretConfig/
			// ListDynamicSecretConfigs/UpdateDynamicSecretConfig/
			// CountDynamicSecretConfigsByClassification/CreateDynamicSecretLease/
			// GetDynamicSecretLease/ListDynamicSecretLeases/CountActiveLeases/
			// UpdateDynamicSecretLease/ListExpiredActiveLeases to THIS server's real
			// storage backend, instead of RemoteStorage's eleven dynamic-secrets
			// methods having no server endpoint to call at all (dynamic secrets —
			// ADR-035 — were entirely non-functional under storage.type: remote).
			// Exactly the same pattern as the invitations/login-attempts proxies
			// above: a thin passthrough onto storage.Storage (no dynamic-secrets
			// POLICY decision — admin-authority checks, TTL/lease-count clamping, the
			// admin-DSN/credential encrypt-decrypt — is made here; that stays
			// entirely in the CALLING server's own core.KeyorixCore, exactly as it
			// does against a local backend), reusing the SAME system.read/
			// system.write tier — no new privilege class. See
			// dynamic_secrets_proxy.go's package doc for why the admin-DSN/
			// credential ciphertext crossing this boundary is safe (it is already
			// opaque ciphertext by the time it reaches here, encrypted with the
			// CALLING server's own key). Static sub-paths
			// (classification-counts, active-count, expired) are registered before
			// their sibling {id}/{leaseID} routes.
			r.Get("/dynamic-secrets/configs/classification-counts", dynamicSecretHandler.CountDynamicSecretConfigsByClassificationProxy)
			r.Get("/dynamic-secrets/configs/{id}", dynamicSecretHandler.GetDynamicSecretConfigProxy)
			r.Get("/dynamic-secrets/configs", dynamicSecretHandler.ListDynamicSecretConfigsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/dynamic-secrets/configs", dynamicSecretHandler.CreateDynamicSecretConfigProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/dynamic-secrets/configs/{id}", dynamicSecretHandler.UpdateDynamicSecretConfigProxy)
			r.Get("/dynamic-secrets/leases/active-count", dynamicSecretHandler.CountActiveLeasesProxy)
			r.Get("/dynamic-secrets/leases/expired", dynamicSecretHandler.ListExpiredActiveLeasesProxy)
			r.Get("/dynamic-secrets/leases/{leaseID}", dynamicSecretHandler.GetDynamicSecretLeaseProxy)
			r.Get("/dynamic-secrets/leases", dynamicSecretHandler.ListDynamicSecretLeasesProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/dynamic-secrets/leases", dynamicSecretHandler.CreateDynamicSecretLeaseProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/dynamic-secrets/leases/{leaseID}", dynamicSecretHandler.UpdateDynamicSecretLeaseProxy)

			// Group CRUD/membership storage-primitive proxy (finding filed round 116).
			// Lets a downstream Keyorix server booted with storage.type: remote
			// (ADR-049) proxy CreateGroup/GetGroup/UpdateGroup/DeleteGroup/
			// RestoreGroup/ListGroups/ListGroupsPage/AddUserToGroup/
			// RemoveUserFromGroup/ListGroupMembers/ListGroupMembersByGroupIDs/
			// GetUserGroups to THIS server's real storage backend, instead of
			// RemoteStorage's Group methods having no server endpoint to call at all
			// (every group-management CLI/API flow, and every group-inherited
			// permission/role check, was completely non-functional — or, for
			// GetUserGroups, silently returning "zero groups" rather than erroring —
			// under storage.type: remote). Exactly the same pattern as the
			// login-attempts and invitations proxies above: a thin passthrough onto
			// storage.Storage (no group POLICY decision — name/description
			// validation, audit-log events, the escalation-by-proxy admin ceilings —
			// is made here; that stays entirely in the CALLING server's own
			// internal/core.KeyorixCore, exactly as it does against a local backend),
			// reusing the SAME system.read/system.write tier rather than the
			// users.write/roles.assign the human-facing /groups routes use, since a
			// RemoteStorage credential already needs system.write for the two proxies
			// above — no new privilege class. Read is baseline system.read;
			// create/update/delete/restore/membership-mutation require system.write,
			// matching every other admin-level mutation in this group. The static
			// "/page" and "/members-by-ids" routes are registered ahead of "/{id}" so
			// chi's router (which prefers a static path segment over a wildcard at the
			// same position) never mistakes either literal segment for a group ID.
			r.Get("/groups/page", groupHandler.ListGroupsPageProxy)
			r.Get("/groups/members-by-ids", groupHandler.ListGroupMembersByIDsProxy)
			r.Get(pathGroups, groupHandler.ListGroupsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathGroups, groupHandler.CreateGroupProxy)
			r.Get(pathGroupsID, groupHandler.GetGroupProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put(pathGroupsID, groupHandler.UpdateGroupProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathGroupsID, groupHandler.DeleteGroupProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/groups/{id}/restore", groupHandler.RestoreGroupProxy)
			r.Get("/groups/{id}/members", groupHandler.ListGroupMembersProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/groups/{id}/members", groupHandler.AddGroupMemberProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/groups/{id}/members/{userId}", groupHandler.RemoveGroupMemberProxy)
			r.Get("/users/{id}/groups", groupHandler.GetUserGroupsProxy)

			// Machine-identity storage-primitive proxy (finding #518). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049)
			// proxy CreateMachineIdentity/GetMachineIdentity/
			// LockMachineIdentityForUpdate/UpdateMachineIdentity/ListMachineIdentities/
			// ListAllMachineIdentities/CountMachineIdentitiesByClassification/
			// CreateMachineIdentityCredential/GetMachineIdentityCredentialByHash/
			// GetMachineIdentityCredentialByID/ListMachineIdentityCredentials/
			// ListActiveMachineIdentityCredentials/UpdateMachineIdentityCredential/
			// CountMachineIdentityCredentialsByClassification/
			// RevokeMachineIdentityCredential/TouchMachineIdentityCredential/
			// AssignMachineRole/RemoveMachineRole/GetMachineRoleIDsAt/GetMachineRoles/
			// CreateOIDCBinding/GetMachineByOIDCSubject/ListOIDCBindings/
			// GetOIDCBindingByID/DeleteOIDCBinding to THIS server's real storage
			// backend, instead of every one of these methods unconditionally
			// returning ErrRemoteUnsupported (machine-identity provisioning,
			// machine-token issuance/validation, machine role grants, and
			// Kubernetes/OIDC workload federation were entirely non-functional under
			// storage.type: remote). Exactly the same pattern as the groups/
			// dynamic-secrets proxies above: a thin passthrough onto storage.Storage
			// (no machine-identity POLICY decision — state-machine transition
			// legality, role-grant authorization, token issuance/hashing, OIDC
			// federation policy — is made here; that stays entirely in the CALLING
			// server's own internal/core.KeyorixCore, exactly as it does against a
			// local backend), reusing the SAME system.read/system.write tier rather
			// than the project-scoped roles.assign the human-facing
			// /projects/{id}/machine-identities routes use — no new privilege class.
			// Read is baseline system.read; every mutating operation requires
			// system.write, matching every other admin-level mutation in this group.
			//
			// TransitionMachineIdentityState is a dedicated conditional-write route
			// (NOT a generic Update), preserving #388's "revoked is terminal"
			// row-lock guarantee across this HTTP hop — see
			// machine_identities_proxy.go's package doc for the full atomicity
			// investigation. CountStaleMachineIdentitiesByProject has no route here;
			// it remains an intentional RemoteStorage stub (the #393 grouped
			// hygiene-rollup query stays server-side, out of this finding's scope).
			//
			// Static sub-paths ("all", "classification-counts", "active", "by-hash/
			// {hash}", "by-subject", and "roles/ids") are registered ahead of their
			// sibling {id}/{roleId} routes, matching chi's static-before-dynamic
			// preference at the same path position (the same ordering the
			// dynamic-secrets/groups proxies above already rely on).
			r.Get("/machine-identities/classification-counts", catalogHandler.CountMachineIdentitiesByClassificationProxy)
			r.Get("/machine-identities/all", catalogHandler.ListAllMachineIdentitiesProxy)
			r.Get("/machine-identities", catalogHandler.ListMachineIdentitiesProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/machine-identities", catalogHandler.CreateMachineIdentityProxy)
			r.Get("/machine-identities/{id}", catalogHandler.GetMachineIdentityProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/machine-identities/{id}", catalogHandler.UpdateMachineIdentityProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/machine-identities/{id}/transition", catalogHandler.TransitionMachineIdentityStateProxy)
			r.Get("/machine-identities/{id}/credentials", catalogHandler.ListMachineIdentityCredentialsProxy)
			r.Get("/machine-identities/{id}/roles/ids", catalogHandler.GetMachineRoleIDsAtProxy)
			r.Get("/machine-identities/{id}/roles", catalogHandler.GetMachineRolesProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/machine-identities/{id}/roles/{roleId}", catalogHandler.AssignMachineRoleProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/machine-identities/{id}/roles/{roleId}", catalogHandler.RemoveMachineRoleProxy)
			r.Get("/machine-identities/{id}/oidc-bindings", catalogHandler.ListOIDCBindingsProxy)

			r.Get("/machine-credentials/classification-counts", catalogHandler.CountMachineIdentityCredentialsByClassificationProxy)
			r.Get("/machine-credentials/active", catalogHandler.ListActiveMachineIdentityCredentialsProxy)
			r.Get("/machine-credentials/by-hash/{hash}", catalogHandler.GetMachineIdentityCredentialByHashProxy)
			r.Get("/machine-credentials/{id}", catalogHandler.GetMachineIdentityCredentialByIDProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/machine-credentials", catalogHandler.CreateMachineIdentityCredentialProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/machine-credentials/{id}", catalogHandler.UpdateMachineIdentityCredentialProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/machine-credentials/{id}/revoke", catalogHandler.RevokeMachineIdentityCredentialProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/machine-credentials/{id}/touch", catalogHandler.TouchMachineIdentityCredentialProxy)

			r.Get("/machine-oidc-bindings/by-subject", catalogHandler.GetMachineByOIDCSubjectProxy)
			r.Get("/machine-oidc-bindings/{id}", catalogHandler.GetOIDCBindingByIDProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/machine-oidc-bindings", catalogHandler.CreateOIDCBindingProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/machine-oidc-bindings/{id}", catalogHandler.DeleteOIDCBindingProxy)

			// Setup-token storage-primitive proxy (#510). Lets a downstream Keyorix
			// server booted with storage.type: remote (ADR-049) proxy
			// CreateSetupToken/GetSetupTokenByHash/SupersedeActiveSetupTokens/
			// MarkSetupTokenConsumed/MarkSetupTokenExpired/CountSetupTokensSince to
			// THIS server's real storage backend, instead of RemoteStorage's six
			// SetupToken methods having no server endpoint to call at all
			// (setup_consume.go's CompleteSetup — every setup-token purpose:
			// account_setup, password_reset_link, invitation_accept — was completely
			// non-functional under storage.type: remote). Exactly the same pattern as
			// the invitations proxy above: a thin passthrough onto storage.Storage (no
			// setup-token POLICY decision made here — the calling server's own
			// core.KeyorixCore still decides that), reusing the SAME
			// system.read/system.write tier — no new privilege class. Read is baseline
			// system.read; every mutating operation (including the single-use
			// consume) requires system.write, matching every other admin-level
			// mutation in this group.
			r.Get("/setup-tokens/by-hash/{hash}", authHandler.GetSetupTokenByHashProxy)
			r.Get("/setup-tokens/count", authHandler.CountSetupTokensSinceProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/setup-tokens", authHandler.CreateSetupTokenProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/setup-tokens/supersede", authHandler.SupersedeSetupTokensProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/setup-tokens/{id}/consume", authHandler.ConsumeSetupTokenProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/setup-tokens/{id}/expire", authHandler.ExpireSetupTokenProxy)

			// Keyorix Connect per-reference-grant storage-primitive proxy (ADR-045;
			// backlog #527). Lets a downstream Keyorix server booted with
			// storage.type: remote (ADR-049) proxy ListConnectRefGrantsByConnector/
			// ListConnectRefGrants/CreateConnectRefGrant/DeleteConnectRefGrant to THIS
			// server's real storage backend, instead of RemoteStorage's four
			// ConnectRefGrant methods having no server endpoint to call at all
			// (connectRefAllowed, called unconditionally by every ReadFederatedSecret,
			// was hard-failing EVERY Keyorix Connect federated read on EVERY connector
			// whenever Connect was configured on a storage.type: remote node — not a
			// hub-only feature at all). Exactly the same pattern as the setup-tokens
			// proxy above: a thin passthrough onto storage.Storage (no Connect POLICY
			// decision — role resolution, prefix/glob matching, expiry — made here;
			// that stays entirely in the CALLING server's own core.KeyorixCore, exactly
			// as it does against a local backend), reusing the SAME
			// system.read/system.write tier — no new privilege class. Read is baseline
			// system.read; create/delete require system.write, matching every other
			// admin-level mutation in this group.
			r.Get("/connect-grants/by-connector/{connector}", authHandler.ListConnectRefGrantsByConnectorProxy)
			r.Get("/connect-grants", authHandler.ListConnectRefGrantsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/connect-grants", authHandler.CreateConnectRefGrantProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/connect-grants/{id}", authHandler.DeleteConnectRefGrantProxy)

			// SSO login-state storage-primitive proxy (#521). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// CreateSSOLoginState/ConsumeSSOLoginState to THIS server's real storage
			// backend, instead of RemoteStorage's two SSOLoginState methods having no
			// server endpoint to call at all (BeginSSO/BeginSAML's very first step —
			// persisting the CSRF-state/nonce row — was completely non-functional
			// under storage.type: remote, breaking human SSO/SAML login end to end).
			// Exactly the same pattern as the setup-token proxy above: a thin
			// passthrough onto storage.Storage (no SSO policy decision made here —
			// the calling server's own core.KeyorixCore still decides that), reusing
			// the SAME system.read/system.write tier — no new privilege class. Both
			// create and the single-use consume are mutations and require
			// system.write.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/sso-state", authHandler.CreateSSOLoginStateProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/sso-state/consume", authHandler.ConsumeSSOLoginStateProxy)

			// Project-membership storage-primitive proxy (#511). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// CreateProjectMembership/GetProjectMembership/UpdateProjectMembership/
			// ListProjectMemberships/GetActiveProjectMembership/
			// ListStaleInvitedMemberships/ListUserProjectMemberships/
			// CountProjectMembershipsByUsers to THIS server's real storage backend,
			// instead of RemoteStorage's eight ProjectMembership methods having no
			// server endpoint to call at all (applyInvitationGrants' own
			// membership-materialization step — the last stage of accepting a project
			// invitation — was completely non-functional under storage.type: remote,
			// even after #507 made the invitation-accept step itself work). Same
			// pattern as the invitations proxy above: a thin passthrough onto
			// storage.Storage (no membership-lifecycle POLICY decision made here — the
			// calling server's own core.KeyorixCore still decides which state a new
			// invite starts in, which transitions are legal, and when the backing role
			// grant is applied/reverted, exactly as it does against a local backend),
			// reusing the SAME system.read/system.write tier — no new privilege class.
			// Static literal segments ("active", "stale", "counts", "by-user/{userID}")
			// take priority over the "{id}" wildcard at the same route depth (chi's
			// router always matches a static child before a param child), so they
			// coexist safely regardless of registration order.
			r.Get("/project-memberships/active", catalogHandler.GetActiveMembershipProxy)
			r.Get("/project-memberships/stale", catalogHandler.ListStaleInvitedMembershipsProxy)
			r.Get("/project-memberships/counts", catalogHandler.CountMembershipsByUsersProxy)
			r.Get("/project-memberships/by-user/{userID}", catalogHandler.ListUserMembershipsProxy)
			r.Get("/project-memberships/{id}", catalogHandler.GetMembershipProxy)
			r.Get("/project-memberships", catalogHandler.ListMembershipsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/project-memberships", catalogHandler.CreateMembershipProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/project-memberships/{id}", catalogHandler.UpdateMembershipProxy)

			// Secret-dependency storage-primitive proxy (finding #519). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049)
			// proxy CreateSecretDependency/GetSecretDependency/
			// ListSecretDependenciesForProject/
			// ListSecretDependenciesForProjectForUpdate/DeleteSecretDependency/
			// CreateSecretDependencyExclusive to THIS server's real storage backend,
			// instead of RemoteStorage's six secret-dependency methods having no
			// server endpoint to call at all (ADR-052's dependency graph — used per
			// ADR-053 for rotation-wave ordering and cascading soft-delete/restore/
			// purge through the graph — was completely non-functional under
			// storage.type: remote). Same pattern as the invitations/memberships
			// proxies above: a thin passthrough onto storage.Storage (no
			// dependency-graph POLICY decision — same-project/same-environment
			// scoping, audit logging — is made here; that stays entirely in the
			// CALLING server's own internal/core.KeyorixCore, exactly as it does
			// against a local backend), reusing the SAME system.read/system.write
			// tier — no new privilege class. The ONE exception is
			// CreateSecretDependencyExclusiveProxy: it DOES evaluate the
			// duplicate/cycle invariant server-side, because no real transaction can
			// span this HTTP hop (RemoteStorage.WithTransaction is a no-op
			// passthrough) — see secret_dependencies_proxy.go's package doc and the
			// storage.Storage interface doc for why AddSecretDependency now calls
			// this instead of orchestrating a list-under-lock-then-create sequence
			// itself. Static sub-paths ("for-update", "exclusive") are registered
			// before the "{id}" wildcard.
			r.Get("/secret-dependencies/for-update", secretHandler.ListSecretDependenciesForProjectForUpdateProxy)
			r.Get("/secret-dependencies/{id}", secretHandler.GetSecretDependencyProxy)
			r.Get("/secret-dependencies", secretHandler.ListSecretDependenciesForProjectProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/secret-dependencies", secretHandler.CreateSecretDependencyProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/secret-dependencies/exclusive", secretHandler.CreateSecretDependencyExclusiveProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/secret-dependencies/{id}", secretHandler.DeleteSecretDependencyProxy)

			// WebAuthn / passkey storage-primitive proxy (finding #517). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049)
			// proxy CreateWebAuthnCredential/ListWebAuthnCredentials/
			// GetWebAuthnCredentialByCredID/LockWebAuthnCredentialForUpdate/
			// UpdateWebAuthnCredential/AdvanceWebAuthnCredentialCounter/
			// DeleteWebAuthnCredential/CountWebAuthnCredentials/
			// SetUserWebAuthnEnabled/CreateWebAuthnSession/ConsumeWebAuthnSession to
			// THIS server's real storage backend, instead of RemoteStorage's ten
			// WebAuthn methods having no server endpoint to call at all (every
			// passkey registration/login flow was completely non-functional under
			// storage.type: remote). Unlike the MFA/TOTP proxy above (a
			// verification proxy — the raw TOTP secret must never leave the server
			// that can decrypt it), a passkey's public key and ceremony session
			// state are not secret, so this is an ordinary CRUD passthrough — no
			// WebAuthn ceremony/ownership/reauth POLICY decision is made here; that
			// stays entirely in the CALLING server's own internal/core.KeyorixCore,
			// exactly as it does against a local backend. Reuses the SAME
			// system.read/system.write tier — no new privilege class. See
			// webauthn_proxy.go's package doc for the signature-counter race fix:
			// AdvanceWebAuthnCredentialCounter is the one route here that performs
			// a full locked compare-and-swap in a single request rather than a
			// plain CRUD read/write, closing the cloned-authenticator TOCTOU a
			// naive Lock-then-Update pair over two separate remote calls would
			// reopen (#306/#517). Static sub-paths (lookup, count,
			// advance-counter) are registered before their sibling {id} routes.
			r.Get("/webauthn/credentials/lookup", authHandler.GetWebAuthnCredentialByCredIDProxy)
			r.Get("/webauthn/credentials/count", authHandler.CountWebAuthnCredentialsProxy)
			r.Get("/webauthn/credentials", authHandler.ListWebAuthnCredentialsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/webauthn/credentials", authHandler.CreateWebAuthnCredentialProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/webauthn/credentials/{id}", authHandler.UpdateWebAuthnCredentialProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Patch("/webauthn/credentials/advance-counter", authHandler.AdvanceWebAuthnCredentialCounterProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/webauthn/users/{userId}/credentials/{id}", authHandler.DeleteWebAuthnCredentialProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/webauthn/users/{userId}/webauthn-enabled", authHandler.SetUserWebAuthnEnabledProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/webauthn/sessions", authHandler.CreateWebAuthnSessionProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/webauthn/sessions/consume", authHandler.ConsumeWebAuthnSessionProxy)

			// Login-lockout accounting storage-primitive proxy (backlog #529). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049) proxy
			// UpdateLoginLockoutState to THIS server's real storage backend, instead of
			// RemoteStorage's one remaining login-lockout method having no server endpoint
			// to call at all (per-account brute-force lockout accounting — every
			// recordFailedLogin/checkLockAndClearLoginFailures/clearLoginFailures/
			// UnlockUser call in internal/core/login_lockout.go — silently failed OPEN
			// under storage.type: remote, the last piece of the #454 gap left after the
			// login-attempts/setup-tokens/groups/webauthn proxies above each closed their
			// own slice of it). Exactly the same pattern as the webauthn proxy above: a
			// thin passthrough onto storage.Storage (no lockout POLICY decision — the
			// failure threshold, the exponential cooldown, WHEN to trip or clear — is made
			// here; that stays entirely in the CALLING server's own
			// internal/core.KeyorixCore, exactly as it does against a local backend),
			// reusing the SAME system.read/system.write tier — no new privilege class.
			// This is a single unconditional column UPDATE, not a compare-and-swap (see
			// login_lockout_proxy.go's package doc for the atomicity analysis): every
			// caller already computes the final values itself under its own
			// LockUserForUpdate + WithTransaction + per-user mutex-shard serialization, so
			// one proxied round trip preserves LocalStorage's own semantics unchanged —
			// unlike AdvanceWebAuthnCredentialCounterProxy just above, no new atomic
			// primitive is needed.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/users/{id}/login-lockout", authHandler.UpdateLoginLockoutStateProxy)

			// Legal-hold storage-primitive proxy (finding #519). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// CreateLegalHold/GetActiveLegalHold/UpdateLegalHold to THIS server's real
			// storage backend, instead of RemoteStorage's three legal-hold methods
			// having no server endpoint to call at all (core.PlaceLegalHold/
			// LiftLegalHold/IsLegalHoldActive — and therefore every purge/prune
			// scheduler's legalHoldGuard check — were completely non-functional under
			// storage.type: remote; the schedulers fail SAFE on that error, so the
			// practical effect was "purges never run" rather than silent data loss,
			// but the legal-hold control itself did not work). Exactly the same
			// pattern as the project-membership proxy above: a thin passthrough onto
			// storage.Storage (no legal-hold POLICY decision — the admin-tier
			// placement gate, the placer-or-admin-tier lift gate, the required-reason
			// validation, the audit events — is made here; that stays entirely in the
			// CALLING server's own internal/core.KeyorixCore, exactly as it does
			// against a local backend), reusing the SAME system.read/system.write
			// tier — no new privilege class. There is no competing GET "{id}" route
			// at this depth (unlike groups/project-memberships, this subsystem has
			// only ever one active row, looked up by "active" rather than by ID), so
			// route registration order here is purely cosmetic.
			r.Get("/legal-hold/active", dashboardHandler.GetActiveLegalHoldProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathLegalHold, dashboardHandler.CreateLegalHoldProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/legal-hold/{id}", dashboardHandler.UpdateLegalHoldProxy)

			// Access-review-campaign storage-primitive proxy (ISO 27001 A.5.18,
			// finding #519). Lets a downstream Keyorix server booted with
			// storage.type: remote (ADR-049) proxy CreateAccessReviewCampaign/
			// GetAccessReviewCampaign/ListAccessReviewCampaigns/
			// GetOpenAccessReviewCampaign/GetLatestClosedAccessReviewCampaign/
			// UpdateAccessReviewCampaign/CreateAccessReviewItems/
			// ListAccessReviewItems/CountPendingAccessReviewItems/
			// GetAccessReviewItem/UpdateAccessReviewItem to THIS server's real
			// storage backend, instead of RemoteStorage's eleven access-review
			// -campaign methods having no server endpoint to call at all (every
			// ISO 27001 A.5.18 periodic-recertification flow was completely
			// non-functional under storage.type: remote). Exactly the same
			// pattern as the project-memberships proxy above: a thin passthrough
			// onto storage.Storage (no campaign-lifecycle POLICY decision —
			// snapshotting the live access-review report into items, the
			// reviewer-independence check, the pending-vs-force-close gate,
			// revoking the underlying grant on a "revoke" decision — is made
			// here; that stays entirely in the CALLING server's own
			// internal/core.KeyorixCore, exactly as it does against a local
			// backend), reusing the SAME system.read/system.write tier rather
			// than the project-scoped roles.read/roles.assign the human-facing
			// /projects/{id}/access-review/campaigns routes use — no new
			// privilege class. Read is baseline system.read; create/update
			// require system.write, matching every other admin-level mutation
			// in this group. Static sub-paths ("open", "latest-closed",
			// "items/{itemID}", "items/pending-count") are registered ahead of
			// the "/{id}" wildcard, the same static-vs-wildcard precedence
			// project-memberships' "active"/"stale"/"counts"/"by-user" above
			// already rely on — see access_review_campaigns_proxy.go's package
			// doc for the UpdateAccessReviewCampaign/UpdateAccessReviewItem
			// atomicity analysis (both are already a single conditional UPDATE
			// on the LocalStorage side, so one proxied round trip preserves the
			// guarantee exactly; no new atomic primitive was needed).
			r.Get("/access-review-campaigns/open", catalogHandler.GetOpenAccessReviewCampaignProxy)
			r.Get("/access-review-campaigns/latest-closed", catalogHandler.GetLatestClosedAccessReviewCampaignProxy)
			r.Get("/access-review-campaigns/items/{itemID}", catalogHandler.GetAccessReviewItemProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/access-review-campaigns/items/{itemID}", catalogHandler.UpdateAccessReviewItemProxy)
			r.Get("/access-review-campaigns", catalogHandler.ListAccessReviewCampaignsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/access-review-campaigns", catalogHandler.CreateAccessReviewCampaignProxy)
			r.Get("/access-review-campaigns/{id}", catalogHandler.GetAccessReviewCampaignProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/access-review-campaigns/{id}", catalogHandler.UpdateAccessReviewCampaignProxy)
			r.Get("/access-review-campaigns/{id}/items/pending-count", catalogHandler.CountPendingAccessReviewItemsProxy)
			r.Get("/access-review-campaigns/{id}/items", catalogHandler.ListAccessReviewItemsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/access-review-campaigns/{id}/items", catalogHandler.CreateAccessReviewItemsProxy)

			// Break-glass activation storage-primitive proxy (#519). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049)
			// proxy CreateBreakGlassActivation/GetBreakGlassActivation/
			// ListBreakGlassActivations/UpdateBreakGlassActivation/
			// RevokeBreakGlassActivation to THIS server's real storage backend,
			// instead of RemoteStorage's five break-glass methods having no server
			// endpoint to call at all (emergency-access self-activation —
			// NIS2/DORA incident response — was completely non-functional under
			// storage.type: remote). Exactly the same pattern as the
			// project-memberships/invitations proxies above: a thin passthrough
			// onto storage.Storage (no break-glass POLICY decision — enablement,
			// project-affiliation, emergency-role containment, TTL clamping, the
			// actual JIT role grant — is made here; that stays entirely in the
			// CALLING server's own internal/core.KeyorixCore, exactly as it does
			// against a local backend), reusing the SAME system.read/system.write
			// tier — no new privilege class. Critically, CreateBreakGlassActivationProxy
			// and RevokeBreakGlassActivationProxy call storage.Storage's own
			// unique-index-backed create and conditional `WHERE state = 'active'`
			// update DIRECTLY (see break_glass_proxy.go's package doc), preserving
			// the #104/PR #670 concurrent-activation race fix across this HTTP hop.
			// Read is baseline system.read; create/update/revoke require
			// system.write, matching every other admin-level mutation in this group.
			r.Get("/break-glass/{id}", catalogHandler.GetBreakGlassActivationProxy)
			r.Get("/break-glass", catalogHandler.ListBreakGlassActivationsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/break-glass", catalogHandler.CreateBreakGlassActivationProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/break-glass/{id}", catalogHandler.UpdateBreakGlassActivationProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/break-glass/{id}/revoke", catalogHandler.RevokeBreakGlassActivationProxy)

			// Risk-exception storage-primitive proxy (#519). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// CreateRiskException/GetRiskException/ListRiskExceptions/
			// UpdateRiskException to THIS server's real storage backend, instead of
			// RemoteStorage's four RiskException methods being unconditional stubs
			// (the risk register — ISO 27001 A.5.8 — was completely non-functional
			// under storage.type: remote). Exactly the same pattern as the
			// project-memberships proxy above: a thin passthrough onto
			// storage.Storage (no risk-exception POLICY decision —
			// title/category/justification validation, the expiry-in-the-future and
			// max-365-day-sunset bounds, dual-control approval, or the
			// effective-status computation from the revoked flag + expiry — is made
			// here; that stays entirely in the CALLING server's own
			// internal/core.KeyorixCore, exactly as it does against a local
			// backend), reusing the SAME system.read/system.write tier rather than
			// the audit.read the human-facing /risk-exceptions routes use, since a
			// RemoteStorage credential already needs system.write for the
			// project-memberships proxy above — no new privilege class.
			r.Get(pathRiskExceptionsID, dashboardHandler.GetRiskExceptionProxy)
			r.Get(pathRiskExceptions, dashboardHandler.ListRiskExceptionsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathRiskExceptions, dashboardHandler.CreateRiskExceptionProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put(pathRiskExceptionsID, dashboardHandler.UpdateRiskExceptionProxy)

			// Separation-of-duties (SoD) policy storage-primitive proxy (finding
			// #519). Lets a downstream Keyorix server booted with storage.type:
			// remote (ADR-049) proxy CreateSoDPolicy/GetSoDPolicy/ListSoDPolicies/
			// DeleteSoDPolicy to THIS server's real storage backend, instead of
			// RemoteStorage's four SoD-policy methods having no server endpoint to
			// call at all (internal/core/sod.go's policy CRUD, plus every preventive
			// grant-time gate that lists policies — requireNoSoDViolation and
			// friends, #419 — was completely non-functional under storage.type:
			// remote). Exactly the same pattern as the project-memberships proxy
			// above: a thin passthrough onto storage.Storage (no SoD-policy POLICY
			// decision — name/permission-pair validation, the audit-log event, the
			// violation-detection scan itself — is made here; that stays entirely in
			// the CALLING server's own internal/core.KeyorixCore, exactly as it does
			// against a local backend), reusing the SAME system.read/system.write
			// tier rather than the human-facing /sod/policies routes' calibration,
			// since a RemoteStorage credential already needs system.write for the
			// proxies above — no new privilege class. Read is baseline system.read;
			// create/delete require system.write, matching every other admin-level
			// mutation in this group.
			r.Get("/sod-policies/{id}", catalogHandler.GetSoDPolicyProxy)
			r.Get("/sod-policies", catalogHandler.ListSoDPoliciesProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/sod-policies", catalogHandler.CreateSoDPolicyProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/sod-policies/{id}", catalogHandler.DeleteSoDPolicyProxy)

			// Data-retention/purge-sweep storage-primitive proxy (finding #520). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049) proxy
			// PurgeDeletedSecretsBefore/DeleteAnomalyAlertsBefore/
			// DeleteClosedAccessReviewsBefore/DeleteExpiredBreakGlassBefore/
			// DeleteResolvedAccessRequestsBefore/DeleteExpiredRoleGrants/
			// DeleteExpiredShareRecords/PurgeDeletedUsersBefore/
			// PurgeDeletedProjectsBefore/PurgeDeletedEnvironmentsBefore/
			// ListUsersInStateBefore to THIS server's real storage backend, instead of
			// RemoteStorage's eleven data-retention/purge-sweep methods being
			// unconditional stubs (every scheduled retention/purge/lifecycle sweep —
			// ADR-032 soft-delete purge, ADR-033/A.5.33 compliance-record retention, the
			// JIT access-expiry sweep, ADR-025 stale-account warnings — was completely
			// non-functional under storage.type: remote). Exactly the same pattern as
			// the SoD-policies/risk-exceptions proxies above: a thin passthrough onto
			// storage.Storage (no retention POLICY decision — which window applies, the
			// legal-hold guard, which rows are "in flight" and excluded — is made here;
			// that stays entirely in the CALLING server's own internal/core.KeyorixCore,
			// exactly as it does against a local backend), reusing the SAME
			// system.read/system.write tier — no new privilege class. See
			// retention_proxy.go's package doc for the atomicity analysis (every method
			// already resolves in one storage.Storage call server-side, so proxying it
			// as one HTTP round trip preserves whatever transactional guarantee the local
			// implementation has) and for why DeleteExpiredRoleGrants/
			// DeleteExpiredShareRecords return the removed rows rather than a bare count
			// (their callers write one audit-log entry per removed row). Every route here
			// is destructive except the one List, gated system.read; every mutating
			// route requires system.write.
			r.Get("/retention/users/stale", userHandler.ListUsersInStateBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/secrets/purge", secretHandler.PurgeDeletedSecretsBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/anomaly-alerts/purge", auditHandler.DeleteAnomalyAlertsBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/access-reviews/purge-closed", catalogHandler.DeleteClosedAccessReviewsBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/break-glass/purge-expired", catalogHandler.DeleteExpiredBreakGlassBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/access-requests/purge-resolved", catalogHandler.DeleteResolvedAccessRequestsBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/role-grants/purge-expired", rbacHandler.DeleteExpiredRoleGrantsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/share-records/purge-expired", shareHandler.DeleteExpiredShareRecordsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/users/purge", userHandler.PurgeDeletedUsersBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/projects/purge", catalogHandler.PurgeDeletedProjectsBeforeProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/retention/environments/purge", catalogHandler.PurgeDeletedEnvironmentsBeforeProxy)

			// Misc storage-primitive proxies (finding #531 — four independent,
			// unrelated small gaps grouped by similar low-to-moderate severity;
			// see server/http/handlers/misc_remote_proxy.go's package doc for the
			// full per-item detail). Every route here reuses the SAME
			// system.read/system.write tier every other proxy above already
			// needs — no new privilege class.
			//
			// Dormant-access activity lookup: lets a downstream Keyorix server
			// booted with storage.type: remote (ADR-049) proxy
			// LastUserSecretActivity/LastUserRoleManagementActivity/
			// LastUserSecretDeletionActivity/LastUserSecretReadActivity/
			// LastUserSecretWriteActivity to THIS server's real storage backend.
			// GenerateProjectAccessReview (ISO 27001/SOC2 recertification) and
			// compliance_posture.go's countDormantRoleGrants both degrade
			// gracefully on a lookup failure, so this was a missing detective
			// signal rather than an outage — but the dormant-access/dormant-
			// role-grant signal was never available at all under storage.type:
			// remote before this fix. Reads only, gated system.read.
			r.Get("/access-activity/secret", userHandler.LastUserSecretActivityProxy)
			r.Get("/access-activity/role-management", userHandler.LastUserRoleManagementActivityProxy)
			r.Get("/access-activity/secret-deletion", userHandler.LastUserSecretDeletionActivityProxy)
			r.Get("/access-activity/secret-read", userHandler.LastUserSecretReadActivityProxy)
			r.Get("/access-activity/secret-write", userHandler.LastUserSecretWriteActivityProxy)

			// GetSecretIncludingDeleted: lets a downstream server proxy an
			// Unscoped (soft-delete-aware) secret lookup to THIS server's real
			// storage backend. Before this fix, ScopeFromDeletedSecretParam (the
			// scope resolver ahead of POST /secrets/{id}/restore,
			// server/middleware/auth.go) hard-failed on this stub, so every
			// restore request 404'd before ever reaching the
			// already-correctly-proxied RestoreSecret. A read, gated
			// system.read.
			r.Get("/secrets/{id}/including-deleted", secretHandler.GetSecretIncludingDeletedProxy)

			// ListSharesByOwner: lets a downstream server proxy the "shares I
			// created" query to THIS server's real storage backend. Before this
			// fix, core.ListSharesByUser (backing the gRPC "list my shares"
			// call) hard-failed with no fallback, unlike the graceful-degrade
			// access-activity gaps above. A read, gated system.read.
			r.Get("/shares/by-owner/{ownerID}", shareHandler.ListSharesByOwnerProxy)

			// ListSharesByUser: the "shares I received" half of the same
			// core.ListSharesByUser call. Its client method used to target a
			// human-facing /api/v1/users/{id}/shares route that was never
			// registered — there never was a "list an arbitrary user's
			// received shares" endpoint (GET /api/v1/shares only resolves the
			// CALLER's own ID from auth context, not a path parameter) — so
			// this was a 404, not a stub, and slipped past the completeness
			// guard for that reason. A read, gated system.read.
			r.Get("/shares/by-user/{userID}", shareHandler.ListSharesByUserProxy)

			// CreateUserWithRoleGrants: the ONE atomic primitive in this group —
			// see misc_remote_proxy.go's CreateUserWithRoleGrantsProxy doc and
			// remote_users.go's CreateUserWithRoleGrants doc for the full
			// atomicity analysis. Before this fix, core.CreateUserWithAssignments
			// (atomic create-user+role-grants, backing POST /api/v1/users and
			// gRPC CreateUser whenever role grants are included) hard-failed on
			// this stub. A mutation, gated system.write.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/users/with-role-grants", userHandler.CreateUserWithRoleGrantsProxy)

			// RBAC role-grant primitive proxy (finding #525). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// GetGroupRoleGrants/AssignRoleWithExpiry/AssignRoleToGroupWithExpiry/
			// RemoveAllProjectRoleGrants/ListGroupRoleAssignments/
			// ListGlobalAdminAssignmentsForUpdate/ListProjectRoleAssignments/
			// ListProjectMachineRoleAssignments to THIS server's real storage
			// backend, instead of RemoteStorage's eight RBAC role-grant methods
			// being unconditional stubs (adding a user to a group, removing a
			// project member, JIT time-bound role grants, and several
			// last-global-admin lockout guards were completely non-functional
			// under storage.type: remote — the guards specifically failed CLOSED,
			// blocking the underlying legitimate action too, not just leaving a
			// gap). Exactly the same pattern as the secret-dependencies/retention
			// proxies above: a thin passthrough onto storage.Storage (no RBAC
			// POLICY decision — the escalation-by-proxy ceiling checks,
			// separation-of-duties, audit-log writes — is made here; that stays
			// entirely in the CALLING server's own internal/core.KeyorixCore,
			// exactly as it does against a local backend), reusing the SAME
			// system.read/system.write tier — no new privilege class.
			//
			// RemoveGlobalAdminRoleGuardedProxy is the ONE exception: it DOES
			// evaluate the last-global-admin invariant server-side, because no
			// real transaction can span this HTTP hop (RemoteStorage.
			// WithTransaction is a no-op passthrough) — see
			// rbac_role_grants_proxy.go's package doc and
			// internal/core/rbac_management.go's RemoveUserRole doc for why
			// RemoveUserRole now calls this instead of a
			// ListGlobalAdminAssignmentsForUpdate-then-RemoveRole sequence for a
			// global-scope admin-conferring role: two separate HTTP round trips
			// would reopen the exact cross-process last-admin-lockout race #340
			// closed for HA Postgres replicas, this time between concurrent
			// spokes (or a spoke and the hub itself). Static sub-paths
			// ("role-grants", "role-assignments" under "/groups/{groupID}",
			// "global-admin-assignments", "global-admin-role/remove-guarded") are
			// registered ahead of nothing that would collide at this depth.
			r.Get("/rbac/groups/{groupID}/role-grants", rbacHandler.GetGroupRoleGrantsProxy)
			r.Get("/rbac/groups/{groupID}/role-assignments", rbacHandler.ListGroupRoleAssignmentsProxy)
			r.Get("/rbac/project-role-assignments", rbacHandler.ListProjectRoleAssignmentsProxy)
			r.Get("/rbac/project-machine-role-assignments", rbacHandler.ListProjectMachineRoleAssignmentsProxy)
			r.Get("/rbac/global-admin-assignments", rbacHandler.ListGlobalAdminAssignmentsForUpdateProxy)
			r.With(customMiddleware.RequirePermission(permRolesRead)).Get("/rbac/permission-matrix", rbacHandler.GetPermissionMatrix)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/rbac/assign-role-with-expiry", rbacHandler.AssignRoleWithExpiryProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/rbac/assign-role-to-group-with-expiry", rbacHandler.AssignRoleToGroupWithExpiryProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/rbac/remove-all-project-role-grants", rbacHandler.RemoveAllProjectRoleGrantsProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/rbac/global-admin-role/remove-guarded", rbacHandler.RemoveGlobalAdminRoleGuardedProxy)

			// MFA enrolment/management storage-primitive proxy (finding #524). Lets a
			// downstream Keyorix server booted with storage.type: remote (ADR-049) proxy
			// UpsertMFASecret/GetMFASecret/ActivateMFASecret/DeleteMFAForUser/
			// SetUserMFAEnabled/CreateMFARecoveryCodes/CountUnusedMFARecoveryCodes/
			// DeleteMFARecoveryCodes to THIS server's real storage backend, instead of
			// RemoteStorage's eight MFA storage methods having no server endpoint to call
			// at all (BeginMFAEnrollment/ActivateMFA/DisableMFA/
			// RegenerateMFARecoveryCodes/MFARecoveryCodesRemaining — every /auth/mfa/*
			// route in internal/core/mfa.go except already-active MFA LOGIN, which #509
			// already proxies separately via RemoteMFAVerifier — was completely
			// non-functional under storage.type: remote). Exactly the same pattern as the
			// webauthn/setup-tokens proxies above: a thin passthrough onto
			// storage.Storage (no MFA POLICY decision — the re-auth gate, recovery-code
			// generation/hashing, post-activation session invalidation — is made here;
			// that stays entirely in the CALLING server's own internal/core.KeyorixCore,
			// exactly as it does against a local backend), reusing the SAME
			// system.read/system.write tier — no new privilege class. See
			// mfa_management_proxy.go's package doc for the atomicity analysis: every
			// route here resolves in ONE storage.Storage call server-side (including
			// DeleteMFAForUserProxy, which inherits local_mfa.go's own internal
			// secret+recovery-codes transaction unchanged), so proxying each as one HTTP
			// round trip preserves whatever guarantee the local backend already had — no
			// new atomic primitive needed, unlike AdvanceWebAuthnCredentialCounterProxy
			// above. Static sub-paths ("secrets", "recovery-codes/count") are registered
			// before their sibling {userId} routes.
			r.Get("/mfa/secrets", authHandler.GetMFASecretProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/mfa/secrets", authHandler.UpsertMFASecretProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/mfa/secrets/{userId}/activate", authHandler.ActivateMFASecretProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/mfa/users/{userId}", authHandler.DeleteMFAForUserProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/mfa/users/{userId}/mfa-enabled", authHandler.SetUserMFAEnabledProxy)
			r.Get("/mfa/recovery-codes/count", authHandler.CountUnusedMFARecoveryCodesProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/mfa/recovery-codes", authHandler.CreateMFARecoveryCodesProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/mfa/recovery-codes/{userId}", authHandler.DeleteMFARecoveryCodesProxy)

			// Project/environment catalog CRUD storage-primitive proxy (finding #528).
			// Lets a downstream Keyorix server booted with storage.type: remote
			// (ADR-049) proxy ListProjects/ListProjectsWithCounts/GetProject/
			// UpdateProject/DeleteProject/RestoreProject/ListEnvironments/
			// ListEnvironmentsByProject/ListEnvironmentsByProjectIncludingDeleted/
			// ListProjectMembers/GetEnvironment/DeleteEnvironment/RestoreEnvironment to
			// THIS server's real storage backend, instead of RemoteStorage's thirteen
			// project/environment catalog methods being unconditional stubs (project and
			// environment catalog CRUD was broadly broken under storage.type: remote —
			// reachable via invitations, membership lifecycle, notifications, users,
			// secret_ref/render, drift, the rotation planner, compliance posture,
			// recertification, deployment hygiene, and a wide swath of scheduled
			// reminder/notification jobs). Exactly the same pattern as the proxies
			// above: a thin passthrough onto storage.Storage (no project/environment
			// POLICY decision — name/description validation, the per-project MFA
			// roles.assign gate, invitation/membership side effects, dynamic-secret
			// lease revocation, audit-log events, the requireAuthorityToReinstateProjectRoles
			// admin-ceiling check on restore — is made here; that stays entirely in the
			// CALLING server's own internal/core.KeyorixCore, exactly as it does against
			// a local backend), reusing the SAME system.read/system.write tier rather
			// than the project-scoped secrets.read/write/roles.assign the human-facing
			// /projects and /environments routes use — no new privilege class. Read is
			// baseline system.read; every mutating operation requires system.write.
			//
			// CreateProject/CreateEnvironment remain deliberately unsupported here (no
			// route registered) — see internal/storage/store/remote_rbac.go's Project/
			// Environment section doc for why. #499's GetEnvironment carve-out inside
			// core.CreateSecret (internal/core/secrets.go) is explicitly untouched by
			// this finding — see environment_catalog_proxy.go's package doc.
			//
			// DeleteProjectIfEmptyProxy is the one atomicity exception here (see
			// project_catalog_proxy.go's package doc and the storage.Storage
			// interface's DeleteProjectIfEmpty doc comment): core.DeleteProject's
			// force=false guard used to run as a WithTransaction-wrapped
			// ListSecrets-then-DeleteProject pair — safe under LocalStorage (a real DB
			// transaction) but WithTransaction is a no-op passthrough over HTTP for
			// RemoteStorage, so a naive two-call proxy of that pair would reopen a
			// TOCTOU window across a full network round trip (a secret created between
			// the count and the cascade would let a force=false delete silently cascade
			// over it anyway). DeleteProjectIfEmpty folds the guard and the cascade into
			// ONE atomic call/route instead, closing that gap for both backends. Static
			// sub-paths ("with-counts", "{id}/delete-if-empty", "{id}/restore",
			// "{id}/members", "{id}/environments") are registered ahead of/alongside the
			// "{id}" wildcard, matching the static-vs-wildcard precedence the proxies
			// above already rely on; "/projects/{projectId}/environments/{id}/restore"
			// reuses a DIFFERENT param name ("projectId") than pathProjectsID at the
			// same path depth, exactly like the existing human-facing
			// "/projects/{id}/environments/{envId}/copy-secrets" vs
			// "/projects/{projectId}/environments/{id}/restore" routes already do.
			r.Get("/projects/with-counts", catalogHandler.ListProjectsWithCountsProxy)
			r.Get(pathProjects, catalogHandler.ListProjectsProxy)
			r.Get(pathProjectsID, catalogHandler.GetProjectProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put(pathProjectsID, catalogHandler.UpdateProjectProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathProjectsID, catalogHandler.DeleteProjectProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/projects/{id}/delete-if-empty", catalogHandler.DeleteProjectIfEmptyProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/projects/{id}/restore", catalogHandler.RestoreProjectProxy)
			r.Get(pathProjectMembers, catalogHandler.ListProjectMembersProxy)
			r.Get(pathProjectEnvs, catalogHandler.ListEnvironmentsByProjectProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/projects/{projectId}/environments/{id}/restore", catalogHandler.RestoreEnvironmentProxy)
			r.Get("/environments", catalogHandler.ListEnvironmentsProxy)
			r.Get(pathEnvironmentsID, catalogHandler.GetEnvironmentProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathEnvironmentsID, catalogHandler.DeleteEnvironmentProxy)

			// Scheduler-lock storage-primitive proxy (#530). Lets a downstream
			// Keyorix server booted with storage.type: remote (ADR-049) proxy
			// TryAcquireSchedulerLock/ReleaseSchedulerLock to THIS server's real
			// storage backend, instead of RemoteStorage.WithSchedulerLock having no
			// server endpoint to call at all (every background scheduler runs
			// unconditionally regardless of storage.type, so this was the sole
			// blocker preventing already-remote-proxied maintenance — e.g. the
			// retention proxy immediately above, #520 — from ever actually running
			// on a schedule under storage.type: remote). Exactly the same pattern
			// as the retention proxy above: a thin passthrough onto storage.Storage
			// (no lock POLICY — which key, how long to hold it, when to renew — is
			// made here; that stays entirely in the CALLING server's own
			// RemoteStorage.WithSchedulerLock, exactly as LocalStorage.
			// WithSchedulerLock decides it against a local backend), reusing the
			// SAME system.read/system.write tier — no new privilege class. BOTH
			// routes are mutations (acquiring or releasing a lock changes state)
			// and require system.write; there is no read-only variant. See
			// scheduler_lock_proxy.go's package doc for the atomicity analysis:
			// each route performs its ENTIRE conditional decision inside ONE
			// storage.Storage call, so no naive "check, then write" pair is ever
			// exposed over this HTTP hop to reopen the exclusivity race the lock
			// exists to prevent.
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/scheduler-lock/acquire", authHandler.AcquireSchedulerLockProxy)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/scheduler-lock/release", authHandler.ReleaseSchedulerLockProxy)
		})

		// Offline-license status (ADR-065) — the locally-evaluated commercial entitlement.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/license/status", licenseHandler.GetLicenseStatus)

		// Personal-access-token hygiene — deployment-wide stale / expired-but-active
		// tokens an admin should revoke (token sprawl). Discloses every user's PAT
		// names/scopes/project-env-scope/AllowedCIDRs/owning user ID deployment-wide, so
		// gated on audit.read (global), NOT the universal system_viewer baseline
		// system.read — same disclosure-family calibration as /compliance/evidence.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/pat-hygiene", patHandler.PATHygiene)
		// Machine-token hygiene — deployment-wide stale / expired-but-active machine
		// credentials an admin should revoke (non-human token sprawl). Same calibration
		// as /pat-hygiene: audit.read, not the baseline.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/machine-token-hygiene", catalogHandler.MachineTokenHygiene)
		// Secret-hygiene rollup — deployment-wide totals of every project's posture
		// (orphaned / unused / expiring / stale-MI / rotation-overdue) + per-project
		// breakdown identified by project name. Same calibration: audit.read.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/hygiene", secretHandler.DeploymentHygiene)

		// Compliance posture — deployment-wide controls snapshot for auditors. Part of
		// the same disclosure family as /compliance/evidence (SoD-violation counts,
		// legal-hold reason, risk-register counts): gated on audit.read, not the
		// universal system_viewer baseline.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/posture", dashboardHandler.GetCompliancePosture)
		// Compliance control matrix — controls mapped to ISO/SOC2/NIS2/DORA + status.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/controls", dashboardHandler.GetComplianceControls)
		// Control matrix as CSV — the same matrix for an auditor's spreadsheet; same gate
		// as the JSON endpoint above (a lower-tier CSV export would just be a bypass).
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/controls.csv", dashboardHandler.ExportComplianceControlsCSV)
		// Compliance digest — on-demand human-readable summary (the scheduled-broadcast
		// text); restates the same posture data, same gate.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/digest", dashboardHandler.GetComplianceDigest)
		// Compliance digest send — triggers an immediate broadcast to notification channels
		// (Slack/Teams/webhook/email). Gated by system.write: it's an active dispatch
		// action, not a read disclosure, even though the content is the same as the GET.
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/compliance/digest/send", dashboardHandler.SendComplianceDigest)
		// Legal hold (ISO A.5.34): status discloses the free-text hold reason
		// deployment-wide, so reads need audit.read; place/lift stay system.write
		// (an admin action, not a read disclosure).
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get(pathLegalHold, dashboardHandler.GetLegalHold)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathLegalHold, dashboardHandler.PlaceLegalHold)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathLegalHold, dashboardHandler.LiftLegalHold)
		// Compliance evidence pack — posture + supporting records, for archival. Gated on
		// audit.read (global), NOT system.read: the deployment-wide pack enumerates
		// cross-project secret NAMES and break-glass JUSTIFICATIONS, which the minimal
		// system_viewer baseline (system.read only) must not be able to export. audit.read
		// is the compliance/auditor persona (system_auditor/system_admin) at global scope;
		// a project-scoped audit.read holder is correctly excluded from the org-wide pack.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/compliance/evidence", dashboardHandler.GetComplianceEvidence)
		// Verify a previously-exported evidence pack against its detached signature.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Post("/compliance/evidence/verify", dashboardHandler.VerifyComplianceEvidence)
		// Risk register (ISO A.5.8): list discloses free-text Reference/Justification
		// (which may itself name a secret) deployment-wide, so reads need audit.read;
		// create/revoke stay system.write.
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get(pathRiskExceptions, dashboardHandler.ListRiskExceptions)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post(pathRiskExceptions, dashboardHandler.CreateRiskException)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/risk-exceptions/{id}/approve", dashboardHandler.ApproveRiskException)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete(pathRiskExceptionsID, dashboardHandler.RevokeRiskException)

		// Separation of duties (ISO A.5.3): policy definitions (name/permission pair, no
		// PII) stay at the baseline system.read; the violations list discloses
		// deployment-wide violator names/emails, so it needs audit.read; create/delete
		// policies need system.write.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/sod/policies", catalogHandler.ListSoDPolicies)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Post("/sod/policies", catalogHandler.CreateSoDPolicy)
		r.With(customMiddleware.RequirePermission(permSystemWrite)).Delete("/sod/policies/{id}", catalogHandler.DeleteSoDPolicy)
		r.With(customMiddleware.RequirePermission(permAuditRead)).Get("/sod/violations", catalogHandler.ListSoDViolations)

		// Usage report — per-project secret counts + read activity over a time window.
		// Deployment-wide aggregation, gated by system.read.
		r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/admin/usage", adminUsageHandler.GetUsageReport)

		// On-demand triggers for the notification/alert jobs that otherwise run only on
		// their background schedulers — dispatch immediately after an incident or config
		// change. Deployment-wide admin actions, gated by system.write.
		r.Route("/admin/jobs", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission(permSystemWrite))
			r.Post("/anomaly-alerts", adminJobsHandler.RunAnomalyAlerts)
			r.Post("/rotation-reminders", adminJobsHandler.RunRotationReminders)
			r.Post("/expiry-reminders", adminJobsHandler.RunExpiryReminders)
			r.Post("/compliance-digest", adminJobsHandler.RunComplianceDigest)
		})

		// Runtime anomaly detection configuration — read/write the DB-persisted
		// detection thresholds without restarting the server.
		r.Route("/admin/anomaly-config", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission(permSystemRead)).Get("/", handlers.GetAnomalyConfig)
			r.With(customMiddleware.RequirePermission(permSystemWrite)).Put("/", handlers.UpdateAnomalyConfig)
		})
	})

	// Swagger UI and the raw OpenAPI spec (optional, based on config). #224: the
	// spec endpoint was previously registered unconditionally, so disabling
	// swagger_enabled still leaked the machine-readable API surface even though
	// the human-facing UI was correctly gated. Both routes must share the same
	// on/off behavior.
	if cfg.Server.HTTP.SwaggerEnabled {
		r.Mount("/swagger/", handlers.SwaggerHandler())
		r.Get("/openapi.yaml", handlers.OpenAPISpec)
	}

	// Serve the web dashboard. Prefer an on-disk build (mounted in the Docker
	// stack, or present in dev); otherwise fall back to the build embedded in the
	// binary, so a single keyorix-server can serve the UI with no web container
	// (the air-gap "one file" deployment).
	if webDir := getWebAssetsPath(cfg); webDir != "" {
		log.Printf("Serving web UI from %s", webDir)
		registerWebUI(r, http.Dir(webDir))
	} else if webui.HasRealBuild() {
		log.Printf("Serving embedded web UI (single-binary mode)")
		registerWebUI(r, webui.HTTPFS())
	} else {
		log.Printf("Web UI not bundled in this build; serving API only (placeholder page at /)")
		registerWebUI(r, webui.HTTPFS())
	}

	return r, nil
}

// backendRoutePrefixes lists every non-SPA route family registered on the router
// outside registerWebUI (see router.go's setup above /api/v1, plus /api/v1 itself).
// #214: NotFound previously only special-cased /api/, so a typo'd path under any
// other backend family (auth, health checks, SCIM, metrics, SAML/SSO endpoints
// under /auth, the OpenAPI/swagger docs) silently fell through to the SPA shell
// with a 200 instead of a 404 — not an auth bypass (same static public shell
// everyone gets at /), but noisy/incorrect status codes confuse health-check
// tooling and WAF rules that expect a clean 404 on an unknown path.
var backendRoutePrefixes = []string{
	"/api/", "/auth/", "/scim/", "/system/init", "/health", "/readyz", pathMetrics, pathStatus, "/swagger/", "/openapi.yaml",
}

func isBackendRoute(p string) bool {
	for _, prefix := range backendRoutePrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// noDirListing wraps a static file handler so a request that resolves to a
// directory (no index file inside it) returns 404 instead of falling through to
// Go's default http.FileServer directory listing (#213). dist/assets has no
// index.html, so a bare GET /assets/ would otherwise list every bundled filename
// including .js.map source-map names — low impact (already discoverable via the
// built JS's own sourceMappingURL comments and index.html's hashed bundle
// references) but unnecessary and inconsistent with serving no directory index.
func noDirListing(fsys http.FileSystem, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upath := req.URL.Path
		if !strings.HasPrefix(upath, "/") {
			upath = "/" + upath
		}
		if f, err := fsys.Open(path.Clean(upath)); err == nil {
			fi, statErr := f.Stat()
			_ = f.Close()
			if statErr == nil && fi.IsDir() {
				http.NotFound(w, req)
				return
			}
		}
		h.ServeHTTP(w, req)
	})
}

// registerWebUI wires the SPA's static assets and the client-side-routing
// fallback against fsys, which is rooted at the dist directory (so request paths
// map directly: /assets/x -> dist/assets/x). fsys is either an on-disk build
// (http.Dir) or the embedded build (webui.HTTPFS()).
func registerWebUI(r chi.Router, fsys http.FileSystem) {
	fileServer := http.FileServer(fsys)
	assetServer := noDirListing(fsys, fileServer)

	// Static assets are read-only: register GET+HEAD only, so a mutating method
	// (DELETE/PUT/POST/PATCH) on an asset gets a 405 from chi rather than the file
	// served with a 200 (http.FileServer ignores the method). Cleaner semantics and a
	// smaller surface for a security product.
	serveStatic := func(pattern string, h http.Handler, mws ...func(http.Handler) http.Handler) {
		rr := r.With(mws...)
		rr.Method(http.MethodGet, pattern, h)
		rr.Method(http.MethodHead, pattern, h)
	}
	serveStatic("/assets/*", assetServer, setCacheHeaders)
	serveStatic("/static/*", assetServer, setCacheHeaders)
	serveStatic("/sw.js", fileServer)
	serveStatic("/manifest.json", fileServer)
	serveStatic("/favicon.ico", fileServer)

	// SPA fallback: serve index.html for any non-API route that didn't match a
	// registered handler, so client-side routes (e.g. /admin/users) resolve. Only for
	// GET/HEAD — a mutating method to an unmatched path is not a page load.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		// An unmatched path under any known backend route family is a 404
		// regardless of method — never the SPA shell.
		if isBackendRoute(req.URL.Path) {
			http.NotFound(w, req)
			return
		}
		// A mutating method to a non-backend, unmatched path is not a page load.
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		f, err := fsys.Open("index.html")
		if err != nil {
			http.NotFound(w, req)
			return
		}
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set(hdrCacheControl, cacheNoCache)
		http.ServeContent(w, req, "index.html", fi.ModTime(), f)
	})
}

// getAllowedOrigins returns the allowed origins for CORS based on configuration
func getAllowedOrigins(cfg *config.Config) []string {
	// In development, allow localhost origins
	if cfg.Environment == "development" {
		return []string{
			"http://localhost:3000",
			"http://localhost:5173", // Vite dev server
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5173",
		}
	}

	// In production, use configured origins or default to same origin
	if len(cfg.Server.HTTP.AllowedOrigins) > 0 {
		return cfg.Server.HTTP.AllowedOrigins
	}

	// Default to same origin only
	return []string{fmt.Sprintf("https://%s", cfg.Server.HTTP.Domain)}
}

// getWebAssetsPath returns the path to web assets based on configuration
func getWebAssetsPath(cfg *config.Config) string {
	// Check if web assets path is configured
	if cfg.Server.HTTP.WebAssetsPath != "" {
		if _, err := os.Stat(cfg.Server.HTTP.WebAssetsPath); err == nil {
			return cfg.Server.HTTP.WebAssetsPath
		}
	}

	// Default paths to check
	defaultPaths := []string{
		"./web/dist",
		"../web/dist",
		"/app/web/dist", // Docker container path
		"./dist",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// setCacheHeaders sets appropriate cache headers for static assets
func setCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cache headers for static assets
		if strings.Contains(r.URL.Path, ".") {
			ext := filepath.Ext(r.URL.Path)
			switch ext {
			case ".js", ".css", ".woff", ".woff2", ".ttf", ".eot":
				// Cache for 1 year
				w.Header().Set(hdrCacheControl, "public, max-age=31536000, immutable")
			case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico":
				// Cache for 1 month
				w.Header().Set(hdrCacheControl, "public, max-age=2592000")
			default:
				// Cache for 1 day
				w.Header().Set(hdrCacheControl, "public, max-age=86400")
			}
		}
		next.ServeHTTP(w, r)
	})
}
