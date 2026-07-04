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

// NewRouter creates and configures the HTTP router
func NewRouter(cfg *config.Config, coreService *core.KeyorixCore) (http.Handler, error) {
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
	// (the health/readiness checks' own "no-cache", the status pages' own "no-cache", and
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
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders: []string{"Link", "X-Total-Count", "X-Page-Count"},
		MaxAge:         300,
	}))

	// Initialize handlers
	_, groupHandler, err := handlers.InitCoreHandlers(coreService)
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
	auditHandler := handlers.NewAuditHandler(coreService)
	licenseHandler := handlers.NewLicenseHandler(coreService)
	rotationPolicyHandler := handlers.NewRotationPolicyHandler(coreService)
	dynamicSecretHandler := handlers.NewDynamicSecretHandler(coreService)
	rbacHandler := handlers.NewRBACHandler(coreService)
	usersRolesHandler := handlers.NewUsersRolesHandler(coreService)
	notificationHandler := handlers.NewNotificationHandler(coreService)
	connectHandler := handlers.NewConnectHandler(coreService)
	adminJobsHandler := handlers.NewAdminJobsHandler(coreService)

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
	r.Handle("/metrics", customMiddleware.MetricsHandler())

	// Status page endpoint - serves stylish status dashboard
	r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
		webDir := getWebAssetsPath(cfg)
		if webDir != "" {
			statusPath := filepath.Join(webDir, "status.html")
			if _, err := os.Stat(statusPath); err == nil {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-cache")
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
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-cache")
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
			r.Get("/Users/{id}", scimHandler.GetUser)
			r.Put("/Users/{id}", scimHandler.ReplaceUser)
			r.Patch("/Users/{id}", scimHandler.PatchUser)
			r.Delete("/Users/{id}", scimHandler.DeleteUser)
			r.Get("/Groups", scimHandler.ListGroups)
			r.Post("/Groups", scimHandler.CreateGroup)
			r.Get("/Groups/{id}", scimHandler.GetGroup)
			r.Put("/Groups/{id}", scimHandler.ReplaceGroup)
			r.Patch("/Groups/{id}", scimHandler.PatchGroup)
			r.Delete("/Groups/{id}", scimHandler.DeleteGroup)
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
		r.With(customMiddleware.RequirePermission("system.read")).Get("/dashboard/stats", dashboardHandler.GetStats)
		// The full activity feed is org-wide audit data — gate it behind audit.read.
		// (Per-user dashboard stats scope their own recent-activity in core.)
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/dashboard/activity", dashboardHandler.GetActivity)

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
		r.With(customMiddleware.RequirePermission("roles.read")).Get("/connect/ref-grants", connectHandler.ListRefGrants)
		r.With(customMiddleware.RequirePermission("roles.write")).Post("/connect/ref-grants", connectHandler.CreateRefGrant)
		r.With(customMiddleware.RequirePermission("roles.write")).Delete("/connect/ref-grants/{id}", connectHandler.DeleteRefGrant)
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/projects", catalogHandler.ListProjects)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}", catalogHandler.GetProject)
		r.With(customMiddleware.RequirePermission("secrets.write")).Post("/projects", catalogHandler.CreateProject)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Put("/projects/{id}", catalogHandler.UpdateProject)
		r.With(customMiddleware.RequireScopedPermission("secrets.delete", projectScope)).Delete("/projects/{id}", catalogHandler.DeleteProject)
		// Restore reinstates every role grant the project carried at deletion — the
		// same blast radius as a role grant — so gate on roles.assign (#161), not
		// secrets.write, mirroring the direct-grant paths (matching #147's group fix).
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/restore", catalogHandler.RestoreProject)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/drift", catalogHandler.GetProjectDrift)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/rotation-order", secretHandler.GetProjectRotationOrder)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/rotation-plan", secretHandler.GetProjectRotationPlan)
		// Deployment-wide rotation plan (ADR-053): aggregates every project. Gated by
		// GLOBAL secrets.read — the same access level as listing all projects — so it
		// reveals no project the caller cannot already see.
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/rotation-plan", secretHandler.GetDeploymentRotationPlan)
		// Project membership (ADR-021 two-tier model). Read = project members may
		// view the roster; mutations require roles.assign at the project scope, so
		// a project_admin can manage their own project's members.
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/members", catalogHandler.ListProjectMembers)
		r.With(customMiddleware.RequireScopedPermission("roles.read", projectScope)).Get("/projects/{id}/access-review", catalogHandler.GetProjectAccessReview)
		// Recertification decisions (ISO 27001 A.5.18): attest is a reviewer action
		// (roles.read); revoke removes the grant and needs roles.assign.
		r.With(customMiddleware.RequireScopedPermission("roles.read", projectScope)).Post("/projects/{id}/access-review/attest", catalogHandler.AttestProjectAccessReview)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/access-review/revoke", catalogHandler.RevokeProjectAccessReview)
		// Access-review campaigns (A.5.18 periodic recertification): reads roles.read,
		// mutations roles.assign, at the project scope.
		r.With(customMiddleware.RequireScopedPermission("roles.read", projectScope)).Get("/projects/{id}/access-review/campaigns", catalogHandler.ListAccessReviewCampaigns)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/access-review/campaigns", catalogHandler.OpenAccessReviewCampaign)
		r.With(customMiddleware.RequireScopedPermission("roles.read", projectScope)).Get("/projects/{id}/access-review/campaigns/{campaignId}", catalogHandler.GetAccessReviewCampaign)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide", catalogHandler.DecideAccessReviewCampaignItem)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/access-review/campaigns/{campaignId}/close", catalogHandler.CloseAccessReviewCampaign)
		// CSV export of a campaign's items + decisions — the auditor's signed-off
		// recertification record (ISO 27001 A.5.18). Read-only, roles.read (project).
		r.With(customMiddleware.RequireScopedPermission("roles.read", projectScope)).Get("/projects/{id}/access-review/campaigns/{campaignId}/export.csv", catalogHandler.ExportAccessReviewCampaignCSV)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/members", catalogHandler.AddProjectMember)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Put("/projects/{id}/members/{userId}", catalogHandler.UpdateProjectMember)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/members/{userId}", catalogHandler.RemoveProjectMember)
		// Membership lifecycle (ADR-022): onboarding state machine, separate from
		// the role grant above. List is project-read; mutations need roles.assign.
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/memberships", catalogHandler.ListProjectMemberships)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/memberships", catalogHandler.InviteMember)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Put("/projects/{id}/memberships/{membershipId}", catalogHandler.TransitionMembership)
		// Invitations (ADR-024): admin-driven (roles.assign at the project scope).
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/invitations", catalogHandler.ListInvitations)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/invitations", catalogHandler.CreateInvitation)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/invitations/{invitationId}", catalogHandler.RevokeInvitation)
		// Resend the invitation's setup link (ADR-028).
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/invitations/{invitationId}/resend", catalogHandler.ResendInvitation)
		// Global (non-project-scoped) invitation (ADR-024): system role + multi-project
		// assignments applied atomically on accept. A system-admin operation (users.write).
		r.With(customMiddleware.RequirePermission("users.write")).Post("/invitations", catalogHandler.CreateGlobalInvitation)
		// Access requests (ADR-024): requesting + withdrawing are self-service (any
		// authenticated user — they don't have project access yet); listing and
		// approving/rejecting require roles.assign at the project scope.
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Get("/projects/{id}/access-requests", catalogHandler.ListAccessRequests)
		r.Post("/projects/{id}/access-requests", catalogHandler.CreateAccessRequest)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Put("/projects/{id}/access-requests/{requestId}", catalogHandler.ResolveAccessRequest)
		r.Post("/projects/{id}/access-requests/{requestId}/withdraw", catalogHandler.WithdrawAccessRequest)
		// Break-glass emergency access: activation is self-service (un-gated — the
		// point is access the caller lacks; controlled by config + justification +
		// audit + auto-expiry). Listing/revoking are review actions (roles.read/assign).
		r.Post("/projects/{id}/break-glass", catalogHandler.ActivateBreakGlass)
		r.With(customMiddleware.RequireScopedPermission("roles.read", projectScope)).Get("/projects/{id}/break-glass", catalogHandler.ListBreakGlassActivations)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/break-glass/{activationId}/revoke", catalogHandler.RevokeBreakGlass)
		// Machine identities (ADR-023): non-human members, segmented from humans.
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/machine-identities", catalogHandler.ListMachineIdentities)
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/machine-identities/stale", catalogHandler.ListStaleMachineIdentities)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/machine-identities", catalogHandler.CreateMachineIdentity)
		// User→machine migration creates a machine identity (roles.assign, project) AND
		// suspends the source user (users.write, global) — require both.
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).
			With(customMiddleware.RequirePermission("users.write")).
			Post("/projects/{id}/machine-identities/migrate-from-user", catalogHandler.MigrateUserToMachine)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Put("/projects/{id}/machine-identities/{machineId}", catalogHandler.TransitionMachineIdentity)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Patch("/projects/{id}/machine-identities/{machineId}/classification", catalogHandler.ClassifyMachineIdentity)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Patch("/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}/classification", catalogHandler.ClassifyMachineToken)
		// Machine-token credentials + role grants (ADR-030). Issuing a token is blocked
		// while impersonating — like PAT creation — so an admin acting as another user
		// cannot plant a durable (potentially non-expiring) credential that outlives the
		// bounded, audited impersonation session.
		r.With(customMiddleware.BlockWhenImpersonating, customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/machine-identities/{machineId}/tokens", catalogHandler.IssueMachineToken)
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/machine-identities/{machineId}/tokens", catalogHandler.ListMachineTokens)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/tokens/{tokenId}", catalogHandler.RevokeMachineToken)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/machine-identities/{machineId}/roles", catalogHandler.GrantMachineRole)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/roles/{roleId}", catalogHandler.RemoveMachineRole)
		// OIDC / Kubernetes-JWT federation bindings (ADR-031).
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/machine-identities/{machineId}/oidc-bindings", catalogHandler.CreateOIDCBinding)
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/machine-identities/{machineId}/oidc-bindings", catalogHandler.ListOIDCBindings)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/machine-identities/{machineId}/oidc-bindings/{bindingId}", catalogHandler.DeleteOIDCBinding)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Post("/projects/{id}/secrets/render", secretHandler.RenderTemplate)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/secrets/deleted", secretHandler.DeletedSecrets)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/secrets/orphaned", secretHandler.OrphanedSecrets)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/hygiene", secretHandler.ProjectHygiene)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/secrets/expiring", secretHandler.ExpiringSecrets)
		// Asset inventory (ISO 27001 A.5.9) — CSV metadata manifest of the project's
		// secrets (no values) for compliance hand-off.
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/secrets/inventory.csv", secretHandler.SecretsInventoryCSV)
		// Naming-policy conformance — live secrets whose names violate the current naming
		// policy (enforced only at create, so a tightened policy leaves stragglers).
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/secrets/name-conformance", secretHandler.SecretNameConformance)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/secrets/suspend-all", secretHandler.SuspendProjectSecrets)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/secrets/resume-all", secretHandler.ResumeProjectSecrets)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/secrets/reassign-owner", secretHandler.ReassignOwner)
		// Bulk expiry renewal — push out the expiration of every expiring/expired secret.
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/secrets/extend-expiring", secretHandler.ExtendExpiringSecrets)
		// Bulk rename toward naming-policy conformance — remediation for name-conformance.
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/secrets/bulk-rename", secretHandler.BulkRenameSecrets)
		// Bulk copy also requires secrets.read on the SOURCE environment (resolved from
		// the envId path param, not attacker-supplied input) — mirroring the single-secret
		// copy route below, which gates secrets.read on the source in addition to
		// secrets.write on the target. Without this leg, a write-only-scoped principal
		// could use the bulk copy to duplicate secret VALUES out of an environment they
		// were deliberately denied read access to, defeating the write-only RBAC role
		// this product's custom-role system is designed to support.
		r.With(
			customMiddleware.RequireScopedPermission("secrets.write", projectScope),
			customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromEnvParam("envId")),
		).Post("/projects/{id}/environments/{envId}/copy-secrets", secretHandler.CopyEnvironmentSecrets)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/environments", catalogHandler.ListProjectEnvironments)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/environments", catalogHandler.CreateProjectEnvironment)
		// Environment restore is nested under the project so the scope resolves
		// from the (live) project ID — the env row is soft-deleted and unloadable.
		// Restore reinstates the environment's role grants, so gate on roles.assign
		// (#161), not secrets.write — same shape as the project-restore fix above.
		r.With(customMiddleware.RequireScopedPermission("roles.assign", customMiddleware.ScopeFromProjectParam("projectId"))).Post("/projects/{projectId}/environments/{id}/restore", catalogHandler.RestoreEnvironment)
		r.With(customMiddleware.RequireScopedPermission("secrets.delete", customMiddleware.ScopeFromEnvParam("id"))).Delete("/environments/{id}", catalogHandler.DeleteEnvironment)
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/environments", catalogHandler.ListEnvironments)

		// Secrets endpoints. Per-secret routes resolve scope from the secret's
		// own project/environment. List authorizes against the project_id/
		// environment_id query filter (a scoped reader must narrow to a project
		// they can read; the same filter then bounds the returned rows). Create
		// authorizes in-handler against the project/environment in the body.
		secretScope := customMiddleware.ScopeFromSecretParam("id")
		r.Route("/secrets", func(r chi.Router) {
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromQuery)).Get("/", secretHandler.ListSecrets)
			// Active create-time policies (naming/value) — any authenticated caller.
			r.Get("/policy", secretHandler.SecretPolicy)
			// Usage analytics (static paths, before /{id}).
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromQuery)).Get("/usage/most-accessed", secretHandler.UsageMostAccessed)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromQuery)).Get("/usage/unused", secretHandler.UsageUnused)
			// Org-wide secret asset inventory (ISO 27001 A.5.9) — CSV manifest of every
			// project's secrets, metadata only (no values), but it DOES disclose every
			// secret's real NAME/classification/owner deployment-wide, so it is gated on
			// audit.read (global), NOT the universal system_viewer baseline system.read —
			// same disclosure-family calibration as /compliance/evidence. Static path,
			// before /{id}.
			r.With(customMiddleware.RequirePermission("audit.read")).Get("/inventory.csv", secretHandler.DeploymentSecretsInventoryCSV)
			// Org-wide naming-policy conformance — every project's secrets whose names
			// violate the current (global) policy; discloses the violating secrets' real
			// names deployment-wide, so audit.read (global), not the baseline. Static
			// path, before /{id}.
			r.With(customMiddleware.RequirePermission("audit.read")).Get("/name-conformance", secretHandler.DeploymentSecretNameConformance)
			// By-reference value read (ESO etc.): resolve project/environment/name → the
			// secret's value. Scoped to the resolved secret; static path, before /{id}.
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromRefQuery)).Get("/value", secretHandler.GetSecretValueByRef)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}", secretHandler.GetSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/versions", secretHandler.GetSecretVersions)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/risk", secretHandler.GetSecretRisk)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/shares", shareHandler.ListSecretShares)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/access", secretHandler.ListAccessors)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/access-log", secretHandler.AccessHistory)
			// Per-secret read statistics — lifetime total + recent-window summary.
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/stats", secretHandler.GetSecretAccessStats)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/audit", secretHandler.AuditTrail)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/tags", secretHandler.GetTags)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Put("/{id}/tags", secretHandler.SetTags)

			// Secret dependency graph (ADR-052).
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/dependencies", secretHandler.ListSecretDependencies)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/dependencies", secretHandler.AddSecretDependency)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Delete("/{id}/dependencies/{depId}", secretHandler.RemoveSecretDependency)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/impact", secretHandler.GetSecretImpact)

			// Certificate inspection (ADR-054) — public X.509 metadata, no value/key.
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/certificate", secretHandler.GetSecretCertificate)

			// Create: authorized inside the handler (scope comes from the body).
			r.Post("/", secretHandler.CreateSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Put("/{id}", secretHandler.UpdateSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Patch("/{id}/classification", secretHandler.ClassifySecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Patch("/{id}/description", secretHandler.DescribeSecret)
			// Copy into another environment: read the source ({id}); the handler also
			// authorizes secrets.write at the target environment's scope.
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Post("/{id}/copy", secretHandler.CopySecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Patch("/{id}/auto-rotate", secretHandler.SetAutoRotate)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/rotate", secretHandler.RotateSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/rollback", secretHandler.RollbackSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/transfer-ownership", secretHandler.TransferOwnership)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/suspend", secretHandler.SuspendSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/resume", secretHandler.ResumeSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/share", shareHandler.ShareSecret)
			// Self-service: a recipient removes their OWN direct share. No scoped
			// permission — the action is on the caller's own grant (core only removes a
			// share whose RecipientID == the caller), so it needs just authentication.
			r.Delete("/{id}/self-share", shareHandler.RemoveSelfFromShare)

			r.With(customMiddleware.RequireScopedPermission("secrets.delete", secretScope)).Delete("/{id}", secretHandler.DeleteSecret)
			// Restore resolves scope from the (soft-deleted) secret via the unscoped resolver.
			r.With(customMiddleware.RequireScopedPermission("secrets.write", customMiddleware.ScopeFromDeletedSecretParam("id"))).Post("/{id}/restore", secretHandler.RestoreSecret)
		})

		// Shares endpoints. The user's own share list stays a global-read op;
		// mutating a specific share is scoped to the shared secret.
		shareScope := customMiddleware.ScopeFromShareParam("id")
		r.Route("/shares", func(r chi.Router) {
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/", shareHandler.ListShares)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", shareScope)).Put("/{id}", shareHandler.UpdateSharePermission)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", shareScope)).Delete("/{id}", shareHandler.RevokeShare)
		})

		// Shared secrets endpoint (the caller's own shares)
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/shared-secrets", shareHandler.ListSharedSecrets)

		// Rotation policies endpoints. List/evaluate take an optional scope
		// filter; per-policy routes resolve scope from the policy; create
		// authorizes in-handler against the body.
		policyScope := customMiddleware.ScopeFromRotationPolicyParam("id")
		r.Route("/rotation-policies", func(r chi.Router) {
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromQuery)).Get("/", rotationPolicyHandler.List)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromQuery)).Get("/evaluate", rotationPolicyHandler.Evaluate)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", customMiddleware.ScopeFromQuery)).Get("/status", rotationPolicyHandler.Status)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", policyScope)).Get("/{id}", rotationPolicyHandler.Get)
			r.Post("/", rotationPolicyHandler.Create)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", policyScope)).Put("/{id}", rotationPolicyHandler.Update)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", policyScope)).Delete("/{id}", rotationPolicyHandler.Delete)
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
			r.Use(customMiddleware.RequirePermission("users.read"))
			r.Get("/", handlers.ListUsers)
			// CreateUser mutates (and can grant roles via ADR-028 atomic provisioning),
			// so it needs users.write — not just the group-level users.read. Without
			// this gate a global read-only persona (system_auditor holds users.read)
			// could POST a user with role:"system_admin" and escalate to global admin.
			r.With(customMiddleware.RequirePermission("users.write")).Post("/", handlers.CreateUser)
			r.Get("/search", handlers.SearchUsers)
			// Stale-account warnings (ADR-025): static path before /{id}.
			r.Get("/stale", handlers.StaleAccounts)
			r.Get("/{id}", handlers.GetUser)
			// Mutations need users.write, not the group-wide users.read (which the
			// read-only system_auditor persona holds) — these were the missed
			// siblings of the suspend/reactivate transitions gated below.
			r.With(customMiddleware.RequirePermission("users.write")).Put("/{id}", handlers.UpdateUser)
			// users.delete, not users.write — matches the gRPC UserService.DeleteUser
			// gate (#141). A custom role granted users.write alone (update, not delete)
			// could otherwise delete users via HTTP while gRPC correctly refused it.
			r.With(customMiddleware.RequirePermission("users.delete")).Delete("/{id}", handlers.DeleteUser)
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/restore", handlers.RestoreUser)
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/unlock", handlers.UnlockUser)
			// Admin force-logout: revoke all of a user's sessions (no state change).
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/revoke-sessions", handlers.RevokeSessions)
			// Account state transitions (ADR-025).
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/suspend", handlers.SuspendUser)
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/reactivate", handlers.ReactivateUser)
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/require-password-reset", handlers.RequirePasswordReset)
			// Credential-delivery resend (ADR-028): reissue + redeliver a setup link.
			r.With(customMiddleware.RequirePermission("users.write")).Post("/{id}/resend-setup-link", handlers.ResendSetupLink)
			// roles.read, not the group-wide users.read (#141) — matches the gRPC
			// RoleService.GetUserRoles gate for the same data. users.read is held by
			// nearly every seeded role (project_viewer, editor, …), so gating a user's
			// full role-assignment list on it let any low-privilege project member
			// enumerate an arbitrary OTHER user's roles — reconnaissance for targeted
			// privilege-escalation attempts. roles.read is held by system_admin/
			// system_auditor/project_admin, the personas that actually manage access.
			r.With(customMiddleware.RequirePermission("roles.read")).Get("/{id}/roles", usersRolesHandler.GetUserRolesForUser)
			// Effective permission set (union across the user's roles) — a read, gated
			// by the group-wide users.read like the roles view used to be. Not part of
			// #141's scope; left as-is.
			r.Get("/{id}/permissions", usersRolesHandler.GetUserPermissionsForUser)
			// Replacing a user's roles is a privilege grant — gate on roles.assign,
			// not the group-wide users.read (which many non-admin roles hold).
			r.With(customMiddleware.RequirePermission("roles.assign")).Put("/{id}/roles", usersRolesHandler.UpdateUserRoles)
			// Per-user project assignments for the detail page (ADR-025).
			r.Get("/{id}/memberships", usersRolesHandler.GetUserMembershipsForUser)
		})

		// Admin impersonation — gated by users.impersonate, which only global
		// admins hold (admin-bypass). Issues a session for the target user.
		r.With(customMiddleware.RequirePermission("users.impersonate")).
			Post("/admin/impersonate", impersonationHandler.Start)

		// Groups endpoints
		r.Route("/groups", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("users.read"))
			r.Get("/", groupHandler.ListGroups)
			// Group CRUD mutates identity/membership state — gate on users.write,
			// not the group-wide users.read (held by the read-only system_auditor).
			r.With(customMiddleware.RequirePermission("users.write")).Post("/", groupHandler.CreateGroup)
			r.Get("/{id}", groupHandler.GetGroup)
			r.With(customMiddleware.RequirePermission("users.write")).Put("/{id}", groupHandler.UpdateGroup)
			r.With(customMiddleware.RequirePermission("users.write")).Delete("/{id}", groupHandler.DeleteGroup)
			// Restore reinstates every role grant the group carried at deletion — the
			// same blast radius as a role grant — so gate on roles.assign (#147), not
			// users.write, mirroring the direct role-grant path below.
			r.With(customMiddleware.RequirePermission("roles.assign")).Post("/{id}/restore", groupHandler.RestoreGroup)
			r.Get("/{id}/members", groupHandler.GetGroupMembers)
			// Secrets a group can reach via shares — reveals secret names, so it needs
			// secrets.read on top of the group-level users.read above.
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/{id}/shared-secrets", shareHandler.ListGroupSharedSecrets)
			// Adding/removing a group member confers (or revokes) every role the group
			// holds — the same blast radius as a role grant, so gate on roles.assign
			// (matching the group's role-grant routes below), not users.read.
			r.With(customMiddleware.RequirePermission("roles.assign")).Post("/{id}/members", groupHandler.AddGroupMember)
			r.With(customMiddleware.RequirePermission("roles.assign")).Delete("/{id}/members/{userId}", groupHandler.RemoveGroupMember)
			r.Get("/{id}/roles", rbacHandler.GetGroupRoles)
			r.With(customMiddleware.RequirePermission("roles.assign")).Post("/{id}/roles", rbacHandler.AssignRoleToGroup)
			r.With(customMiddleware.RequirePermission("roles.assign")).Delete("/{id}/roles/{roleId}", rbacHandler.RemoveRoleFromGroup)
		})

		// Roles endpoints (RBAC)
		r.Route("/roles", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("roles.read"))
			r.Get("/", rbacHandler.ListRoles)
			r.With(customMiddleware.RequirePermission("roles.write")).Post("/", rbacHandler.CreateRole)
			r.Get("/{id}", rbacHandler.GetRole)
			r.With(customMiddleware.RequirePermission("roles.write")).Put("/{id}", rbacHandler.UpdateRole)
			r.With(customMiddleware.RequirePermission("roles.write")).Delete("/{id}", rbacHandler.DeleteRole)
			r.Get("/{id}/permissions", rbacHandler.GetRolePermissions)
			r.With(customMiddleware.RequirePermission("roles.write")).Post("/{id}/permissions", rbacHandler.AssignPermissionToRole)
			r.With(customMiddleware.RequirePermission("roles.write")).Delete("/{id}/permissions/{permissionId}", rbacHandler.RemovePermissionFromRole)
		})

		// Permissions endpoints
		r.Route("/permissions", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("roles.read"))
			r.Get("/", rbacHandler.ListPermissions)
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
			r.Use(customMiddleware.RequirePermission("roles.assign"))
			r.Post("/", rbacHandler.AssignRole)
			r.Delete("/", rbacHandler.RemoveRole)
			r.Get("/user/{userId}", rbacHandler.GetUserRoles)
		})

		// Audit logs endpoints
		r.Route("/audit", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("audit.read"))
			r.Get("/logs", auditHandler.GetAuditLogs)
			r.Get("/export", auditHandler.ExportAuditLogs)
			r.Get("/export.csv", auditHandler.ExportAuditLogsCSV)
			r.Get("/rbac-logs", auditHandler.GetRBACAuditLogs)
			r.Get("/retention", auditHandler.GetAuditRetention)
			r.Get("/verify", auditHandler.VerifyAuditChain)
			// Writing a checkpoint is a privileged integrity-control action — gate it
			// above the group's audit.read with system.write (admin-level).
			r.With(customMiddleware.RequirePermission("system.write")).Post("/checkpoint", auditHandler.WriteAuditCheckpoint)
			r.Get("/anomalies", handlers.ListAnomalyAlerts)
			// Acknowledging (dismissing) an alert mutates a security-detection record, so
			// gate it above the group's audit.read with system.write — like /checkpoint —
			// rather than letting any read-only auditor silently bury alerts.
			r.With(customMiddleware.RequirePermission("system.write")).Post("/anomalies/{id}/acknowledge", handlers.AcknowledgeAnomalyAlert)
		})

		// System endpoints
		r.Route("/system", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("system.read"))
			r.Get("/info", handlers.MakeSystemInfoHandler(cfg))
			r.Get("/metrics", handlers.GetMetrics)
			// Per-scheduler last-run/last-success timestamps (Prometheus exposition
			// format), deliberately kept off the public, unauthenticated /metrics
			// endpoint — see server/middleware/scheduler_metrics.go — since an exact
			// tick timestamp would let an anonymous caller predict a security-relevant
			// job's next execution to sub-second precision. Gated behind system.read
			// like the rest of this group.
			r.Get("/scheduler-metrics", customMiddleware.SchedulerMetricsHandler().ServeHTTP)
		})

		// Offline-license status (ADR-065) — the locally-evaluated commercial entitlement.
		r.With(customMiddleware.RequirePermission("system.read")).Get("/license/status", licenseHandler.GetLicenseStatus)

		// Personal-access-token hygiene — deployment-wide stale / expired-but-active
		// tokens an admin should revoke (token sprawl). Discloses every user's PAT
		// names/scopes/project-env-scope/AllowedCIDRs/owning user ID deployment-wide, so
		// gated on audit.read (global), NOT the universal system_viewer baseline
		// system.read — same disclosure-family calibration as /compliance/evidence.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/pat-hygiene", patHandler.PATHygiene)
		// Machine-token hygiene — deployment-wide stale / expired-but-active machine
		// credentials an admin should revoke (non-human token sprawl). Same calibration
		// as /pat-hygiene: audit.read, not the baseline.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/machine-token-hygiene", catalogHandler.MachineTokenHygiene)
		// Secret-hygiene rollup — deployment-wide totals of every project's posture
		// (orphaned / unused / expiring / stale-MI / rotation-overdue) + per-project
		// breakdown identified by project name. Same calibration: audit.read.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/hygiene", secretHandler.DeploymentHygiene)

		// Compliance posture — deployment-wide controls snapshot for auditors. Part of
		// the same disclosure family as /compliance/evidence (SoD-violation counts,
		// legal-hold reason, risk-register counts): gated on audit.read, not the
		// universal system_viewer baseline.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/compliance/posture", dashboardHandler.GetCompliancePosture)
		// Compliance control matrix — controls mapped to ISO/SOC2/NIS2/DORA + status.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/compliance/controls", dashboardHandler.GetComplianceControls)
		// Control matrix as CSV — the same matrix for an auditor's spreadsheet; same gate
		// as the JSON endpoint above (a lower-tier CSV export would just be a bypass).
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/compliance/controls.csv", dashboardHandler.ExportComplianceControlsCSV)
		// Compliance digest — on-demand human-readable summary (the scheduled-broadcast
		// text); restates the same posture data, same gate.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/compliance/digest", dashboardHandler.GetComplianceDigest)
		// Legal hold (ISO A.5.34): status discloses the free-text hold reason
		// deployment-wide, so reads need audit.read; place/lift stay system.write
		// (an admin action, not a read disclosure).
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/legal-hold", dashboardHandler.GetLegalHold)
		r.With(customMiddleware.RequirePermission("system.write")).Post("/legal-hold", dashboardHandler.PlaceLegalHold)
		r.With(customMiddleware.RequirePermission("system.write")).Delete("/legal-hold", dashboardHandler.LiftLegalHold)
		// Compliance evidence pack — posture + supporting records, for archival. Gated on
		// audit.read (global), NOT system.read: the deployment-wide pack enumerates
		// cross-project secret NAMES and break-glass JUSTIFICATIONS, which the minimal
		// system_viewer baseline (system.read only) must not be able to export. audit.read
		// is the compliance/auditor persona (system_auditor/system_admin) at global scope;
		// a project-scoped audit.read holder is correctly excluded from the org-wide pack.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/compliance/evidence", dashboardHandler.GetComplianceEvidence)
		// Verify a previously-exported evidence pack against its detached signature.
		r.With(customMiddleware.RequirePermission("audit.read")).Post("/compliance/evidence/verify", dashboardHandler.VerifyComplianceEvidence)
		// Risk register (ISO A.5.8): list discloses free-text Reference/Justification
		// (which may itself name a secret) deployment-wide, so reads need audit.read;
		// create/revoke stay system.write.
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/risk-exceptions", dashboardHandler.ListRiskExceptions)
		r.With(customMiddleware.RequirePermission("system.write")).Post("/risk-exceptions", dashboardHandler.CreateRiskException)
		r.With(customMiddleware.RequirePermission("system.write")).Post("/risk-exceptions/{id}/approve", dashboardHandler.ApproveRiskException)
		r.With(customMiddleware.RequirePermission("system.write")).Delete("/risk-exceptions/{id}", dashboardHandler.RevokeRiskException)

		// Separation of duties (ISO A.5.3): policy definitions (name/permission pair, no
		// PII) stay at the baseline system.read; the violations list discloses
		// deployment-wide violator names/emails, so it needs audit.read; create/delete
		// policies need system.write.
		r.With(customMiddleware.RequirePermission("system.read")).Get("/sod/policies", catalogHandler.ListSoDPolicies)
		r.With(customMiddleware.RequirePermission("system.write")).Post("/sod/policies", catalogHandler.CreateSoDPolicy)
		r.With(customMiddleware.RequirePermission("system.write")).Delete("/sod/policies/{id}", catalogHandler.DeleteSoDPolicy)
		r.With(customMiddleware.RequirePermission("audit.read")).Get("/sod/violations", catalogHandler.ListSoDViolations)

		// On-demand triggers for the notification/alert jobs that otherwise run only on
		// their background schedulers — dispatch immediately after an incident or config
		// change. Deployment-wide admin actions, gated by system.write.
		r.Route("/admin/jobs", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("system.write"))
			r.Post("/anomaly-alerts", adminJobsHandler.RunAnomalyAlerts)
			r.Post("/rotation-reminders", adminJobsHandler.RunRotationReminders)
			r.Post("/expiry-reminders", adminJobsHandler.RunExpiryReminders)
			r.Post("/compliance-digest", adminJobsHandler.RunComplianceDigest)
		})
	})

	// Swagger UI (optional, based on config)
	if cfg.Server.HTTP.SwaggerEnabled {
		r.Mount("/swagger/", handlers.SwaggerHandler())
	}

	// OpenAPI spec endpoint
	r.Get("/openapi.yaml", handlers.OpenAPISpec)

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
	"/api/", "/auth/", "/scim/", "/system/init", "/health", "/readyz", "/metrics", "/status", "/swagger/", "/openapi.yaml",
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
		w.Header().Set("Cache-Control", "no-cache")
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
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico":
				// Cache for 1 month
				w.Header().Set("Cache-Control", "public, max-age=2592000")
			default:
				// Cache for 1 day
				w.Header().Set("Cache-Control", "public, max-age=86400")
			}
		}
		next.ServeHTTP(w, r)
	})
}
