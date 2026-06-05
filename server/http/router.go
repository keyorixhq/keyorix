package http

import (
	"fmt"
	"net/http"
	"os"
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
)

// NewRouter creates and configures the HTTP router
func NewRouter(cfg *config.Config, coreService *core.KeyorixCore) (http.Handler, error) {
	r := chi.NewRouter()

	// Apply middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(customMiddleware.Logger())
	r.Use(customMiddleware.Recovery())
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration - updated for web dashboard
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   getAllowedOrigins(cfg),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders:   []string{"Link", "X-Total-Count", "X-Page-Count"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Initialize handlers
	_, groupHandler, err := handlers.InitCoreHandlers(coreService)
	if err != nil {
		return nil, fmt.Errorf("failed to init core HTTP handlers: %w", err)
	}

	authHandler := handlers.NewAuthHandler(coreService)
	patHandler := handlers.NewPATHandler(coreService)
	impersonationHandler := handlers.NewImpersonationHandler(coreService)

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
	rotationPolicyHandler := handlers.NewRotationPolicyHandler(coreService)
	rbacHandler := handlers.NewRBACHandler(coreService)
	usersRolesHandler := handlers.NewUsersRolesHandler(coreService)

	// Auth endpoints (no authentication middleware)
	r.Post("/auth/login", authHandler.Login)
	r.Post("/auth/logout", authHandler.Logout)
	r.Post("/auth/refresh", authHandler.RefreshToken)
	r.Post("/auth/password-reset", authHandler.PasswordReset)
	r.Post("/system/init", authHandler.InitSystem)

	// Health check endpoint
	r.Get("/health", handlers.HealthCheck)

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

	// Test route
	r.Get("/test-route", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Test route working")) // #nosec G104
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
	r.Route("/api/v1", func(r chi.Router) {
		// Authentication middleware for API routes
		r.Use(customMiddleware.Authentication(coreService))

		// Self-service account endpoints (My Account). Authenticated but not
		// permission-gated — every user manages their own profile, password,
		// sessions, and personal access tokens. ADR-021 / ADR-027.
		r.Get("/auth/profile", authHandler.Profile)
		r.Put("/auth/profile", authHandler.UpdateProfile)
		r.Post("/auth/change-password", authHandler.ChangePassword)
		r.Get("/auth/sessions", authHandler.ListSessions)
		r.Delete("/auth/sessions/{id}", authHandler.RevokeSession)
		r.Get("/auth/tokens", patHandler.ListPATs)
		r.Post("/auth/tokens", patHandler.CreatePAT)
		r.Delete("/auth/tokens/{id}", patHandler.RevokePAT)
		// Self-scoped: end the current impersonation session (no permission gate).
		r.Post("/auth/end-impersonation", impersonationHandler.End)

		// Dashboard endpoints
		r.Get("/dashboard/stats", dashboardHandler.GetStats)
		r.Get("/dashboard/activity", dashboardHandler.GetActivity)

		// Catalog endpoints (projects, environments).
		// List endpoints need global read (browse everything); accessing a
		// specific project/environment is scoped to that project. Creating a
		// project has no parent scope, so it requires global write.
		projectScope := customMiddleware.ScopeFromProjectParam("id")
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/projects", catalogHandler.ListProjects)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}", catalogHandler.GetProject)
		r.With(customMiddleware.RequirePermission("secrets.write")).Post("/projects", catalogHandler.CreateProject)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Put("/projects/{id}", catalogHandler.UpdateProject)
		r.With(customMiddleware.RequireScopedPermission("secrets.delete", projectScope)).Delete("/projects/{id}", catalogHandler.DeleteProject)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/restore", catalogHandler.RestoreProject)
		// Project membership (ADR-021 two-tier model). Read = project members may
		// view the roster; mutations require roles.assign at the project scope, so
		// a project_admin can manage their own project's members.
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/members", catalogHandler.ListProjectMembers)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/members", catalogHandler.AddProjectMember)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Put("/projects/{id}/members/{userId}", catalogHandler.UpdateProjectMember)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/members/{userId}", catalogHandler.RemoveProjectMember)
		// Invitations (ADR-024): admin-driven (roles.assign at the project scope).
		r.With(customMiddleware.RequireScopedPermission("users.read", projectScope)).Get("/projects/{id}/invitations", catalogHandler.ListInvitations)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Post("/projects/{id}/invitations", catalogHandler.CreateInvitation)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Delete("/projects/{id}/invitations/{invitationId}", catalogHandler.RevokeInvitation)
		// Access requests (ADR-024): requesting + withdrawing are self-service (any
		// authenticated user — they don't have project access yet); listing and
		// approving/rejecting require roles.assign at the project scope.
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Get("/projects/{id}/access-requests", catalogHandler.ListAccessRequests)
		r.Post("/projects/{id}/access-requests", catalogHandler.CreateAccessRequest)
		r.With(customMiddleware.RequireScopedPermission("roles.assign", projectScope)).Put("/projects/{id}/access-requests/{requestId}", catalogHandler.ResolveAccessRequest)
		r.Post("/projects/{id}/access-requests/{requestId}/withdraw", catalogHandler.WithdrawAccessRequest)
		r.With(customMiddleware.RequireScopedPermission("secrets.read", projectScope)).Get("/projects/{id}/environments", catalogHandler.ListProjectEnvironments)
		r.With(customMiddleware.RequireScopedPermission("secrets.write", projectScope)).Post("/projects/{id}/environments", catalogHandler.CreateProjectEnvironment)
		// Environment restore is nested under the project so the scope resolves
		// from the (live) project ID — the env row is soft-deleted and unloadable.
		r.With(customMiddleware.RequireScopedPermission("secrets.write", customMiddleware.ScopeFromProjectParam("projectId"))).Post("/projects/{projectId}/environments/{id}/restore", catalogHandler.RestoreEnvironment)
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
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}", secretHandler.GetSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/versions", secretHandler.GetSecretVersions)
			r.With(customMiddleware.RequireScopedPermission("secrets.read", secretScope)).Get("/{id}/shares", shareHandler.ListSecretShares)

			// Create: authorized inside the handler (scope comes from the body).
			r.Post("/", secretHandler.CreateSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Put("/{id}", secretHandler.UpdateSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/rotate", secretHandler.RotateSecret)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", secretScope)).Post("/{id}/share", shareHandler.ShareSecret)

			r.With(customMiddleware.RequireScopedPermission("secrets.delete", secretScope)).Delete("/{id}", secretHandler.DeleteSecret)
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
			r.With(customMiddleware.RequireScopedPermission("secrets.read", policyScope)).Get("/{id}", rotationPolicyHandler.Get)
			r.Post("/", rotationPolicyHandler.Create)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", policyScope)).Put("/{id}", rotationPolicyHandler.Update)
			r.With(customMiddleware.RequireScopedPermission("secrets.write", policyScope)).Delete("/{id}", rotationPolicyHandler.Delete)
		})

		// Users endpoints (RBAC)
		r.Route("/users", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("users.read"))
			r.Get("/", handlers.ListUsers)
			r.Post("/", handlers.CreateUser)
			r.Get("/search", handlers.SearchUsers)
			r.Get("/{id}", handlers.GetUser)
			r.Put("/{id}", handlers.UpdateUser)
			r.Delete("/{id}", handlers.DeleteUser)
			r.Post("/{id}/restore", handlers.RestoreUser)
			r.Get("/{id}/roles", usersRolesHandler.GetUserRolesForUser)
			r.Put("/{id}/roles", usersRolesHandler.UpdateUserRoles)
		})

		// Admin impersonation — gated by users.impersonate, which only global
		// admins hold (admin-bypass). Issues a session for the target user.
		r.With(customMiddleware.RequirePermission("users.impersonate")).
			Post("/admin/impersonate", impersonationHandler.Start)

		// Groups endpoints
		r.Route("/groups", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("users.read"))
			r.Get("/", groupHandler.ListGroups)
			r.Post("/", groupHandler.CreateGroup)
			r.Get("/{id}", groupHandler.GetGroup)
			r.Put("/{id}", groupHandler.UpdateGroup)
			r.Delete("/{id}", groupHandler.DeleteGroup)
			r.Get("/{id}/members", groupHandler.GetGroupMembers)
			r.Post("/{id}/members", groupHandler.AddGroupMember)
			r.Delete("/{id}/members/{userId}", groupHandler.RemoveGroupMember)
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

		saHandler := handlers.NewServiceAccountHandler(coreService)
		r.Route("/service-accounts", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("users.read"))
			r.Get("/", saHandler.ListServiceAccounts)
			r.With(customMiddleware.RequirePermission("users.write")).
				Post("/", saHandler.CreateServiceAccount)
			r.Get("/{clientId}", saHandler.GetServiceAccount)
			r.With(customMiddleware.RequirePermission("users.write")).
				Put("/{clientId}", saHandler.UpdateServiceAccount)
			r.With(customMiddleware.RequirePermission("users.write")).
				Delete("/{clientId}", saHandler.DeactivateServiceAccount)
			r.Get("/{clientId}/tokens", saHandler.ListTokens)
			r.With(customMiddleware.RequirePermission("users.write")).
				Post("/{clientId}/tokens", saHandler.CreateToken)
			r.With(customMiddleware.RequirePermission("users.write")).
				Delete("/{clientId}/tokens/{tokenId}", saHandler.RevokeToken)
		})

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
			r.Get("/rbac-logs", auditHandler.GetRBACAuditLogs)
			r.Get("/anomalies", handlers.ListAnomalyAlerts)
			r.Post("/anomalies/{id}/acknowledge", handlers.AcknowledgeAnomalyAlert)
		})

		// System endpoints
		r.Route("/system", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("system.read"))
			r.Get("/info", handlers.MakeSystemInfoHandler(cfg))
			r.Get("/metrics", handlers.GetMetrics)
		})
	})

	// Swagger UI (optional, based on config)
	if cfg.Server.HTTP.SwaggerEnabled {
		r.Mount("/swagger/", handlers.SwaggerHandler())
	}

	// OpenAPI spec endpoint
	r.Get("/openapi.yaml", handlers.OpenAPISpec)

	// Serve web dashboard static files
	webDir := getWebAssetsPath(cfg)
	if webDir != "" {
		// Serve static assets with cache headers
		r.Route("/static", func(r chi.Router) {
			r.Use(setCacheHeaders)
			fileServer := http.FileServer(http.Dir(filepath.Join(webDir, "static")))
			r.Handle("/*", http.StripPrefix("/static", fileServer))
		})

		// Serve other assets (favicon, manifest, etc.)
		r.Route("/assets", func(r chi.Router) {
			r.Use(setCacheHeaders)
			fileServer := http.FileServer(http.Dir(filepath.Join(webDir, "assets")))
			r.Handle("/*", http.StripPrefix("/assets", fileServer))
		})

		// Serve service worker
		r.Get("/sw.js", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFile(w, r, filepath.Join(webDir, "sw.js"))
		})

		// Serve manifest and other root files
		r.Get("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, filepath.Join(webDir, "manifest.json"))
		})

		r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(webDir, "favicon.ico"))
		})

		// SPA fallback - serve index.html for all non-API routes
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			// Don't serve SPA for API routes
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}

			// Serve index.html for SPA routing
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
		})
	}

	return r, nil
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
