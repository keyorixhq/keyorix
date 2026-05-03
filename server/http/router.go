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
		w.Write([]byte("Test route working")) // #nosec G104
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

		// Auth profile (requires valid token)
		r.Get("/auth/profile", authHandler.Profile)

		// Dashboard endpoints
		r.Get("/dashboard/stats", dashboardHandler.GetStats)
		r.Get("/dashboard/activity", dashboardHandler.GetActivity)

		// Catalog endpoints (namespaces, zones, environments)
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/namespaces", catalogHandler.ListNamespaces)
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/zones", catalogHandler.ListZones)
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/environments", catalogHandler.ListEnvironments)

		// Secrets endpoints
		r.Route("/secrets", func(r chi.Router) {
			// Require secrets.read permission for GET operations
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/", secretHandler.ListSecrets)
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/{id}", secretHandler.GetSecret)
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/{id}/versions", secretHandler.GetSecretVersions)
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/{id}/shares", shareHandler.ListSecretShares)

			// Require secrets.write permission for write operations
			r.With(customMiddleware.RequirePermission("secrets.write")).Post("/", secretHandler.CreateSecret)
			r.With(customMiddleware.RequirePermission("secrets.write")).Put("/{id}", secretHandler.UpdateSecret)
			r.With(customMiddleware.RequirePermission("secrets.write")).Post("/{id}/rotate", secretHandler.RotateSecret)
			r.With(customMiddleware.RequirePermission("secrets.write")).Post("/{id}/share", shareHandler.ShareSecret)

			// Require secrets.delete permission for delete operations
			r.With(customMiddleware.RequirePermission("secrets.delete")).Delete("/{id}", secretHandler.DeleteSecret)
		})

		// Shares endpoints
		r.Route("/shares", func(r chi.Router) {
			// Require secrets.read permission for GET operations
			r.With(customMiddleware.RequirePermission("secrets.read")).Get("/", shareHandler.ListShares)

			// Require secrets.write permission for write operations
			r.With(customMiddleware.RequirePermission("secrets.write")).Put("/{id}", shareHandler.UpdateSharePermission)

			// Require secrets.delete permission for delete operations
			r.With(customMiddleware.RequirePermission("secrets.write")).Delete("/{id}", shareHandler.RevokeShare)
		})

		// Shared secrets endpoint
		r.With(customMiddleware.RequirePermission("secrets.read")).Get("/shared-secrets", shareHandler.ListSharedSecrets)

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
		})

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
		})

		// Roles endpoints (RBAC)
		r.Route("/roles", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("roles.read"))
			r.Get("/", handlers.ListRoles)
			r.Post("/", handlers.CreateRole)
			r.Get("/{id}", handlers.GetRole)
			r.Put("/{id}", handlers.UpdateRole)
			r.Delete("/{id}", handlers.DeleteRole)
		})

		// User roles endpoints
		r.Route("/user-roles", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("roles.assign"))
			r.Post("/", handlers.AssignRole)
			r.Delete("/", handlers.RemoveRole)
			r.Get("/user/{userId}", handlers.GetUserRoles)
		})

		// Audit logs endpoints
		r.Route("/audit", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("audit.read"))
			r.Get("/logs", handlers.GetAuditLogs)
			r.Get("/rbac-logs", handlers.GetRBACAuditLogs)
			r.Get("/anomalies", handlers.ListAnomalyAlerts)
			r.Post("/anomalies/{id}/acknowledge", handlers.AcknowledgeAnomalyAlert)
		})

		// System endpoints
		r.Route("/system", func(r chi.Router) {
			r.Use(customMiddleware.RequirePermission("system.read"))
			r.Get("/info", handlers.GetSystemInfo)
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
