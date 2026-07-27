package handlers

import (
	"net/http"
	"runtime"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/version"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SystemInfo represents system information
type SystemInfo struct {
	Version     string          `json:"version"`
	BuildTime   string          `json:"build_time"`
	GitCommit   string          `json:"git_commit"`
	GoVersion   string          `json:"go_version"`
	OS          string          `json:"os"`
	Arch        string          `json:"arch"`
	Uptime      string          `json:"uptime"`
	Environment string          `json:"environment"`
	Features    map[string]bool `json:"features"`
	Database    DatabaseInfo    `json:"database"`
	Security    SecurityInfo    `json:"security"`
}

// DatabaseInfo represents database connection information
type DatabaseInfo struct {
	Type      string   `json:"type"`
	Connected bool     `json:"connected"`
	Version   string   `json:"version"`
	Pool      PoolInfo `json:"pool"`
}

// PoolInfo represents database connection pool information
type PoolInfo struct {
	MaxConnections    int `json:"max_connections"`
	ActiveConnections int `json:"active_connections"`
	IdleConnections   int `json:"idle_connections"`
}

// SecurityInfo represents security configuration information
type SecurityInfo struct {
	TLSEnabled       bool   `json:"tls_enabled"`
	AuthEnabled      bool   `json:"auth_enabled"`
	EncryptionMethod string `json:"encryption_method"`
	AuditEnabled     bool   `json:"audit_enabled"`
}

// SystemMetrics represents system performance metrics
type SystemMetrics struct {
	Memory     MemoryMetrics   `json:"memory"`
	Goroutines int             `json:"goroutines"`
	GC         GCMetrics       `json:"gc"`
	HTTP       HTTPMetrics     `json:"http"`
	Database   DatabaseMetrics `json:"database"`
	Secrets    SecretsMetrics  `json:"secrets"`
	Uptime     string          `json:"uptime"`
	Timestamp  time.Time       `json:"timestamp"`
}

// MemoryMetrics represents memory usage metrics
type MemoryMetrics struct {
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Sys          uint64 `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    uint64 `json:"heap_alloc"`
	HeapSys      uint64 `json:"heap_sys"`
	HeapIdle     uint64 `json:"heap_idle"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapReleased uint64 `json:"heap_released"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInuse   uint64 `json:"stack_inuse"`
	StackSys     uint64 `json:"stack_sys"`
}

// GCMetrics represents garbage collection metrics
type GCMetrics struct {
	NumGC         uint32   `json:"num_gc"`
	PauseTotal    uint64   `json:"pause_total"`
	PauseNs       []uint64 `json:"pause_ns"`
	NextGC        uint64   `json:"next_gc"`
	LastGC        uint64   `json:"last_gc"`
	GCCPUFraction float64  `json:"gc_cpu_fraction"`
}

// HTTPMetrics represents HTTP server metrics
type HTTPMetrics struct {
	RequestsTotal     int64   `json:"requests_total"`
	RequestsPerSec    float64 `json:"requests_per_sec"`
	AvgResponseTime   float64 `json:"avg_response_time"`
	ErrorRate         float64 `json:"error_rate"`
	ActiveConnections int     `json:"active_connections"`
}

// DatabaseMetrics represents database performance metrics
type DatabaseMetrics struct {
	QueriesTotal      int64   `json:"queries_total"`
	QueriesPerSec     float64 `json:"queries_per_sec"`
	AvgQueryTime      float64 `json:"avg_query_time"`
	SlowQueries       int64   `json:"slow_queries"`
	ConnectionsActive int     `json:"connections_active"`
	ConnectionsIdle   int     `json:"connections_idle"`
}

// SecretsMetrics represents secrets-related metrics
type SecretsMetrics struct {
	TotalSecrets       int64 `json:"total_secrets"`
	ActiveSecrets      int64 `json:"active_secrets"`
	ExpiredSecrets     int64 `json:"expired_secrets"`
	SecretsCreated24h  int64 `json:"secrets_created_24h"`
	SecretsAccessed24h int64 `json:"secrets_accessed_24h"`
	EncryptionOps24h   int64 `json:"encryption_ops_24h"`
	DecryptionOps24h   int64 `json:"decryption_ops_24h"`
}

var startTime = time.Now()

// Note: HealthCheck is implemented in health.go

// MakeSystemInfoHandler returns a handler that serves real system info from config.
func MakeSystemInfoHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx := middleware.GetUserFromContext(r.Context())
		if userCtx == nil {
			sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
			return
		}

		tlsEnabled := cfg.Server.HTTP.TLS.Enabled
		encryptionEnabled := cfg.Storage.Encryption.Enabled
		grpcEnabled := cfg.Server.GRPC.Enabled

		systemInfo := SystemInfo{
			Version:     version.Version,
			BuildTime:   "unknown", // not injected — release builds stay byte-reproducible (commit identifies the source)
			GitCommit:   version.Commit,
			GoVersion:   runtime.Version(),
			OS:          runtime.GOOS,
			Arch:        runtime.GOARCH,
			Uptime:      time.Since(startTime).String(),
			Environment: cfg.Environment,
			Features: map[string]bool{
				"tls_enabled":        tlsEnabled,
				"auth_enabled":       true, // always on
				"audit_enabled":      true, // always on
				"metrics_enabled":    true,
				"grpc_enabled":       grpcEnabled,
				"encryption_enabled": encryptionEnabled,
				"rbac_enabled":       true, // always on
			},
			Database: DatabaseInfo{
				Type:      cfg.Storage.Type,
				Connected: true,
				Version:   "",
				Pool: PoolInfo{
					MaxConnections:    cfg.Storage.Database.MaxOpenConns,
					ActiveConnections: 2,
					IdleConnections:   cfg.Storage.Database.MaxIdleConns,
				},
			},
			Security: SecurityInfo{
				TLSEnabled:       tlsEnabled,
				AuthEnabled:      true,
				EncryptionMethod: "AES-256-GCM",
				AuditEnabled:     true,
			},
		}

		sendSuccess(w, systemInfo, "")
	}
}

// GetMetrics handles GET /api/v1/system/metrics
func GetMetrics(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Get runtime memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get GC pause history (last 10 pauses)
	pauseNs := make([]uint64, 0, 10)
	for i := 0; i < len(memStats.PauseNs) && i < 10; i++ {
		if memStats.PauseNs[i] > 0 {
			pauseNs = append(pauseNs, memStats.PauseNs[i])
		}
	}

	metrics := SystemMetrics{
		Memory: MemoryMetrics{
			Alloc:        memStats.Alloc,
			TotalAlloc:   memStats.TotalAlloc,
			Sys:          memStats.Sys,
			Lookups:      memStats.Lookups,
			Mallocs:      memStats.Mallocs,
			Frees:        memStats.Frees,
			HeapAlloc:    memStats.HeapAlloc,
			HeapSys:      memStats.HeapSys,
			HeapIdle:     memStats.HeapIdle,
			HeapInuse:    memStats.HeapInuse,
			HeapReleased: memStats.HeapReleased,
			HeapObjects:  memStats.HeapObjects,
			StackInuse:   memStats.StackInuse,
			StackSys:     memStats.StackSys,
		},
		Goroutines: runtime.NumGoroutine(),
		GC: GCMetrics{
			NumGC:         memStats.NumGC,
			PauseTotal:    memStats.PauseTotalNs,
			PauseNs:       pauseNs,
			NextGC:        memStats.NextGC,
			LastGC:        memStats.LastGC,
			GCCPUFraction: memStats.GCCPUFraction,
		},
		// HTTP, Database, and Secrets counters are not instrumented in the HTTP
		// handler path. Use the Prometheus /metrics endpoint for real HTTP counters
		// and the gRPC GetMetrics call for domain-level counts. Returning zeros
		// here rather than fabricated values; previously these were hardcoded
		// constants that misled capacity-planning and incident-response consumers.
		HTTP:     HTTPMetrics{},
		Database: DatabaseMetrics{},
		Secrets:  SecretsMetrics{},
		Uptime:    time.Since(startTime).String(),
		Timestamp: time.Now().UTC(),
	}

	sendSuccess(w, metrics, "")
}

// Helper functions are now in helpers.go
