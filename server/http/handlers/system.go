package handlers

import (
	"net/http"
	"runtime"
	"time"

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

// GetSystemInfo handles GET /api/v1/system/info
func GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	systemInfo := SystemInfo{
		Version:     "1.0.0",
		BuildTime:   "2024-01-15T10:30:00Z",
		GitCommit:   "abc123def456",
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Uptime:      time.Since(startTime).String(),
		Environment: "production", // This would come from config
		Features: map[string]bool{
			"tls_enabled":        true,
			"auth_enabled":       true,
			"audit_enabled":      true,
			"metrics_enabled":    true,
			"swagger_enabled":    true,
			"grpc_enabled":       true,
			"encryption_enabled": true,
			"rbac_enabled":       true,
		},
		Database: DatabaseInfo{
			Type:      "sqlite",
			Connected: true,
			Version:   "3.40.0",
			Pool: PoolInfo{
				MaxConnections:    10,
				ActiveConnections: 2,
				IdleConnections:   8,
			},
		},
		Security: SecurityInfo{
			TLSEnabled:       true,
			AuthEnabled:      true,
			EncryptionMethod: "AES-256-GCM",
			AuditEnabled:     true,
		},
	}

	sendSuccess(w, systemInfo, "")
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
		HTTP: HTTPMetrics{
			RequestsTotal:     12543,
			RequestsPerSec:    15.2,
			AvgResponseTime:   45.3,
			ErrorRate:         0.02,
			ActiveConnections: 8,
		},
		Database: DatabaseMetrics{
			QueriesTotal:      8932,
			QueriesPerSec:     12.1,
			AvgQueryTime:      8.7,
			SlowQueries:       3,
			ConnectionsActive: 2,
			ConnectionsIdle:   8,
		},
		Secrets: SecretsMetrics{
			TotalSecrets:       1247,
			ActiveSecrets:      1198,
			ExpiredSecrets:     49,
			SecretsCreated24h:  23,
			SecretsAccessed24h: 456,
			EncryptionOps24h:   789,
			DecryptionOps24h:   456,
		},
		Uptime:    time.Since(startTime).String(),
		Timestamp: time.Now().UTC(),
	}

	sendSuccess(w, metrics, "")
}

// Helper functions are now in helpers.go
