package services

import (
	"context"
	"runtime"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// systemVersion is the reported server version. (Build-time injection can refine
// this later; kept as a constant so GetSystemInfo/HealthCheck have a value.)
const systemVersion = "0.1.0"

// SystemGRPCService implements pb.SystemServiceServer. Info/metrics are drawn
// from config + runtime + cheap core counts; HealthCheck is a public liveness
// probe (see interceptors.isPublicMethod).
type SystemGRPCService struct {
	pb.UnimplementedSystemServiceServer
	core *core.KeyorixCore
	cfg  *config.Config
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.SystemServiceServer = (*SystemGRPCService)(nil)

// NewSystemService creates a system gRPC service.
func NewSystemService(coreService *core.KeyorixCore, cfg *config.Config) *SystemGRPCService {
	return &SystemGRPCService{core: coreService, cfg: cfg}
}

// HealthCheck is a public liveness probe.
func (s *SystemGRPCService) HealthCheck(ctx context.Context, _ *emptypb.Empty) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Status:    "healthy",
		Timestamp: timestamppb.New(time.Now()),
		Version:   systemVersion,
		Services:  map[string]string{"core": "healthy"},
	}, nil
}

// GetSystemInfo returns static + runtime system information.
func (s *SystemGRPCService) GetSystemInfo(ctx context.Context, _ *emptypb.Empty) (*pb.SystemInfo, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "system.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read system info")
	}

	info := &pb.SystemInfo{
		Version:   systemVersion,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Features: map[string]bool{
			"audit_enabled": true,
			"rbac_enabled":  true,
		},
	}
	if s.cfg != nil {
		info.Environment = s.cfg.Environment
		info.Features["tls_enabled"] = s.cfg.Server.HTTP.TLS.Enabled
		info.Features["grpc_enabled"] = s.cfg.Server.GRPC.Enabled
		info.Features["encryption_enabled"] = s.cfg.Storage.Encryption.Enabled
		info.Database = &pb.DatabaseInfo{
			Status: "connected",
			Type:   s.cfg.Storage.Type,
		}
		info.Encryption = &pb.EncryptionInfo{
			Status:    encStatus(s.cfg.Storage.Encryption.Enabled),
			Algorithm: "AES-256-GCM",
		}
	}
	return info, nil
}

// GetMetrics returns an operational snapshot: gRPC request counters (collected
// by the metrics interceptor), Go runtime stats, and cheap domain counts
// (active secrets, total users). Host CPU/disk usage come from gopsutil and DB
// latency from a timed storage health check; each is best-effort (reports 0 on
// error).
func (s *SystemGRPCService) GetMetrics(ctx context.Context, _ *emptypb.Empty) (*pb.Metrics, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(actor.Permissions, "system.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read metrics")
	}

	// Request/performance metrics from the gRPC metrics interceptor.
	rm := interceptors.GetGRPCMetrics()
	requests := &pb.RequestMetrics{
		Total:         nonNegU64(rm.TotalRequests),
		Success:       nonNegU64(rm.SuccessRequests),
		Errors:        nonNegU64(rm.ErrorRequests),
		AvgDurationMs: rm.GetAverageResponseTime(),
	}
	performance := &pb.PerformanceMetrics{
		AvgResponseTimeMs: rm.GetAverageResponseTime(),
		ErrorRatePercent:  rm.GetErrorRate(),
	}

	// Go runtime stats.
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	var memPercent float64
	if mem.Sys > 0 {
		memPercent = float64(mem.HeapInuse) / float64(mem.Sys) * 100
	}
	system := &pb.SystemMetrics{
		Goroutines:         uint32(runtime.NumGoroutine()), // #nosec G115 — goroutine count fits uint32
		MemoryUsagePercent: memPercent,
		CpuUsagePercent:    hostCPUPercent(),
		DiskUsagePercent:   hostDiskPercent(),
	}

	// DB round-trip latency: time a storage health check.
	performance.DbLatencyMs = s.dbLatencyMs(ctx)

	// Domain counts.
	activeSecrets := uint64(len(s.core.ListActiveSecrets(ctx)))
	var totalUsers uint64
	if _, total, err := s.core.ListUsers(ctx, &corestorage.UserFilter{Page: 1, PageSize: 1}); err == nil && total >= 0 {
		totalUsers = uint64(total)
	}

	return &pb.Metrics{
		Requests:    requests,
		Performance: performance,
		System:      system,
		Secrets:     &pb.SecretMetrics{Active: activeSecrets, Total: activeSecrets},
		Users:       &pb.UserMetrics{Total: totalUsers},
	}, nil
}

// nonNegU64 converts a counter to uint64, flooring negatives at 0.
func nonNegU64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// hostCPUPercent returns overall host CPU utilisation since the previous call
// (interval 0 is non-blocking). Best-effort: 0 on error.
func hostCPUPercent() float64 {
	pcts, err := cpu.Percent(0, false)
	if err != nil || len(pcts) == 0 {
		return 0
	}
	return pcts[0]
}

// hostDiskPercent returns root-filesystem usage percent. Best-effort: 0 on error.
func hostDiskPercent() float64 {
	usage, err := disk.Usage("/")
	if err != nil || usage == nil {
		return 0
	}
	return usage.UsedPercent
}

// dbLatencyMs times a storage health check (one DB round-trip). Best-effort:
// 0 if the health check errors.
func (s *SystemGRPCService) dbLatencyMs(ctx context.Context) float64 {
	start := time.Now()
	if err := s.core.Storage().HealthCheck(ctx); err != nil {
		return 0
	}
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func encStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
