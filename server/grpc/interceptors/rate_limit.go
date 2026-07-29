package interceptors

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/config"
)

// GRPCRateLimitInterceptor returns a unary server interceptor that enforces a
// per-principal token-bucket request budget over the gRPC transport, mirroring
// the HTTP PrincipalRateLimit middleware so an authenticated caller cannot bypass
// the rate limit by switching transports (GRPC-009).
//
// Keyed by the same principal identity as the HTTP middleware (user ID, machine
// identity ID, or source IP as fallback). Disabled when cfg.Enabled == false,
// matching the HTTP middleware's zero-value behaviour.
func GRPCRateLimitInterceptor(cfg config.RateLimitConfig) grpc.UnaryServerInterceptor {
	if !cfg.Enabled || cfg.RequestsPerSecond <= 0 {
		log.Printf("Keyorix: GRPCRateLimitInterceptor is disabled (server.grpc.ratelimit.enabled=false) — no per-principal gRPC rate limit is active; enable in production")
		return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			return handler(ctx, req)
		}
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.RequestsPerSecond
	}
	rl := &grpcRateLimiter{
		rps:      rate.Limit(cfg.RequestsPerSecond),
		burst:    burst,
		limiters: make(map[string]*grpcPrincipalBucket),
	}
	return rl.intercept
}

const (
	grpcPrincipalLimiterIdleTTL   = 10 * time.Minute
	grpcPrincipalLimiterSweepEvery = 1000
)

type grpcPrincipalBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type grpcRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*grpcPrincipalBucket
	rps      rate.Limit
	burst    int
	requests uint64
}

func (rl *grpcRateLimiter) intercept(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if !rl.allow(grpcRateLimitKey(ctx)) {
		return nil, status.Error(codes.ResourceExhausted, "too many requests; slow down")
	}
	return handler(ctx, req)
}

func (rl *grpcRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests++
	if rl.requests%grpcPrincipalLimiterSweepEvery == 0 {
		rl.sweepLocked()
	}
	b, ok := rl.limiters[key]
	if !ok {
		b = &grpcPrincipalBucket{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[key] = b
	}
	b.lastSeen = time.Now()
	return b.limiter.Allow()
}

func (rl *grpcRateLimiter) sweepLocked() {
	cutoff := time.Now().Add(-grpcPrincipalLimiterIdleTTL)
	for k, b := range rl.limiters {
		if b.lastSeen.Before(cutoff) {
			delete(rl.limiters, k)
		}
	}
}

// grpcRateLimitKey identifies the request's budget bucket, mirroring the HTTP
// rateLimitKey: authenticated user or machine identity first, source IP as fallback.
func grpcRateLimitKey(ctx context.Context) string {
	if u := GetUserFromGRPCContext(ctx); u != nil {
		if u.MachineIdentityID != 0 {
			return "machine:" + strconv.FormatUint(uint64(u.MachineIdentityID), 10)
		}
		if u.UserID != 0 {
			return "user:" + strconv.FormatUint(uint64(u.UserID), 10)
		}
	}
	if p, ok := peer.FromContext(ctx); ok {
		return fmt.Sprintf("ip:%s", p.Addr.String())
	}
	return "ip:unknown"
}
