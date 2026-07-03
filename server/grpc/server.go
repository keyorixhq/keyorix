package grpc

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// grpcUnaryTimeout caps each unary RPC's duration, matching the HTTP API's 60s
// request-timeout middleware (server/http/router.go) so the bound is the same on
// both transports. Streaming RPCs are exempt (see TimeoutInterceptor).
const grpcUnaryTimeout = 60 * time.Second

// NewServer creates a new gRPC server. The auth interceptor validates session
// tokens against the shared core service. Service registration is wired in a
// later phase; until then the server runs with interceptors only.
func NewServer(cfg *config.Config, coreService *core.KeyorixCore) (*grpc.Server, error) {
	// Surface the gRPC interceptor metrics on the shared Prometheus /metrics endpoint.
	interceptors.RegisterPrometheusMetrics()

	// Create server options
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			interceptors.LoggingInterceptor(),
			interceptors.RecoveryInterceptor(),
			// Cap each unary RPC at the same 60s the HTTP API's Timeout middleware
			// enforces, so a hung handler can't tie up resources over gRPC when it would
			// be bounded over HTTP. Streams are intentionally exempt (StreamAuditLogs is
			// long-lived), so the stream chain carries no timeout.
			interceptors.TimeoutInterceptor(grpcUnaryTimeout),
			interceptors.AuthInterceptor(coreService, cfg.Security.RequireMFA),
			interceptors.MetricsInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			interceptors.StreamLoggingInterceptor(),
			interceptors.StreamRecoveryInterceptor(),
			interceptors.StreamAuthInterceptor(coreService, cfg.Security.RequireMFA),
		),
	}

	// Honor the configured request-size cap on gRPC too. HTTP enforces it via the
	// MaxBodyBytes middleware (max_request_body_bytes) to mitigate memory-exhaustion
	// DoS; without this gRPC silently kept grpc-go's own 4 MiB default and ignored the
	// operator's server.grpc setting, so the cap was bypassable by switching transport.
	// Bounds the inbound message; clamp to MaxInt32 so the int64→int conversion is safe
	// on every platform (a >2 GiB request cap is nonsensical anyway).
	maxMsg := cfg.Server.GRPC.EffectiveMaxRequestBodyBytes()
	if maxMsg > math.MaxInt32 {
		maxMsg = math.MaxInt32
	}
	opts = append(opts, grpc.MaxRecvMsgSize(int(maxMsg)))

	// Add TLS if enabled
	if cfg.Server.GRPC.TLS.Enabled {
		tlsConfig, err := createGRPCTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC TLS config: %w", err)
		}
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	}

	// Create server
	server := grpc.NewServer(opts...)

	// Register services. The remaining services are migrated to the generated
	// pb.*ServiceServer interfaces in subsequent phases:
	pb.RegisterSecretServiceServer(server, services.NewSecretService(coreService))
	pb.RegisterShareServiceServer(server, services.NewShareService(coreService))
	pb.RegisterUserServiceServer(server, services.NewUserService(coreService))
	pb.RegisterRoleServiceServer(server, services.NewRoleService(coreService))
	pb.RegisterAuditServiceServer(server, services.NewAuditService(coreService))
	pb.RegisterSystemServiceServer(server, services.NewSystemService(coreService, cfg))
	pb.RegisterProjectServiceServer(server, services.NewProjectService(coreService))
	pb.RegisterMachineIdentityServiceServer(server, services.NewMachineIdentityService(coreService))
	pb.RegisterDynamicSecretServiceServer(server, services.NewDynamicSecretService(coreService))
	pb.RegisterComplianceServiceServer(server, services.NewComplianceService(coreService))
	pb.RegisterConnectServiceServer(server, services.NewConnectService(coreService))
	pb.RegisterBreakGlassServiceServer(server, services.NewBreakGlassService(coreService))
	pb.RegisterGroupServiceServer(server, services.NewGroupService(coreService))

	// Enable reflection for development
	if cfg.Server.GRPC.ReflectionEnabled {
		reflection.Register(server)
		log.Println("gRPC reflection enabled")
	}

	log.Println("gRPC server configured (all 13 services registered)")
	return server, nil
}

// hardenedCipherSuites is the explicit AEAD-only cipher suite allowlist applied to
// every gRPC TLS listener, regardless of how its certificate is sourced.
var hardenedCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// applyTLSHardening layers the deliberately hardened MinVersion/CipherSuites onto
// tlsConfig in place. The protocol-version floor and cipher-suite allowlist are
// independent of how the certificate itself is sourced, so this must be applied
// uniformly on both the AutoCert and non-AutoCert paths below — AutoCert should only
// supply the certificate, not silently determine the rest of the TLS posture too
// (#172).
func applyTLSHardening(tlsConfig *tls.Config) {
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.CipherSuites = hardenedCipherSuites
}

// createGRPCTLSConfig creates TLS configuration for gRPC server
func createGRPCTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.GRPC.TLS.AutoCert {
		// For gRPC, autocert (certificate acquisition) is more complex and typically
		// not wired up here — but the hardened MinVersion/CipherSuites below must
		// still apply, matching the non-AutoCert path's posture (#172).
		tlsConfig := &tls.Config{}
		applyTLSHardening(tlsConfig)
		return tlsConfig, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Server.GRPC.TLS.CertFile, cfg.Server.GRPC.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	applyTLSHardening(tlsConfig)
	return tlsConfig, nil
}
