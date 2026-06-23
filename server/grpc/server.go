package grpc

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

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
			interceptors.AuthInterceptor(coreService),
			interceptors.MetricsInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			interceptors.StreamLoggingInterceptor(),
			interceptors.StreamRecoveryInterceptor(),
			interceptors.StreamAuthInterceptor(coreService),
		),
	}

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

	// Enable reflection for development
	if cfg.Server.GRPC.ReflectionEnabled {
		reflection.Register(server)
		log.Println("gRPC reflection enabled")
	}

	log.Println("gRPC server configured (all 12 services registered)")
	return server, nil
}

// createGRPCTLSConfig creates TLS configuration for gRPC server
func createGRPCTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.GRPC.TLS.AutoCert {
		// For gRPC, autocert is more complex and typically not used
		// Return a basic TLS config for now
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
		}, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Server.GRPC.TLS.CertFile, cfg.Server.GRPC.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}
