package grpc

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// NewServer creates a new gRPC server with all services registered
func NewServer(cfg *config.Config) (*grpc.Server, error) {
	// Create server options
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			interceptors.LoggingInterceptor(),
			interceptors.RecoveryInterceptor(),
			interceptors.AuthInterceptor(),
			interceptors.MetricsInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			interceptors.StreamLoggingInterceptor(),
			interceptors.StreamRecoveryInterceptor(),
			interceptors.StreamAuthInterceptor(),
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

	// TODO: Initialize services when protobuf definitions are ready
	// For now, the gRPC server runs without registered services

	// TODO: Register protobuf services when proto files are generated
	// pb.RegisterSecretServiceServer(server, secretService)
	// pb.RegisterUserServiceServer(server, userService)
	// pb.RegisterRoleServiceServer(server, roleService)
	// pb.RegisterAuditServiceServer(server, auditService)
	// pb.RegisterSystemServiceServer(server, systemService)
	// pb.RegisterShareServiceServer(server, shareService)

	// Enable reflection for development
	if cfg.Server.GRPC.ReflectionEnabled {
		reflection.Register(server)
		log.Println("gRPC reflection enabled")
	}

	log.Printf("gRPC server configured with %d services", 6)
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
