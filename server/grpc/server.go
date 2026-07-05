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
	"google.golang.org/grpc/keepalive"
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
		// grpc.ChainUnaryInterceptor/ChainStreamInterceptor run interceptors in the
		// order listed: the first is OUTERMOST (executes first on the way in, last on
		// the way out), wrapping every interceptor listed after it. RecoveryInterceptor
		// / StreamRecoveryInterceptor are listed FIRST so a panic in ANY later
		// interceptor — metrics, logging, timeout, auth, or the handler itself — is
		// caught, instead of only panics inside the handler. A panic that unwound past
		// an inner (non-outermost) recovery interceptor would otherwise crash the
		// request with none of Recovery's clean INTERNAL status + logged stack trace.
		//
		// MetricsInterceptor is listed SECOND — inside Recovery but wrapping everything
		// after it, including AuthInterceptor — for parity with the HTTP API, where
		// PrometheusMiddleware is registered before the Authentication middleware
		// (server/http/router.go) and so records every request regardless of auth
		// outcome. Metrics used to run last, after Auth, so an auth-rejected gRPC call
		// (bad/expired token, IP-allowlist miss, MFA required) never reached it and was
		// invisible to keyorix_grpc_requests_total — a credential-stuffing campaign
		// against the gRPC endpoint produced zero movement in Prometheus-based
		// alerting, even though LoggingInterceptor (also outermost) still logged every
		// attempt. Metrics sits just inside Recovery (not outside it) so a panic is
		// still caught and turned into a clean INTERNAL status before Metrics' own
		// deferred bookkeeping runs on the way out.
		grpc.ChainUnaryInterceptor(
			interceptors.RecoveryInterceptor(),
			interceptors.MetricsInterceptor(),
			interceptors.LoggingInterceptor(),
			// Cap each unary RPC at the same 60s the HTTP API's Timeout middleware
			// enforces, so a hung handler can't tie up resources over gRPC when it would
			// be bounded over HTTP. Streams are intentionally exempt (StreamAuditLogs is
			// long-lived), so the stream chain carries no timeout.
			interceptors.TimeoutInterceptor(grpcUnaryTimeout),
			interceptors.AuthInterceptor(coreService, cfg.Security.RequireMFA),
		),
		// The stream chain intentionally carries no metrics interceptor: MetricsInterceptor
		// (and the keyorix_grpc_requests_total / _duration_seconds_total series it feeds)
		// times a single request/response round trip, and grpcMetrics.TotalDuration backs
		// an average-latency figure. A streaming call's "handler" blocks for the entire
		// life of the stream (StreamAuditLogs can run for hours), so folding stream call
		// establishment into the same counters/duration total would both misrepresent unary
		// latency (one long-lived stream would dominate the average) and conflate two
		// different things under one metric name. Auth-rejected stream opens are still
		// visible via StreamLoggingInterceptor (also outermost here). A correct fix — a
		// separate, stream-specific metric — is tracked as its own follow-up rather than
		// folded into this reordering.
		grpc.ChainStreamInterceptor(
			interceptors.StreamRecoveryInterceptor(),
			interceptors.StreamLoggingInterceptor(),
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

	// Detect and reclaim idle/abandoned connections (#222/#435). Without server-side
	// keepalive, a valid audit.read (or any other) credential holder can open many
	// long-lived, mostly-idle connections that the server can never detect as dead —
	// a slow-drip goroutine/fd exhaustion surface distinct from the per-principal
	// concurrency cap already applied to StreamAuditLogs (which only bounds "many
	// streams from one principal", not "idle connections nobody ever closes").
	ka := cfg.Server.GRPC.Keepalive
	opts = append(opts,
		grpc.KeepaliveParams(keepalive.ServerParameters{
			// Ping an idle connection after this long to check it's still alive.
			Time: ka.GetTime(),
			// Close the connection if the ping isn't ack'd within this long.
			Timeout: ka.GetTimeout(),
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// Reject a client that pings more often than this as abusive (GOAWAY
			// ENHANCE_YOUR_CALM) rather than let ping frequency itself become a DoS
			// vector.
			MinTime: ka.GetMinTime(),
			// No client here legitimately pings with zero active RPCs/streams — even
			// StreamAuditLogs keeps its stream open for as long as it needs pings — so
			// streamless pings are rejected outright rather than tolerated.
			PermitWithoutStream: ka.PermitWithoutStream,
		}),
	)

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
// every gRPC TLS listener, regardless of how its certificate is sourced, UNLESS the
// operator has explicitly configured tls.allowed_ciphers (#333) — in which case that
// configured list is honored instead (see applyTLSHardening).
var hardenedCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// applyTLSHardening layers the hardened MinVersion/CipherSuites onto tlsConfig in
// place. The protocol-version floor and cipher-suite allowlist are independent of how
// the certificate itself is sourced, so this must be applied uniformly on both the
// AutoCert and non-AutoCert paths below — AutoCert should only supply the certificate,
// not silently determine the rest of the TLS posture too (#172).
//
// CipherSuites is resolved from tlsCfg.AllowedCiphers (#333): unset means the hardcoded
// hardenedCipherSuites default above applies unchanged (no regression for existing
// deployments); set means the operator's configured suite list is honored instead,
// validated against config.SecureCipherSuiteNames so a weak/deprecated/misspelled
// suite name fails closed rather than being silently ignored or accepted. MinVersion
// stays fixed at TLS 1.2 — TLS 1.3 has no equivalent per-suite selection.
func applyTLSHardening(tlsConfig *tls.Config, tlsCfg config.TLSConfig) error {
	tlsConfig.MinVersion = tls.VersionTLS12
	suites, err := tlsCfg.ResolveCipherSuites(hardenedCipherSuites)
	if err != nil {
		return fmt.Errorf("invalid gRPC TLS configuration: %w", err)
	}
	tlsConfig.CipherSuites = suites
	return nil
}

// createGRPCTLSConfig creates TLS configuration for gRPC server
func createGRPCTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.GRPC.TLS.AutoCert {
		// For gRPC, autocert (certificate acquisition) is more complex and typically
		// not wired up here — but the hardened MinVersion/CipherSuites below must
		// still apply, matching the non-AutoCert path's posture (#172).
		tlsConfig := &tls.Config{}
		if err := applyTLSHardening(tlsConfig, cfg.Server.GRPC.TLS); err != nil {
			return nil, err
		}
		return tlsConfig, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Server.GRPC.TLS.CertFile, cfg.Server.GRPC.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	if err := applyTLSHardening(tlsConfig, cfg.Server.GRPC.TLS); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}
