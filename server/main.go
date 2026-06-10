/*
Keyorix Server - Enterprise Secret Management System
Copyright (C) 2025 Keyorix Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/server/grpc"
	httpServer "github.com/keyorixhq/keyorix/server/http"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize i18n system
	if err := i18n.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize i18n system: %v", err)
	}

	// Print startup info
	if cfg.Server.HTTP.Enabled {
		scheme := "http"
		if cfg.Server.HTTP.TLS.Enabled {
			scheme = "https"
		}
		host := cfg.Server.HTTP.Domain
		if host == "" {
			host = "localhost"
		}
		log.Printf("HTTP server will start on %s://%s:%s", scheme, host, cfg.Server.HTTP.Port)
	} else {
		log.Printf("HTTP server is disabled (check keyorix.yaml)")
	}
	if cfg.Server.GRPC.Enabled {
		log.Printf("gRPC server will start on localhost:%s", cfg.Server.GRPC.Port)
	}
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start HTTP server
	if cfg.Server.HTTP.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := startHTTPServer(ctx, cfg); err != nil {
				log.Printf("HTTP server error: %v", err)
			}
		}()
	}

	// Start gRPC server
	if cfg.Server.GRPC.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := startGRPCServer(ctx, cfg); err != nil {
				log.Printf("gRPC server error: %v", err)
			}
		}()
	}

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, gracefully shutting down...")

	// Cancel context to signal shutdown
	cancel()

	// Wait for all servers to shutdown
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		log.Println("All servers shut down gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Shutdown timeout exceeded, forcing exit")
	}
}

// initializeEncryption derives the KEK from KEYORIX_MASTER_PASSWORD and returns
// an initialized encryption.Service. If encryption is disabled in config, it returns
// nil without error. Exits loudly if encryption is enabled but no passphrase is set.
func initializeEncryption(cfg *config.Config) (*encryption.Service, error) {
	if !cfg.Storage.Encryption.Enabled {
		return nil, nil
	}

	passphrase := strings.TrimSpace(os.Getenv("KEYORIX_MASTER_PASSWORD"))
	if passphrase == "" {
		return nil, fmt.Errorf(
			"encryption is enabled but KEYORIX_MASTER_PASSWORD is not set; " +
				"set this environment variable before starting the server")
	}

	baseDir := ""
	if !filepath.IsAbs(cfg.Storage.Encryption.DEKPath) {
		baseDir = "."
	}
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	svc.CleanPendingDEK() // remove leftover .pending file from any interrupted prior rotation
	if err := svc.Initialize(passphrase); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption (KEK derivation): %w", err)
	}

	log.Printf("Encryption initialised — KEK derived from passphrase, key version: %s", svc.GetKeyVersion())
	return svc, nil
}

func initializeCoreService(cfg *config.Config) (*core.KeyorixCore, *encryption.Service, error) {
	// Use storage factory to support SQLite, PostgreSQL, and remote storage
	factory := appstorage.NewStorageFactory()
	store, err := factory.CreateStorage(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	encSvc, err := initializeEncryption(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	var coreService *core.KeyorixCore
	if encSvc != nil {
		// Encryption enabled: pass the service to core (used for future SecretEncryption wiring)
		coreService = core.NewKeyorixCore(store)
	} else {
		coreService = core.NewKeyorixCore(store)
	}

	// Apply a configured password policy, if any. An absent block leaves the
	// core's conservative built-in defaults in place (ADR-025).
	if pp := cfg.PasswordPolicy; !pp.IsZero() {
		coreService.SetPasswordPolicy(core.PasswordPolicy{
			MinLength:             pp.MinLength,
			RequireUppercase:      pp.RequireUppercase,
			RequireLowercase:      pp.RequireLowercase,
			RequireDigit:          pp.RequireDigit,
			RequireSpecial:        pp.RequireSpecial,
			RejectPersonalInfo:    pp.RejectPersonalInfo,
			RejectCommonPasswords: pp.RejectCommonPasswords,
			HistoryCount:          pp.HistoryCount,
			MaxAgeDays:            pp.MaxAgeDays,
		})
	}

	// Wire native SIEM audit forwarding if configured. New returns (nil, nil)
	// when disabled, so SetAuditForwarder(nil) keeps forwarding off.
	if sc := cfg.Audit.SIEM; sc.Enabled {
		forwarder, ferr := siem.New(siem.Config{
			Enabled:            sc.Enabled,
			Provider:           siem.Provider(sc.Provider),
			Endpoint:           sc.Endpoint,
			Token:              sc.GetToken(),
			InsecureSkipVerify: sc.InsecureSkipVerify,
		})
		if ferr != nil {
			return nil, nil, fmt.Errorf("failed to init SIEM audit forwarder: %w", ferr)
		}
		coreService.SetAuditForwarder(forwarder)
		log.Printf("SIEM audit forwarding enabled (provider=%s)", sc.Provider)
	}

	// Apply the project membership validation mode (ADR-022). Empty = allowlist.
	if vm := cfg.Membership.ValidationMode; vm != "" {
		coreService.SetMembershipValidationMode(vm)
	}

	// Apply the credential-delivery setup-token TTL (ADR-028). GetSetupTokenTTL
	// falls back to 24h when the block is absent or invalid.
	coreService.SetSetupTokenTTL(cfg.CredentialDelivery.GetSetupTokenTTL())

	// Apply session-token lifetimes (short-lived tokens with silent auto-refresh).
	// Defaults preserve the historic 24h access window with no absolute ceiling, so
	// an install without a session block behaves exactly as before.
	coreService.SetSessionTTLs(cfg.Session.GetAccessTTL(), cfg.Session.GetAbsoluteTTL())

	// Wire the credential-delivery channel (ADR-028). New selects out-of-band/SMTP/
	// log from the configured mode and fails loud on a bad mode (e.g. smtp with no
	// host), so a misconfigured install does not silently drop setup links.
	cd := cfg.CredentialDelivery
	deliverer, derr := delivery.New(cd.DeliveryConfig())
	if derr != nil {
		return nil, nil, fmt.Errorf("failed to init credential delivery: %w", derr)
	}
	coreService.SetCredentialDelivery(deliverer, cd.BaseURL)

	return coreService, encSvc, nil
}

func startHTTPServer(ctx context.Context, cfg *config.Config) error {
	// Initialize core service (and encryption if enabled)
	coreService, encSvc, err := initializeCoreService(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize core service: %w", err)
	}

	// Ensure KEK is wiped from memory on shutdown
	if encSvc != nil {
		defer encSvc.Shutdown()
	}

	// Create HTTP router
	router, err := httpServer.NewRouter(cfg, coreService)
	if err != nil {
		return fmt.Errorf("failed to create HTTP router: %w", err)
	}

	// Start anomaly detection scheduler (runs every hour)
	go func() {
		detector := core.NewAnomalyDetector(coreService.Storage())
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		// Run once immediately on startup
		_ = detector.RunDetection(ctx, coreService.ListActiveSecrets(ctx))
		for {
			select {
			case <-ticker.C:
				_ = detector.RunDetection(ctx, coreService.ListActiveSecrets(ctx))
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start the retention purge scheduler (ADR-032) — opt-in. Hard-deletes
	// soft-deleted users/projects/environments older than the retention window.
	if cfg.Purge.Enabled {
		retentionDays := cfg.SoftDelete.GetRetentionDays()
		interval := cfg.Purge.GetInterval()
		log.Printf("Retention purge scheduler enabled: every %s, %d-day retention", interval, retentionDays)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			runPurge := func() {
				cutoff := time.Now().AddDate(0, 0, -retentionDays)
				if res, err := coreService.PurgeExpiredSoftDeletes(ctx, cutoff); err != nil {
					log.Printf("Retention purge error: %v", err)
				} else if res.Total() > 0 {
					log.Printf("Retention purge removed %d soft-deleted records (users=%d, projects=%d, environments=%d, secrets=%d)",
						res.Total(), res.Users, res.Projects, res.Environments, res.Secrets)
				}
			}
			runPurge() // run once on startup
			for {
				select {
				case <-ticker.C:
					runPurge()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.HTTP.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configure TLS if enabled
	if cfg.Server.HTTP.TLS.Enabled {
		tlsConfig, err := createTLSConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		server.TLSConfig = tlsConfig
	}

	// Bind the listener early so we can confirm the address before serving
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind HTTP listener: %w", err)
	}

	scheme := "http"
	if cfg.Server.HTTP.TLS.Enabled {
		scheme = "https"
	}
	ip := resolveOutboundIP()
	log.Printf("HTTP server listening on %s://%s:%s", scheme, ip, cfg.Server.HTTP.Port)

	// Start server
	go func() {
		var serveErr error
		if cfg.Server.HTTP.TLS.Enabled {
			if cfg.Server.HTTP.TLS.AutoCert {
				m := &autocert.Manager{
					Cache:      autocert.DirCache("certs"),
					Prompt:     autocert.AcceptTOS,
					HostPolicy: autocert.HostWhitelist(cfg.Server.HTTP.TLS.Domains...),
				}
				server.TLSConfig = m.TLSConfig()
				serveErr = server.ServeTLS(ln, "", "")
			} else {
				serveErr = server.ServeTLS(ln, cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile)
			}
		} else {
			serveErr = server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", serveErr)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("Shutting down HTTP server...")
	return server.Shutdown(shutdownCtx)
}

func startGRPCServer(ctx context.Context, cfg *config.Config) error {
	// Initialize the core service so the gRPC auth interceptor can validate
	// session tokens (mirrors the HTTP server's own core initialization).
	coreService, _, err := initializeCoreService(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize core service: %w", err)
	}

	// Create gRPC server
	grpcServer, err := grpc.NewServer(cfg, coreService)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}

	// Create listener
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Server.GRPC.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}

	log.Printf("gRPC server listening on %s", lis.Addr().String())

	// Start server
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	return nil
}

func createTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.HTTP.TLS.AutoCert {
		// Autocert will handle TLS config
		return nil, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
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

// resolveOutboundIP returns the machine's preferred outbound IP address.
func resolveOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close() //nolint:errcheck
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
