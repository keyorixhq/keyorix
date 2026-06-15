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
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/evidencesink"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/notifychan"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/server/grpc"
	httpServer "github.com/keyorixhq/keyorix/server/http"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
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

// Scheduler advisory-lock keys (ADR-039) — arbitrary distinct constants,
// namespaced to each background job, so on PostgreSQL only one replica runs a
// given scheduler per tick. Distinct from the audit-chain key (0x4B455941_55444954).
const (
	schedLockAnomaly      int64 = 0x4B455953_414E4F4D // "KEYSANOM"
	schedLockPurge        int64 = 0x4B455953_50555247 // "KEYSPURG"
	schedLockDynamicSweep int64 = 0x4B455953_44594E53 // "KEYSDYNS"
	schedLockLoginPrune   int64 = 0x4B455953_4C474E50 // "KEYSLGNP"
	schedLockRotationRmdr int64 = 0x4B455953_524F5452 // "KEYSROTR"
	schedLockAuditCkpt    int64 = 0x4B455953_41434B50 // "KEYSACKP"
	schedLockJITExpiry    int64 = 0x4B455953_4A495445 // "KEYSJITE"
	schedLockRetention    int64 = 0x4B455953_52455445 // "KEYSRETE"
	schedLockEvidence     int64 = 0x4B455953_45564944 // "KEYSEVID"
	schedLockRecertify    int64 = 0x4B455953_52454354 // "KEYSRECT"
	schedLockDigest       int64 = 0x4B455953_44494753 // "KEYSDIGS"
)

// initializeEncryption sources the KEK per the configured key provider (ADR-038)
// and returns an initialized encryption.Service. If encryption is disabled in
// config, it returns nil without error. For the default "password" provider it
// requires KEYORIX_MASTER_PASSWORD; for the "file"/"env" providers the KEK comes
// from key material elsewhere, so no passphrase is needed.
func initializeEncryption(cfg *config.Config) (*encryption.Service, error) {
	if !cfg.Storage.Encryption.Enabled {
		return nil, nil
	}

	providerType := cfg.Storage.Encryption.KeyProvider.Type
	passphrase := strings.TrimSpace(os.Getenv("KEYORIX_MASTER_PASSWORD"))
	if (providerType == "" || providerType == "password") && passphrase == "" {
		return nil, fmt.Errorf(
			"encryption is enabled with the password key provider but KEYORIX_MASTER_PASSWORD " +
				"is not set; set it, or configure storage.encryption.key_provider (file/env/aws-kms)")
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

	kekSource := providerType
	if kekSource == "" {
		kekSource = "password"
	}
	log.Printf("Encryption initialised — KEK source: %s, key version: %s", kekSource, svc.GetKeyVersion())
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

	coreService := core.NewKeyorixCore(store)
	if encSvc != nil {
		// Wire the initialised encryption service for reversibly-encrypted auth
		// secrets (the TOTP MFA secret, which cannot be hashed).
		coreService.SetAuthEncryptor(encSvc)
		// Derive the audit-checkpoint signing key from the DEK (ADR-029) so signed
		// checkpoints — and on-box truncation detection — are available. Unavailable
		// when encryption is off (no DEK).
		if key, keyVer, ok := encSvc.AuditCheckpointKey(); ok {
			coreService.SetAuditCheckpointKey(key, keyVer)
		}
		// Derive the evidence-pack signing key from the DEK so scheduled evidence
		// exports are signed (and verifiable). Unavailable when encryption is off.
		if key, keyVer, ok := encSvc.EvidenceSignKey(); ok {
			coreService.SetEvidenceSignKey(key, keyVer)
		}
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

	// Wire external notification channels if configured. Each in-app notification is
	// fanned out to every enabled channel (best-effort, async); with none enabled it
	// stays in-app only.
	var notifySinks []core.NotificationSink
	if wc := cfg.Notifications.Webhook; wc.Enabled {
		sink, werr := notifychan.NewWebhook(notifychan.WebhookConfig{
			Endpoint:           wc.Endpoint,
			Token:              wc.GetToken(),
			InsecureSkipVerify: wc.InsecureSkipVerify,
		})
		if werr != nil {
			return nil, nil, fmt.Errorf("failed to init notification webhook channel: %w", werr)
		}
		notifySinks = append(notifySinks, sink)
		log.Printf("Notification webhook channel enabled (endpoint=%s)", wc.Endpoint)
	}
	if ec := cfg.Notifications.Email; ec.Enabled {
		sink, eerr := notifychan.NewEmail(notifychan.EmailConfig{
			Host:     ec.Host,
			Port:     ec.Port,
			Username: ec.Username,
			Password: ec.GetPassword(),
			From:     ec.From,
			TLS:      ec.TLS,
		})
		if eerr != nil {
			return nil, nil, fmt.Errorf("failed to init notification email channel: %w", eerr)
		}
		notifySinks = append(notifySinks, sink)
		log.Printf("Notification email channel enabled (host=%s)", ec.Host)
	}
	if cfg.Notifications.Slack.Enabled {
		sink, serr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatSlack, WebhookURL: cfg.Notifications.GetSlackWebhookURL()})
		if serr != nil {
			return nil, nil, fmt.Errorf("failed to init Slack notification channel: %w", serr)
		}
		notifySinks = append(notifySinks, sink)
		log.Printf("Notification Slack channel enabled")
	}
	if cfg.Notifications.Teams.Enabled {
		sink, terr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatTeams, WebhookURL: cfg.Notifications.GetTeamsWebhookURL()})
		if terr != nil {
			return nil, nil, fmt.Errorf("failed to init Teams notification channel: %w", terr)
		}
		notifySinks = append(notifySinks, sink)
		log.Printf("Notification Teams channel enabled")
	}
	if sink := notifychan.NewMulti(notifySinks...); sink != nil {
		coreService.SetNotificationSink(sink)
	}

	// Wire an off-box evidence webhook target if configured, so the scheduled
	// evidence pack is POSTed off-box in addition to (or instead of) a local dir.
	if ew := cfg.EvidenceDelivery.Webhook; ew.Enabled {
		fwd, ferr := evidencesink.NewWebhook(evidencesink.WebhookConfig{
			Endpoint:           ew.Endpoint,
			Token:              ew.GetToken(),
			InsecureSkipVerify: ew.InsecureSkipVerify,
		})
		if ferr != nil {
			return nil, nil, fmt.Errorf("failed to init evidence webhook target: %w", ferr)
		}
		coreService.SetEvidenceForwarder(fwd)
		log.Printf("Evidence webhook target enabled (endpoint=%s)", ew.Endpoint)
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

	// Tell core whether the auto-revoke sweeper runs (started below), so IssueLease
	// refuses to mint from backends whose lease TTL only the sweeper enforces
	// (MySQL/MongoDB) when it is disabled — otherwise the credential never expires.
	coreService.SetDynamicSweepEnabled(cfg.DynamicSecrets.SweepEnabled)

	// Wire self-service emergency access (break-glass); zero value = disabled.
	coreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled:       cfg.BreakGlass.Enabled,
		EmergencyRole: cfg.BreakGlass.EmergencyRole,
		DefaultTTL:    cfg.BreakGlass.GetDefaultTTL(),
		MaxTTL:        cfg.BreakGlass.GetMaxTTL(),
	})

	// Wire N-of-M dual-control approval for access requests (1 = disabled).
	coreService.SetDualControlPolicy(cfg.DualControl.GetRequiredApprovals())
	if n := cfg.DualControl.GetRequiredApprovals(); n > 1 {
		log.Printf("Dual-control approval enabled: %d approvals required per access request", n)
	}

	// Wire the configured data-retention windows (A.5.33) so the compliance posture
	// reports them; the scheduler below drives the actual purge.
	coreService.SetRetentionPolicy(core.RetentionPolicy{
		AnomalyAlertsDays:          cfg.DataRetention.AnomalyAlertsDays,
		ClosedAccessReviewsDays:    cfg.DataRetention.ClosedAccessReviewsDays,
		BreakGlassDays:             cfg.DataRetention.BreakGlassDays,
		ResolvedAccessRequestsDays: cfg.DataRetention.ResolvedAccessRequestsDays,
	})

	// Wire the access-recertification cadence (A.5.18) so the posture flags overdue
	// projects; the scheduler below acts on it when enabled.
	coreService.SetRecertificationCadence(cfg.Recertification.CadenceDays)

	// Wire the credential-delivery channel (ADR-028). New selects out-of-band/SMTP/
	// log from the configured mode and fails loud on a bad mode (e.g. smtp with no
	// host), so a misconfigured install does not silently drop setup links.
	cd := cfg.CredentialDelivery
	deliverer, derr := delivery.New(cd.DeliveryConfig())
	if derr != nil {
		return nil, nil, fmt.Errorf("failed to init credential delivery: %w", derr)
	}
	coreService.SetCredentialDelivery(deliverer, cd.BaseURL)

	// Wire OIDC / Kubernetes-JWT federation (ADR-031) when configured. A bad
	// issuer config (e.g. missing audiences) fails loud rather than silently
	// disabling federation.
	if oidc := cfg.OIDC; oidc.Enabled && len(oidc.Issuers) > 0 {
		trusted := make([]core.OIDCTrustedIssuer, 0, len(oidc.Issuers))
		jwksURIs := make(map[string]string, len(oidc.Issuers))
		for _, iss := range oidc.Issuers {
			trusted = append(trusted, core.OIDCTrustedIssuer{Issuer: iss.Issuer, Audiences: iss.Audiences})
			jwksURIs[iss.Issuer] = iss.JWKSURI
		}
		resolver, rerr := core.NewHTTPJWKSResolver(jwksURIs)
		if rerr != nil {
			return nil, nil, fmt.Errorf("invalid OIDC jwks_uri: %w", rerr)
		}
		verifier, verr := core.NewOIDCVerifier(trusted, resolver)
		if verr != nil {
			return nil, nil, fmt.Errorf("failed to init OIDC federation: %w", verr)
		}
		coreService.SetOIDCVerifier(verifier)
		log.Printf("OIDC federation enabled for %d issuer(s)", len(oidc.Issuers))
	}

	// Wire human SSO login (OIDC authorization-code flow) when configured. Each
	// provider's endpoints are discovered from its issuer; a provider whose discovery
	// fails is skipped with a warning rather than failing startup.
	if sso := cfg.SSO; sso.Enabled && len(sso.Providers) > 0 {
		providers, jwks, n := buildSSOProviders(sso)
		if n > 0 {
			coreService.SetSSOProviders(providers, jwks)
			log.Printf("Human SSO enabled for %d provider(s)", n)
		}
	}

	// Wire WebAuthn / passkeys (ADR-036) when configured. A bad RP config (no
	// origins / invalid RP ID) fails loud rather than silently disabling passkeys.
	if wa := cfg.WebAuthn; wa.Enabled {
		rp, werr := webauthn.New(&webauthn.Config{
			RPID:          wa.RPID,
			RPDisplayName: cmpOr(wa.RPDisplayName, "Keyorix"),
			RPOrigins:     wa.RPOrigins,
		})
		if werr != nil {
			return nil, nil, fmt.Errorf("failed to init WebAuthn: %w", werr)
		}
		coreService.SetWebAuthn(rp)
		log.Printf("WebAuthn enabled (RP ID %q, %d origin(s))", wa.RPID, len(wa.RPOrigins))
	}

	return coreService, encSvc, nil
}

// cmpOr returns a if non-empty, else b (a tiny local helper to avoid a new import).
func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
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

	// Start anomaly detection scheduler. Single-replica-gated (ADR-039) so N
	// replicas don't emit N copies of each alert. When anomaly_alerts is enabled,
	// each detection pass is followed by an alerting pass that pushes newly detected
	// anomalies to project admins + the audit/SIEM pipeline.
	go func() {
		detector := core.NewAnomalyDetector(coreService.Storage())
		alertsEnabled := cfg.AnomalyAlerts.Enabled
		interval := cfg.AnomalyAlerts.GetInterval()
		if alertsEnabled {
			log.Printf("Anomaly alerting enabled: scan + alert every %s", interval)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		runDetect := func() {
			if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockAnomaly, func() error {
				if derr := detector.RunDetection(ctx, coreService.ListActiveSecrets(ctx)); derr != nil {
					return derr
				}
				if alertsEnabled {
					if n, aerr := coreService.AlertNewAnomalies(ctx); aerr != nil {
						return aerr
					} else if n > 0 {
						log.Printf("Anomaly alerting: announced %d new anomaly alert(s)", n)
					}
				}
				return nil
			}); err != nil {
				log.Printf("Anomaly detection scheduler error: %v", err)
			}
		}
		runDetect() // run once immediately on startup
		for {
			select {
			case <-ticker.C:
				runDetect()
			case <-ctx.Done():
				return
			}
		}
	}()

	// legalHoldBlocks reports whether a deployment-wide legal hold (ISO A.5.34)
	// should block a hard-delete purge job this tick. Fails SAFE: if the hold status
	// can't be read it returns true (skip the purge), so records that may be under
	// hold are never destroyed on a transient lookup error.
	legalHoldBlocks := func(job string) bool {
		active, err := coreService.IsLegalHoldActive(ctx)
		if err != nil {
			log.Printf("%s skipped: could not check legal-hold status: %v", job, err)
			return true
		}
		if active {
			log.Printf("%s skipped: a legal hold is active", job)
			return true
		}
		return false
	}

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
				if legalHoldBlocks("Retention purge") {
					return
				}
				// Single-replica-gated (ADR-039): only one replica runs the purge.
				if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockPurge, func() error {
					cutoff := time.Now().AddDate(0, 0, -retentionDays)
					res, err := coreService.PurgeExpiredSoftDeletes(ctx, cutoff)
					if err != nil {
						log.Printf("Retention purge error: %v", err)
						return err
					}
					if res.Total() > 0 {
						log.Printf("Retention purge removed %d soft-deleted records (users=%d, projects=%d, environments=%d, secrets=%d)",
							res.Total(), res.Users, res.Projects, res.Environments, res.Secrets)
					}
					return nil
				}); err != nil {
					log.Printf("Retention purge scheduler error: %v", err)
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

	// Start the data-retention scheduler (ISO A.5.33 / GDPR / DORA) — opt-in.
	// Hard-deletes compliance records (anomaly alerts, closed campaigns, the
	// break-glass register, resolved access requests) past their per-type window.
	// Legal-hold-gated and single-replica-gated (ADR-039); audit events are never
	// touched (append-only). Runs only when at least one window is configured.
	if cfg.DataRetention.Enabled {
		policy := core.RetentionPolicy{
			AnomalyAlertsDays:          cfg.DataRetention.AnomalyAlertsDays,
			ClosedAccessReviewsDays:    cfg.DataRetention.ClosedAccessReviewsDays,
			BreakGlassDays:             cfg.DataRetention.BreakGlassDays,
			ResolvedAccessRequestsDays: cfg.DataRetention.ResolvedAccessRequestsDays,
		}
		if !policy.Configured() {
			log.Printf("Data-retention scheduler enabled but no retention windows are set; nothing to purge")
		} else {
			interval := cfg.DataRetention.GetInterval()
			log.Printf("Data-retention scheduler enabled: every %s (anomaly_alerts=%dd, closed_reviews=%dd, break_glass=%dd, access_requests=%dd; 0=keep)",
				interval, policy.AnomalyAlertsDays, policy.ClosedAccessReviewsDays, policy.BreakGlassDays, policy.ResolvedAccessRequestsDays)
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				runRetention := func() {
					if legalHoldBlocks("Data-retention purge") {
						return
					}
					if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockRetention, func() error {
						res, err := coreService.PurgeExpiredComplianceRecords(ctx, time.Now(), policy)
						if err != nil {
							log.Printf("Data-retention purge error: %v", err)
							return err
						}
						if res.Total() > 0 {
							log.Printf("Data-retention purge removed %d records (anomaly_alerts=%d, closed_campaigns=%d, review_items=%d, break_glass=%d, access_requests=%d, approvals=%d)",
								res.Total(), res.AnomalyAlerts, res.ClosedAccessReviews, res.AccessReviewItems,
								res.BreakGlass, res.ResolvedAccessRequests, res.AccessRequestApprovals)
						}
						return nil
					}); err != nil {
						log.Printf("Data-retention scheduler error: %v", err)
					}
				}
				runRetention() // run once on startup
				for {
					select {
					case <-ticker.C:
						runRetention()
					case <-ctx.Done():
						return
					}
				}
			}()
		}
	}

	// Start the rotation-reminder scheduler — opt-in. Notifies project admins of
	// secrets overdue/approaching their rotation deadline (proactive rotation
	// hygiene; a NIS2/ISO control). Single-replica-gated (ADR-039) so admins aren't
	// notified N times in an HA deployment.
	if cfg.RotationReminders.Enabled {
		interval := cfg.RotationReminders.GetInterval()
		log.Printf("Rotation-reminder scheduler enabled: every %s", interval)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			runReminders := func() {
				if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockRotationRmdr, func() error {
					n, rerr := coreService.SendRotationReminders(ctx)
					if rerr != nil {
						log.Printf("Rotation-reminder error: %v", rerr)
						return rerr
					}
					if n > 0 {
						log.Printf("Rotation reminders: sent %d notification(s)", n)
					}
					return nil
				}); err != nil {
					log.Printf("Rotation-reminder scheduler error: %v", err)
				}
			}
			runReminders() // run once on startup
			for {
				select {
				case <-ticker.C:
					runReminders()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Start the compliance-digest scheduler — opt-in. Periodically broadcasts a
	// posture + control-matrix summary to the configured notification channels
	// (Slack/Teams/webhook). Single-replica-gated (ADR-039) so the channel gets one
	// digest per tick. A no-op (logged) when no notification channel is configured.
	if cfg.ComplianceDigest.Enabled {
		interval := cfg.ComplianceDigest.GetInterval()
		log.Printf("Compliance-digest scheduler enabled: every %s", interval)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			runDigest := func() {
				if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockDigest, func() error {
					sent, derr := coreService.SendComplianceDigest(ctx)
					if derr != nil {
						log.Printf("Compliance-digest error: %v", derr)
						return derr
					}
					if !sent {
						log.Printf("Compliance digest: no notification channel configured; nothing sent")
					}
					return nil
				}); err != nil {
					log.Printf("Compliance-digest scheduler error: %v", err)
				}
			}
			runDigest() // run once on startup
			for {
				select {
				case <-ticker.C:
					runDigest()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Start the scheduled access-recertification scheduler (ISO 27001 A.5.18) —
	// opt-in. Finds projects overdue for review and either auto-opens a recert
	// campaign (when auto_open) or reminds the project's admins to; also nudges
	// admins of in-flight campaigns with pending items. A create/notify, not a
	// delete, so NOT legal-hold-gated. Single-replica-gated (ADR-039) so a campaign
	// is opened once per project per tick in HA.
	if cfg.Recertification.Enabled {
		interval := cfg.Recertification.GetInterval()
		cadence := cfg.Recertification.CadenceDays
		autoOpen := cfg.Recertification.AutoOpen
		log.Printf("Recertification scheduler enabled: every %s (cadence %dd, auto_open=%t)", interval, cadence, autoOpen)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			runRecert := func() {
				if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockRecertify, func() error {
					res, rerr := coreService.RunScheduledRecertification(ctx, cadence, autoOpen)
					if rerr != nil {
						log.Printf("Recertification error: %v", rerr)
						return rerr
					}
					if res.Opened > 0 || res.Reminded > 0 {
						log.Printf("Recertification: opened %d campaign(s), sent %d reminder(s)", res.Opened, res.Reminded)
					}
					return nil
				}); err != nil {
					log.Printf("Recertification scheduler error: %v", err)
				}
			}
			runRecert() // run once on startup
			for {
				select {
				case <-ticker.C:
					runRecert()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Start the scheduled compliance-evidence delivery (ISO 27001 / SOC 2) — opt-in.
	// Periodically generates the auditor evidence pack and delivers it to the
	// configured targets (a local directory and/or a webhook); each export emits an
	// audit event (forwarded to a SIEM if configured). Single-replica-gated (ADR-039)
	// so one pack is delivered per tick. Not legal-hold-gated (it only reads).
	if cfg.EvidenceDelivery.Enabled {
		if !cfg.EvidenceDelivery.HasTarget() {
			log.Printf("Evidence-delivery scheduler enabled but no target (output_dir or webhook) is configured; skipping")
		} else {
			outputDir := cfg.EvidenceDelivery.OutputDir
			interval := cfg.EvidenceDelivery.GetInterval()
			log.Printf("Evidence-delivery scheduler enabled: every %s (dir=%q, webhook=%t)", interval, outputDir, cfg.EvidenceDelivery.Webhook.Enabled)
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				runExport := func() {
					if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockEvidence, func() error {
						res, err := coreService.ExportComplianceEvidence(ctx, outputDir)
						if err != nil {
							log.Printf("Evidence-delivery error: %v", err)
							return err
						}
						log.Printf("Evidence pack exported: %d bytes → %v", res.Bytes, res.Targets)
						return nil
					}); err != nil {
						log.Printf("Evidence-delivery scheduler error: %v", err)
					}
				}
				runExport() // run once on startup
				for {
					select {
					case <-ticker.C:
						runExport()
					case <-ctx.Done():
						return
					}
				}
			}()
		}
	}

	// Start the audit-checkpoint scheduler (ADR-029) — opt-in. Periodically signs
	// the verified audit-chain head so tail-truncation / genesis re-seed becomes
	// detectable on-box. HA-gated so one replica writes per tick. Requires
	// encryption (the signing key is DEK-derived); skipped with a warning if not.
	if cfg.AuditCheckpoints.Enabled {
		if !coreService.AuditCheckpointsAvailable() {
			log.Printf("Audit-checkpoint scheduler requested but encryption is disabled (no signing key); skipping")
		} else {
			interval := cfg.AuditCheckpoints.GetInterval()
			log.Printf("Audit-checkpoint scheduler enabled: every %s", interval)
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				writeCheckpoint := func() {
					if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockAuditCkpt, func() error {
						cp, written, werr := coreService.WriteAuditCheckpoint(ctx)
						if werr != nil {
							log.Printf("Audit-checkpoint error: %v", werr)
							return werr
						}
						if written {
							log.Printf("Audit checkpoint written: #%d head=%d events=%d", cp.ID, cp.HeadID, cp.ChainedEvents)
						}
						return nil
					}); err != nil {
						log.Printf("Audit-checkpoint scheduler error: %v", err)
					}
				}
				writeCheckpoint() // run once on startup
				for {
					select {
					case <-ticker.C:
						writeCheckpoint()
					case <-ctx.Done():
						return
					}
				}
			}()
		}
	}

	// Start the JIT access-expiry sweeper — opt-in. Removes time-bound role grants
	// whose expiry has passed (auditing each as role.expired) and reclaims the rows.
	// Expired grants already stop authorizing immediately (the auth queries filter
	// on expiry); this just keeps the tables clean and writes the expiry audit trail.
	if cfg.JITAccessExpiry.Enabled {
		interval := cfg.JITAccessExpiry.GetInterval()
		log.Printf("JIT access-expiry sweeper enabled: every %s", interval)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			runSweep := func() {
				// A legal hold preserves the grant rows (the auth queries still deny
				// expired grants immediately, so blocking the sweep loses no security).
				if legalHoldBlocks("JIT access-expiry sweep") {
					return
				}
				// Single-replica-gated (ADR-039): one replica sweeps per tick.
				if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockJITExpiry, func() error {
					n, rerr := coreService.RemoveExpiredRoleGrants(ctx, time.Now())
					if rerr != nil {
						log.Printf("JIT access-expiry sweep error: %v", rerr)
						return rerr
					}
					if n > 0 {
						log.Printf("JIT access-expiry sweep removed %d expired grant(s)", n)
					}
					return nil
				}); err != nil {
					log.Printf("JIT access-expiry scheduler error: %v", err)
				}
			}
			runSweep() // run once on startup
			for {
				select {
				case <-ticker.C:
					runSweep()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Start the dynamic-secrets auto-revoke sweeper (ADR-035) — opt-in. Revokes
	// every active lease past its expiry so credentials don't outlive their TTL.
	if cfg.DynamicSecrets.SweepEnabled {
		interval := cfg.DynamicSecrets.GetSweepInterval()
		log.Printf("Dynamic-secrets auto-revoke sweeper enabled: every %s", interval)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			runSweep := func() {
				// Single-replica-gated (ADR-039): one replica revokes per tick, so
				// replicas don't storm the target DBs revoking the same leases.
				if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockDynamicSweep, func() error {
					n, rerr := coreService.RevokeExpiredLeases(ctx, time.Now())
					if rerr != nil {
						log.Printf("Dynamic-secrets sweep error: %v", rerr)
						return rerr
					}
					if n > 0 {
						log.Printf("Dynamic-secrets sweep revoked %d expired lease(s)", n)
					}
					return nil
				}); err != nil {
					log.Printf("Dynamic-secrets sweep scheduler error: %v", err)
				}
			}
			runSweep() // run once on startup
			for {
				select {
				case <-ticker.C:
					runSweep()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Prune expired login-attempt records hourly (ADR-040). Single-replica-gated;
	// always on (the limiter table needs bounded growth regardless of the purge
	// scheduler). Rows past the rate-limit window are never read again.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		runPrune := func() {
			if legalHoldBlocks("Login-attempt prune") {
				return
			}
			if _, err := coreService.Storage().WithSchedulerLock(ctx, schedLockLoginPrune, func() error {
				_, perr := coreService.PruneLoginAttempts(ctx)
				return perr
			}); err != nil {
				log.Printf("Login-attempt prune error: %v", err)
			}
		}
		runPrune() // run once on startup
		for {
			select {
			case <-ticker.C:
				runPrune()
			case <-ctx.Done():
				return
			}
		}
	}()

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

// oidcDiscovery is the subset of an OIDC discovery document we need.
type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// discoverOIDC fetches an issuer's /.well-known/openid-configuration.
func discoverOIDC(issuer string) (*oidcDiscovery, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u) // #nosec G107 -- issuer is operator-configured, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %s", resp.Status)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document is missing required endpoints")
	}
	return &d, nil
}

// ssoCompleteURL derives the SPA completion URL (<redirect origin>/auth/sso/complete)
// from a provider's redirect_url.
func ssoCompleteURL(redirectURL string) (string, error) {
	u, err := url.Parse(redirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid redirect_url %q", redirectURL)
	}
	return u.Scheme + "://" + u.Host + "/auth/sso/complete", nil
}

// buildSSOProviders discovers each configured provider and builds the resolved
// providers + a JWKS resolver over their issuers. A provider that is misconfigured
// or whose discovery fails is skipped with a warning (it must not block startup).
func buildSSOProviders(sso config.SSOConfig) (map[string]*core.SSOProvider, core.JWKSResolver, int) {
	providers := map[string]*core.SSOProvider{}
	jwksURIs := map[string]string{}
	for i := range sso.Providers {
		pc := sso.Providers[i]
		if pc.Name == "" || pc.Issuer == "" || pc.ClientID == "" || pc.RedirectURL == "" {
			log.Printf("SSO provider %q misconfigured (name/issuer/client_id/redirect_url required); skipping", pc.Name)
			continue
		}
		disc, err := discoverOIDC(pc.Issuer)
		if err != nil {
			log.Printf("SSO provider %q discovery failed: %v; skipping", pc.Name, err)
			continue
		}
		completeURL, err := ssoCompleteURL(pc.RedirectURL)
		if err != nil {
			log.Printf("SSO provider %q: %v; skipping", pc.Name, err)
			continue
		}
		scopes := pc.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		providers[pc.Name] = &core.SSOProvider{
			Name:     pc.Name,
			Issuer:   pc.Issuer,
			ClientID: pc.ClientID,
			OAuth: &oauth2.Config{
				ClientID:     pc.ClientID,
				ClientSecret: pc.GetClientSecret(),
				Endpoint:     oauth2.Endpoint{AuthURL: disc.AuthorizationEndpoint, TokenURL: disc.TokenEndpoint},
				RedirectURL:  pc.RedirectURL,
				Scopes:       scopes,
			},
			CompleteURL:   completeURL,
			AutoProvision: pc.AutoProvision,
			DefaultRole:   pc.DefaultRole,
		}
		jwksURIs[pc.Issuer] = disc.JWKSURI
	}
	if len(providers) == 0 {
		return nil, nil, 0
	}
	resolver, err := core.NewHTTPJWKSResolver(jwksURIs)
	if err != nil {
		log.Printf("SSO disabled: jwks resolver init failed: %v", err)
		return nil, nil, 0
	}
	return providers, resolver, len(providers)
}
