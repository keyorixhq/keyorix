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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/evidencesink"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/notifychan"
	"github.com/keyorixhq/keyorix/internal/rotation"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/startup"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/keyorixhq/keyorix/server/grpc"
	httpServer "github.com/keyorixhq/keyorix/server/http"
	"github.com/keyorixhq/keyorix/server/middleware"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
)

func main() { // NOSONAR -- cognitive complexity 22, suppress go:S3776
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Schema/sanity validation (ports, TLS cert/key presence, storage DSN/path) — always
	// enforced, independent of any security flag: a malformed config should never boot.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration is invalid: %v", err)
	}

	// Run the file-permission / encryption-key / database-reachability checks that were
	// previously reachable ONLY via the manual `keyorix system validate` CLI subcommand
	// (#330), despite official docs and that command's own help text claiming they run
	// automatically on every boot.
	if err := runStartupValidation(cfg); err != nil {
		log.Fatalf("startup validation: %v", err)
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

	// Refuse (or loudly warn about) serving bearer tokens + secret values in cleartext.
	if err := checkTransportTLSPosture(cfg); err != nil {
		log.Fatalf("transport security: %v", err)
	}

	// Refuse (or warn) when key material on disk is readable beyond its owner.
	if err := enforceKeyFilePermissions(cfg); err != nil {
		log.Fatalf("key file security: %v", err)
	}

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
	schedLockExpiryRmdr   int64 = 0x4B455953_45585052 // "KEYSEXPR"
	schedLockCertExpiry   int64 = 0x4B455953_43455254 // "KEYSCERT"
	schedLockAutoRotate   int64 = 0x4B455953_4155544F // "KEYSAUTO"
	schedLockAuditCkpt    int64 = 0x4B455953_41434B50 // "KEYSACKP"
	schedLockJITExpiry    int64 = 0x4B455953_4A495445 // "KEYSJITE"
	schedLockRetention    int64 = 0x4B455953_52455445 // "KEYSRETE"
	schedLockEvidence     int64 = 0x4B455953_45564944 // "KEYSEVID"
	schedLockRecertify    int64 = 0x4B455953_52454354 // "KEYSRECT"
	schedLockDigest       int64 = 0x4B455953_44494753 // "KEYSDIGS"
	schedLockLicenseExp   int64 = 0x4B455953_4C494345 // "KEYSLICE"
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
	// Hold the exclusive DEK lock for the server's whole lifetime (released by
	// Shutdown on graceful stop) so DEK rotation — a separate CLI process — can
	// never promote a new DEK while this server still has the old one cached in
	// memory (#92). Refuses to start if another live holder (another server
	// instance, or an in-progress rotation) already has it.
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return nil, fmt.Errorf("failed to acquire the encryption key lock: %w", err)
	}

	kekSource := providerType
	if kekSource == "" {
		kekSource = "password"
	}
	log.Printf("Encryption initialised — KEK source: %s, key version: %s", kekSource, svc.GetKeyVersion())
	return svc, nil
}

// loadCertPool reads a PEM bundle from path and returns a cert pool of its
// certificates (the TSA trust anchor for verifying checkpoint anchors).
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) // #nosec G304 -- operator-configured trusted CA bundle path
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

func initializeCoreService(cfg *config.Config) (*core.KeyorixCore, *encryption.Service, error) { // NOSONAR -- cognitive complexity 159, suppress go:S3776
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

	// Top up the canonical RBAC permission catalog (ADR-044): adds any permission
	// introduced in a later release to an already-initialised install, granting it to
	// its baseline roles. No-op pre-bootstrap and best-effort (never blocks startup).
	if err := coreService.ReconcileRBACPermissions(context.Background()); err != nil {
		log.Printf("RBAC permission reconciliation: %v (continuing)", err)
	}

	// Wire the bootstrap token that gates POST /system/init. Prefer an operator-set
	// KEYORIX_BOOTSTRAP_TOKEN (for automation); otherwise generate one and, while the
	// install is still empty, log it so the operator can complete first-boot init. This
	// closes the unauthenticated, first-caller-wins admin-claim race on a fresh, reachable
	// instance.
	bootstrapToken := strings.TrimSpace(os.Getenv("KEYORIX_BOOTSTRAP_TOKEN"))
	bootstrapTokenGenerated := false
	if bootstrapToken == "" {
		if t, gerr := core.GenerateBootstrapToken(); gerr == nil {
			bootstrapToken, bootstrapTokenGenerated = t, true
		} else {
			log.Printf("failed to generate a bootstrap token: %v (API system-init will be disabled)", gerr)
		}
	}
	coreService.SetBootstrapToken(bootstrapToken)
	// Let core token-revocation paths (e.g. revoking PATs on a password change) evict the
	// HTTP auth cache immediately, rather than waiting out the positive-cache TTL.
	coreService.SetTokenCacheInvalidator(middleware.InvalidateTokenCacheByHash)
	if needs, berr := coreService.SystemNeedsBootstrap(context.Background()); berr == nil && needs && bootstrapToken != "" {
		if bootstrapTokenGenerated {
			log.Printf("system not initialised — run `keyorix system init` with this one-time bootstrap token (set KEYORIX_BOOTSTRAP_TOKEN to pin your own):\n    BOOTSTRAP TOKEN: %s", bootstrapToken)
		} else {
			log.Printf("system not initialised — run `keyorix system init` with the configured KEYORIX_BOOTSTRAP_TOKEN")
		}
	}

	if encSvc != nil {
		// Wire the initialised encryption service for secret VALUES at rest (ADR-004
		// envelope encryption). Without this, storage.encryption.enabled would derive a
		// KEK but never actually encrypt any secret value — every secret would persist as
		// plaintext. Fail closed immediately after wiring: if encryption was configured
		// but did not actually engage, refuse to start rather than silently store
		// plaintext in a secrets manager.
		coreService.SetSecretValueEncryptor(encSvc)
		if !coreService.SecretValueEncryptionActive() {
			return nil, nil, fmt.Errorf("storage.encryption is enabled but secret-value encryption did not engage (encryptor not initialised) — refusing to start to avoid storing secrets in plaintext")
		}
		// Wire the same initialised service for reversibly-encrypted auth secrets (the
		// TOTP MFA secret, which cannot be hashed).
		coreService.SetAuthEncryptor(encSvc)
		// Derive the audit-checkpoint signing key from the DEK (ADR-029) so signed
		// checkpoints — and on-box truncation detection — are available. Unavailable
		// when encryption is off (no DEK).
		if key, keyVer, ok := encSvc.AuditCheckpointKey(); ok {
			coreService.SetAuditCheckpointKey(key, keyVer)
			// Restore the in-memory anti-rollback watermark from the persisted high-water
			// mark so a process restart cannot reset it to zero (ADR-029).
			coreService.SeedAuditWatermark(context.Background())
		}
		// Derive the evidence-pack signing key from the KEK (not the DEK — #268, so a
		// routine DEK rotation does not invalidate previously-signed packs) so
		// scheduled evidence exports are signed (and verifiable). Unavailable when
		// encryption is off.
		if key, keyVer, ok := encSvc.EvidenceSignKey(); ok {
			coreService.SetEvidenceSignKey(key, keyVer)
		}
	}

	// Wire external-notary anchoring of audit checkpoints if enabled (ADR-029): each
	// written checkpoint gets an independent RFC 3161 timestamp the server cannot
	// forge. Anchoring is best-effort and only meaningful when checkpoints are
	// written (which requires encryption).
	if cn := cfg.Audit.CheckpointNotary; cn.Enabled {
		if cn.URL == "" {
			log.Printf("Audit checkpoint notary enabled but no url set; skipping external anchoring")
		} else {
			coreService.SetCheckpointNotary(notary.NewRFC3161(cn.URL, cn.GetTimeout()))
			// Load the TSA trust anchor used to VERIFY stored anchors. Without it,
			// anchoring still records tokens but verification fails closed (an
			// untrusted issuer must not be trusted).
			if cn.CACertPath == "" {
				log.Printf("Audit checkpoint external anchoring enabled (rfc3161, url=%s) — WARNING: no ca_cert_path set, stored anchors cannot be verified", cn.URL)
			} else if roots, err := loadCertPool(cn.CACertPath); err != nil {
				log.Printf("Audit checkpoint notary: failed to load ca_cert_path %q (%v) — anchors cannot be verified", cn.CACertPath, err)
			} else {
				coreService.SetCheckpointAnchorRoots(roots)
				log.Printf("Audit checkpoint external anchoring enabled (rfc3161, url=%s, timeout=%s, trust anchor=%s)", cn.URL, cn.GetTimeout(), cn.CACertPath)
			}
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

	// Apply the optional secret-value quality gate (reject weak/placeholder values).
	if svp := cfg.SecretValuePolicy; svp.Enabled {
		coreService.SetSecretValuePolicy(core.SecretValuePolicy{
			Enabled:       true,
			MinLength:     svp.MinLength,
			RejectCommon:  svp.RejectCommon,
			ExtraDenylist: svp.ExtraDenylist,
		})
		log.Printf("Secret-value policy enabled (min_length=%d, reject_common=%t, denylist=%d)",
			svp.MinLength, svp.RejectCommon, len(svp.ExtraDenylist))
	}

	// Apply the optional secret naming convention (regex / max-length on names).
	if snp := cfg.SecretNamePolicy; snp.Enabled {
		if err := coreService.SetSecretNamePolicy(core.SecretNamePolicy{
			Enabled:   true,
			Pattern:   snp.Pattern,
			MaxLength: snp.MaxLength,
		}); err != nil {
			log.Fatalf("Invalid secret_name_policy: %v", err)
		}
		log.Printf("Secret-name policy enabled (pattern=%q, max_length=%d)", snp.Pattern, snp.MaxLength)
	}

	// Apply per-account login lockout (brute-force protection, distinct from and
	// complementary to the per-IP rate limiter, which distributed guessing can evade).
	// Enabled BY DEFAULT — a secrets-manager login must resist online guessing out of
	// the box; set login_lockout.disabled to opt out.
	if ll := cfg.Security.LoginLockout; !ll.Disabled {
		coreService.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
			Enabled:      true,
			MaxAttempts:  ll.GetMaxAttempts(),
			Window:       ll.GetWindow(),
			BaseCooldown: ll.GetBaseCooldown(),
			MaxCooldown:  ll.GetMaxCooldown(),
		})
		log.Printf("Per-account login lockout enabled (max_attempts=%d, window=%s, base_cooldown=%s, max_cooldown=%s)",
			ll.GetMaxAttempts(), ll.GetWindow(), ll.GetBaseCooldown(), ll.GetMaxCooldown())
	} else {
		log.Printf("WARNING: per-account login lockout is DISABLED — only the per-IP rate limiter throttles password guessing, which distributed/botnet guessing against a single account can evade")
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
			SpoolDir:           sc.SpoolDir,
		})
		if ferr != nil {
			return nil, nil, fmt.Errorf("failed to init SIEM audit forwarder: %w", ferr)
		}
		coreService.SetAuditForwarder(forwarder)
		log.Printf("SIEM audit forwarding enabled (provider=%s)", sc.Provider)
	}

	// Wire external notification channels if configured.
	//
	// #391: two distinct fan-out sets are built, not one. broadcastSinks (every
	// enabled channel) backs the deployment-wide, aggregate notifications
	// (compliance digest, auto-rotation-failure summary) — those are genuinely
	// relevant to the whole deployment's ops audience. recipientSinks (only
	// channels that can address a single user — currently email) backs every
	// per-user/per-project notification (secret shared, share revoked, ownership
	// transferred, access requested, anomaly alert, break-glass activation, …).
	// Slack/Teams/webhook are deliberately excluded from recipientSinks: they are
	// one fixed destination an operator configures, with no per-user chat-identity
	// mapping in this codebase to target a specific recipient, so routing a
	// per-user event there would broadcast it to everyone with channel visibility
	// regardless of project membership or secret access. See
	// internal/core/notifications.go and internal/core/service.go.
	var broadcastSinks []core.NotificationSink
	var recipientSinks []core.NotificationSink
	if wc := cfg.Notifications.Webhook; wc.Enabled {
		sink, werr := notifychan.NewWebhook(notifychan.WebhookConfig{
			Endpoint:                  wc.Endpoint,
			Token:                     wc.GetToken(),
			InsecureSkipVerify:        wc.InsecureSkipVerify,
			AllowPrivateNetworkTarget: wc.AllowPrivateNetworkTarget,
			SigningSecret:             wc.GetSigningSecret(),
		})
		if werr != nil {
			return nil, nil, fmt.Errorf("failed to init notification webhook channel: %w", werr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification webhook channel enabled (endpoint=%s)", wc.Endpoint)
	}
	if ec := cfg.Notifications.Email; ec.Enabled {
		sink, eerr := notifychan.NewEmail(notifychan.EmailConfig{
			Host:        ec.Host,
			Port:        ec.Port,
			Username:    ec.Username,
			Password:    ec.GetPassword(),
			From:        ec.From,
			TLS:         ec.TLS,
			BroadcastTo: ec.BroadcastTo,
		})
		if eerr != nil {
			return nil, nil, fmt.Errorf("failed to init notification email channel: %w", eerr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		recipientSinks = append(recipientSinks, sink)
		log.Printf("Notification email channel enabled (host=%s)", ec.Host)
	}
	if cfg.Notifications.Slack.Enabled {
		sink, serr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatSlack, WebhookURL: cfg.Notifications.GetSlackWebhookURL()})
		if serr != nil {
			return nil, nil, fmt.Errorf("failed to init Slack notification channel: %w", serr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification Slack channel enabled")
	}
	if cfg.Notifications.Teams.Enabled {
		sink, terr := notifychan.NewChat(notifychan.ChatConfig{Kind: notifychan.ChatTeams, WebhookURL: cfg.Notifications.GetTeamsWebhookURL()})
		if terr != nil {
			return nil, nil, fmt.Errorf("failed to init Teams notification channel: %w", terr)
		}
		broadcastSinks = append(broadcastSinks, sink)
		log.Printf("Notification Teams channel enabled")
	}
	// #221: email-only, with no email.broadcast_to configured, has no destination
	// for a deployment-wide broadcast (compliance digest, auto-rotation-failure
	// alert) to route to — it will keep no-op'ing every time one fires. Warn at
	// startup rather than let an operator discover it only from the (also newly
	// added, #221) dropped-delivery metric/log after the fact.
	if cfg.Notifications.Email.Enabled && cfg.Notifications.Email.BroadcastTo == "" &&
		!cfg.Notifications.Webhook.Enabled && !cfg.Notifications.Slack.Enabled && !cfg.Notifications.Teams.Enabled {
		log.Printf("WARNING: notifications.email is the only enabled notification channel and notifications.email.broadcast_to is not set — the compliance digest and auto-rotation-failure alerts have no destination to broadcast to and will silently no-op every time they fire; set notifications.email.broadcast_to to an admin/ops address to receive them")
	}
	if sink := notifychan.NewMulti(broadcastSinks...); sink != nil {
		coreService.SetNotificationSink(sink)
	}
	if sink := notifychan.NewMulti(recipientSinks...); sink != nil {
		coreService.SetRecipientNotificationSink(sink)
	}

	// Wire Keyorix Connect (ADR-043) read-through federation if enabled.
	if cc := cfg.Connect; cc.Enabled && len(cc.Connectors) > 0 {
		var connectors []connect.Connector
		for _, cn := range cc.Connectors {
			switch cn.Type {
			case "aws-secrets-manager":
				connectors = append(connectors, connect.NewAWSSecretsManagerConnector(cn.Name, cn.Region, cn.AllowedRefs))
			case "gcp-secret-manager":
				if cn.ProjectID == "" {
					log.Printf("Keyorix Connect: gcp-secret-manager connector %q has no project_id configured — reads can reach ANY GCP project the ambient identity can access, relying solely on allowed_refs to scope reach; set project_id to pin the connector to one project (#431)", cn.Name)
				}
				connectors = append(connectors, connect.NewGCPSecretManagerConnector(cn.Name, cn.ProjectID, cn.AllowedRefs))
			case "azure-key-vault":
				connectors = append(connectors, connect.NewAzureKeyVaultConnector(cn.Name, cn.Address, cn.AllowedRefs))
			case "vault":
				tokenEnv := cn.TokenEnv
				if tokenEnv == "" {
					tokenEnv = "VAULT_TOKEN"
				}
				token := os.Getenv(tokenEnv)
				if token == "" {
					log.Printf("Keyorix Connect: vault connector %q has no token (%s unset) — reads will fail", cn.Name, tokenEnv)
				}
				connectors = append(connectors, connect.NewVaultConnector(cn.Name, cn.Address, token, cn.AllowedRefs))
			default:
				log.Printf("Keyorix Connect: skipping connector %q with unknown type %q", cn.Name, cn.Type)
			}
		}
		if len(connectors) > 0 {
			coreService.SetConnectManager(connect.NewManager(connectors))
			log.Printf("Keyorix Connect enabled (%d connector(s))", len(connectors))
		}
	}

	// Wire backend rotation executors (ADR-047) — upstream systems whose credentials the
	// auto-rotation flow can rotate in place. Admin DSNs come from the environment, never
	// the config file.
	if len(cfg.AutoRotation.Backends) > 0 {
		var execs []rotation.Executor
		for _, b := range cfg.AutoRotation.Backends {
			switch b.Type {
			case "postgresql":
				// Fail closed: a backend runs privileged DDL with an admin DSN, so an
				// explicit allow-list is required — refuse to register an unbounded one.
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				dsn := b.GetDSN()
				if dsn == "" {
					log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
				}
				execs = append(execs, rotation.NewPostgresExecutor(b.Name, dsn, b.AllowedRefs))
			case "mysql":
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				dsn := b.GetDSN()
				if dsn == "" {
					log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
				}
				execs = append(execs, rotation.NewMySQLExecutor(b.Name, dsn, b.AllowedRefs))
			case "mongodb":
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				dsn := b.GetDSN()
				if dsn == "" {
					log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
				}
				execs = append(execs, rotation.NewMongoExecutor(b.Name, dsn, b.AllowedRefs))
			case "redis":
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				dsn := b.GetDSN()
				if dsn == "" {
					log.Printf("Rotation backend %q has no admin DSN (%s unset) — rotations will fail", b.Name, b.DSNEnv)
				}
				execs = append(execs, rotation.NewRedisExecutor(b.Name, dsn, b.AllowedRefs))
			case "aws-iam":
				// Generate-upstream backend: AWS mints the new key; credentials come from
				// the ambient AWS chain (no DSN). Still fail-closed on allowed_refs.
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				execs = append(execs, rotation.NewAWSIAMExecutor(b.Name, b.Region, b.AllowedRefs))
			case "gcp-service-account":
				// Generate-upstream backend: GCP mints the key; credentials come from
				// Application Default Credentials (no DSN). Fail-closed on allowed_refs.
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				execs = append(execs, rotation.NewGCPServiceAccountKeyExecutor(b.Name, b.AllowedRefs))
			case "azure-app":
				// Generate-upstream backend: Azure mints the client secret via Graph;
				// credentials come from the ambient Azure chain (no DSN). Fail-closed.
				if len(b.AllowedRefs) == 0 {
					log.Printf("Rotation backend %q has no allowed_refs — refusing to register (fail-closed; set allowed_refs)", b.Name)
					continue
				}
				execs = append(execs, rotation.NewAzureAppSecretExecutor(b.Name, b.AllowedRefs))
			default:
				log.Printf("Rotation backend %q: unknown type %q, skipping", b.Name, b.Type)
			}
		}
		if len(execs) > 0 {
			coreService.SetRotationManager(rotation.NewManager(execs))
			log.Printf("Backend rotation executors enabled (%d backend(s))", len(execs))
		}
	}

	// Wire any off-box evidence targets (webhook and/or S3-compatible object store),
	// so the scheduled evidence pack is delivered off-box in addition to (or instead
	// of) a local dir. When both are configured the pack fans out to both.
	var evidenceTargets []evidencesink.Forwarder
	if ew := cfg.EvidenceDelivery.Webhook; ew.Enabled {
		fwd, ferr := evidencesink.NewWebhook(evidencesink.WebhookConfig{
			Endpoint:                  ew.Endpoint,
			Token:                     ew.GetToken(),
			InsecureSkipVerify:        ew.InsecureSkipVerify,
			AllowPrivateNetworkTarget: ew.AllowPrivateNetworkTarget,
		})
		if ferr != nil {
			return nil, nil, fmt.Errorf("failed to init evidence webhook target: %w", ferr)
		}
		evidenceTargets = append(evidenceTargets, fwd)
		log.Printf("Evidence webhook target enabled (endpoint=%s)", ew.Endpoint)
	}
	if os := cfg.EvidenceDelivery.ObjectStore; os.Enabled {
		sink, oerr := evidencesink.NewObjectStore(context.Background(), evidencesink.ObjectStoreConfig{
			Bucket:         os.Bucket,
			Prefix:         os.Prefix,
			Region:         os.Region,
			Endpoint:       os.Endpoint,
			UsePathStyle:   os.UsePathStyle,
			LockMode:       os.LockMode,
			LockRetainDays: os.LockRetainDays,
			LegalHold:      os.LegalHold,
		})
		if oerr != nil {
			return nil, nil, fmt.Errorf("failed to init evidence object-store target: %w", oerr)
		}
		evidenceTargets = append(evidenceTargets, sink)
		log.Printf("Evidence object-store target enabled (bucket=%s, prefix=%q)", os.Bucket, os.Prefix)
	}
	switch len(evidenceTargets) {
	case 0:
	case 1:
		coreService.SetEvidenceForwarder(evidenceTargets[0])
	default:
		coreService.SetEvidenceForwarder(evidencesink.NewMulti(evidenceTargets...))
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
	// Install-wide hard ceiling on any dynamic-secret lease's TTL (#97); enforced on
	// top of each config's own optional (default-unbounded) MaxTTLSeconds.
	coreService.SetDynamicMaxLeaseTTL(cfg.DynamicSecrets.GetMaxLeaseTTL())

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

	// Wire the "restricted" classification read-time gate (#128's product
	// decision); false (the default) leaves the label purely informational,
	// identical to every deployment's behaviour today.
	coreService.SetClassificationRestrictedRequiresApproval(cfg.Classification.RestrictedRequiresApproval)
	if cfg.Classification.RestrictedRequiresApproval {
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires an approved, secret-scoped access request")
	}
	coreService.SetClassificationRestrictedRequiresPermission(cfg.Classification.RestrictedRequiresPermission)
	if cfg.Classification.RestrictedRequiresPermission {
		log.Printf("Classification enforcement enabled: reading a \"restricted\" secret's value now requires the %q permission at the project scope", core.PermSecretReadRestricted)
	}

	// Wire the configured data-retention windows (A.5.33) so the compliance posture
	// reports them; the scheduler below drives the actual purge. Audited (#160) so a
	// shortened window is on the record, not just its eventual purge counts.
	coreService.SetRetentionPolicy(context.Background(), core.RetentionPolicy{
		AnomalyAlertsDays:               cfg.DataRetention.AnomalyAlertsDays,
		AnomalyAlertsUnackedCeilingDays: cfg.DataRetention.AnomalyAlertsUnackedCeilingDays,
		ClosedAccessReviewsDays:         cfg.DataRetention.ClosedAccessReviewsDays,
		BreakGlassDays:                  cfg.DataRetention.BreakGlassDays,
		ResolvedAccessRequestsDays:      cfg.DataRetention.ResolvedAccessRequestsDays,
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
			trusted = append(trusted, core.OIDCTrustedIssuer{
				Issuer: iss.Issuer, Audiences: iss.Audiences,
				MaxTokenAge: time.Duration(iss.MaxTokenAgeSeconds) * time.Second,
			})
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

	// Wire the offline-license feature gate (ADR-065). Fail-safe throughout: a missing,
	// unreadable, or invalid license never blocks startup — the gate degrades to the
	// community baseline. A non-release build embeds no license key, so any token evaluates
	// to the baseline anyway. The gate evaluates the token freshly on every call.
	reg, terr := trust.DefaultRegistry()
	if terr != nil {
		// A malformed embedded key spec is a build/release misconfiguration; surface it,
		// but still run (no trusted keys → baseline).
		log.Printf("WARNING: trusted-key registry: %v (running community baseline)", terr)
		reg = nil
	}
	var token string
	if p := strings.TrimSpace(cfg.License.Path); p != "" {
		b, rerr := os.ReadFile(p) // #nosec G304 -- operator-configured license path
		if rerr != nil {
			log.Printf("WARNING: license file %q unreadable: %v (running community baseline)", p, rerr)
		} else {
			token = strings.TrimSpace(string(b))
		}
	}
	gate := license.NewGate(token, reg, cfg.License.DeploymentID, cfg.LicenseGrace())
	coreService.SetLicenseGate(gate)
	st := gate.Status()
	if st.Grants() {
		log.Printf("License: %s (%s) — state %s", st.Licensee, st.Plan, st.State)
	} else {
		log.Printf("License: community baseline (state %s)", st.State)
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

func startHTTPServer(ctx context.Context, cfg *config.Config) error { // NOSONAR -- cognitive complexity 188, suppress go:S3776
	// Initialize core service (and encryption if enabled)
	coreService, encSvc, err := initializeCoreService(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize core service: %w", err)
	}

	// Ensure KEK is wiped from memory on shutdown
	if encSvc != nil {
		defer encSvc.Shutdown()
	}

	// Record the evaluated license state once at startup (ADR-065), so the entitlement
	// (and any degrade reason) is on the audit record.
	coreService.AuditLicenseState(ctx)

	// Create HTTP router
	router, err := httpServer.NewRouter(cfg, coreService)
	if err != nil {
		return fmt.Errorf("failed to create HTTP router: %w", err)
	}

	// Start anomaly detection scheduler. Single-replica-gated (ADR-039) so N
	// replicas don't emit N copies of each alert. When anomaly_alerts is enabled,
	// each detection pass is followed by an alerting pass that pushes newly detected
	// anomalies to project admins + the audit/SIEM pipeline.
	{
		detector := core.NewAnomalyDetector(coreService.Storage())
		if bh := cfg.AnomalyAlerts.BusinessHours; bh.Timezone != "" || bh.OffHoursStart != 0 || bh.OffHoursEnd != 0 {
			tzLabel := bh.Timezone
			if tzLabel == "" {
				tzLabel = "UTC"
			}
			if err := detector.SetBusinessHours(ctx, bh.Timezone, bh.OffHoursStart, bh.OffHoursEnd); err != nil {
				// Misconfigured timezone: keep the safe UTC default rather than fail startup.
				log.Printf("Anomaly off-hours config ignored (%v); using UTC 22:00–06:00", err)
			} else {
				log.Printf("Anomaly off-hours rule configured (timezone %s)", tzLabel)
			}
		}
		if mlc := cfg.AnomalyAlerts.ML; mlc.Enabled {
			detector.SetMLConfig(core.MLConfig{
				Enabled:    true,
				Threshold:  mlc.Threshold,
				NumTrees:   mlc.NumTrees,
				SampleSize: mlc.SampleSize,
				Seed:       mlc.Seed,
			})
			log.Printf("Anomaly ML (Isolation Forest) detection enabled")
		}
		alertsEnabled := cfg.AnomalyAlerts.Enabled
		interval := cfg.AnomalyAlerts.GetInterval()
		// Scan a window at least as long as the cadence, so a longer schedule doesn't
		// leave the time between passes unexamined (floored at 1h inside SetLookback).
		detector.SetLookback(interval)
		detector.SetBaselineQuarantine(cfg.AnomalyAlerts.GetBaselineQuarantine())
		// Overlay the DB-persisted anomaly config on top of the file-based defaults.
		// Best-effort at startup: a storage error keeps the file-based settings rather
		// than aborting startup or leaving the detector unconfigured.
		if err := coreService.ApplyAnomalyConfig(ctx, detector); err != nil {
			log.Printf("Anomaly: could not load persisted config (%v); using file-based defaults", err)
		} else {
			log.Printf("Anomaly: persisted runtime config applied")
		}
		if alertsEnabled {
			log.Printf("Anomaly alerting enabled: scan + alert every %s", interval)
		}
		runScheduler(ctx, "anomaly_detection", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAnomaly, "Anomaly detection", func() error {
				// Hotload: re-apply the persisted config before each pass so an operator's
				// runtime change takes effect without a restart. Best-effort: a transient
				// storage failure here is logged but does not skip the detection pass.
				if err := coreService.ApplyAnomalyConfig(ctx, detector); err != nil {
					log.Printf("Anomaly: failed to reload persisted config (%v); running with prior settings", err)
				}
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
			})
		})
	}

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
		runScheduler(ctx, "retention_purge", interval, func() middleware.SchedulerOutcome {
			if legalHoldBlocks("Retention purge") {
				return middleware.SchedulerSkipped
			}
			// Single-replica-gated (ADR-039): only one replica runs the purge.
			return lockedRun(ctx, coreService.Storage(), schedLockPurge, "Retention purge", func() error {
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
			})
		})
	}

	// Start the data-retention scheduler (ISO A.5.33 / GDPR / DORA) — opt-in.
	// Hard-deletes compliance records (anomaly alerts, closed campaigns, the
	// break-glass register, resolved access requests) past their per-type window.
	// Legal-hold-gated and single-replica-gated (ADR-039); audit events are never
	// touched (append-only). Runs only when at least one window is configured.
	if cfg.DataRetention.Enabled {
		policy := core.RetentionPolicy{
			AnomalyAlertsDays:               cfg.DataRetention.AnomalyAlertsDays,
			AnomalyAlertsUnackedCeilingDays: cfg.DataRetention.AnomalyAlertsUnackedCeilingDays,
			ClosedAccessReviewsDays:         cfg.DataRetention.ClosedAccessReviewsDays,
			BreakGlassDays:                  cfg.DataRetention.BreakGlassDays,
			ResolvedAccessRequestsDays:      cfg.DataRetention.ResolvedAccessRequestsDays,
		}
		if !policy.Configured() {
			log.Printf("Data-retention scheduler enabled but no retention windows are set; nothing to purge")
		} else {
			interval := cfg.DataRetention.GetInterval()
			log.Printf("Data-retention scheduler enabled: every %s (anomaly_alerts=%dd, anomaly_alerts_unacked_ceiling=%dd, closed_reviews=%dd, break_glass=%dd, access_requests=%dd; 0=keep)",
				interval, policy.AnomalyAlertsDays, policy.AnomalyAlertsUnackedCeilingDays, policy.ClosedAccessReviewsDays, policy.BreakGlassDays, policy.ResolvedAccessRequestsDays)
			runScheduler(ctx, "data_retention", interval, func() middleware.SchedulerOutcome {
				if legalHoldBlocks("Data-retention purge") {
					return middleware.SchedulerSkipped
				}
				return lockedRun(ctx, coreService.Storage(), schedLockRetention, "Data-retention", func() error {
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
				})
			})
		}
	}

	// Start the rotation-reminder scheduler — opt-in. Notifies project admins of
	// secrets overdue/approaching their rotation deadline (proactive rotation
	// hygiene; a NIS2/ISO control). Single-replica-gated (ADR-039) so admins aren't
	// notified N times in an HA deployment.
	if cfg.RotationReminders.Enabled {
		interval := cfg.RotationReminders.GetInterval()
		log.Printf("Rotation-reminder scheduler enabled: every %s", interval)
		runScheduler(ctx, "rotation_reminder", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockRotationRmdr, "Rotation-reminder", func() error {
				n, rerr := coreService.SendRotationReminders(ctx)
				if rerr != nil {
					log.Printf("Rotation-reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Rotation reminders: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the secret-expiry reminder scheduler — opt-in. Notifies project admins of
	// secrets that have expired or are approaching expiration, so a secret never silently
	// lapses. Single-replica-gated (ADR-039) so admins aren't notified N times in HA.
	if cfg.ExpiryReminders.Enabled {
		interval := cfg.ExpiryReminders.GetInterval()
		leadDays := cfg.ExpiryReminders.LeadDays
		log.Printf("Expiry-reminder scheduler enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "expiry_reminder", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockExpiryRmdr, "Expiry-reminder", func() error {
				n, rerr := coreService.SendExpiryReminders(ctx, leadDays)
				if rerr != nil {
					log.Printf("Expiry-reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Expiry reminders: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the certificate-expiry scan — opt-in (ADR-055). Parses certificate-typed
	// secrets and notifies project admins of certs expired/expiring within the window.
	// Single-replica-gated (ADR-039).
	if cfg.CertificateExpiry.Enabled {
		interval := cfg.CertificateExpiry.GetInterval()
		leadDays := cfg.CertificateExpiry.LeadDays
		log.Printf("Certificate-expiry scan enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "certificate_expiry", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockCertExpiry, "Certificate-expiry", func() error {
				n, rerr := coreService.ScanCertificateExpiry(ctx, leadDays)
				if rerr != nil {
					log.Printf("Certificate-expiry scan error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Certificate-expiry scan: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the license-expiry reminder — opt-in (ADR-065 Phase 2c). Notifies install-wide
	// admins when the offline commercial license is approaching or past expiry, so a lapse
	// (which silently disables commercial features) doesn't go unnoticed. Single-replica-
	// gated (ADR-039) so N replicas don't each notify.
	if cfg.LicenseExpiry.Enabled {
		interval := cfg.LicenseExpiry.GetInterval()
		leadDays := cfg.LicenseExpiry.LeadDays
		log.Printf("License-expiry reminder enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "license_expiry", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockLicenseExp, "License-expiry", func() error {
				n, rerr := coreService.ScanLicenseExpiry(ctx, leadDays)
				if rerr != nil {
					log.Printf("License-expiry reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("License-expiry reminder: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}

	// Start the automated-rotation scheduler — opt-in (ADR-046). Rotates auto-rotate-
	// enabled secrets that are overdue under an active policy, regenerating their value.
	// Single-replica-gated (ADR-039) so a secret rotates once per tick in an HA
	// deployment.
	if cfg.AutoRotation.Enabled {
		interval := cfg.AutoRotation.GetInterval()
		log.Printf("Auto-rotation scheduler enabled: every %s", interval)
		runScheduler(ctx, "auto_rotation", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAutoRotate, "Auto-rotation", func() error {
				n, rerr := coreService.RunAutoRotation(ctx)
				if rerr != nil {
					log.Printf("Auto-rotation error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Auto-rotation: rotated %d secret(s)", n)
				}
				return nil
			})
		})
	}

	// Start the compliance-digest scheduler — opt-in. Periodically broadcasts a
	// posture + control-matrix summary to the configured notification channels
	// (Slack/Teams/webhook). Single-replica-gated (ADR-039) so the channel gets one
	// digest per tick. A no-op (logged) when no notification channel is configured.
	if cfg.ComplianceDigest.Enabled {
		interval := cfg.ComplianceDigest.GetInterval()
		log.Printf("Compliance-digest scheduler enabled: every %s", interval)
		runScheduler(ctx, "compliance_digest", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockDigest, "Compliance-digest", func() error {
				sent, derr := coreService.SendComplianceDigest(ctx)
				if derr != nil {
					log.Printf("Compliance-digest error: %v", derr)
					return derr
				}
				if !sent {
					log.Printf("Compliance digest: no notification channel configured; nothing sent")
				}
				return nil
			})
		})
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
		runScheduler(ctx, "recertification", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockRecertify, "Recertification", func() error {
				res, rerr := coreService.RunScheduledRecertification(ctx, cadence, autoOpen)
				if rerr != nil {
					log.Printf("Recertification error: %v", rerr)
					return rerr
				}
				if res.Opened > 0 || res.Reminded > 0 {
					log.Printf("Recertification: opened %d campaign(s), sent %d reminder(s)", res.Opened, res.Reminded)
				}
				return nil
			})
		})
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
			runScheduler(ctx, "evidence_delivery", interval, func() middleware.SchedulerOutcome {
				return lockedRun(ctx, coreService.Storage(), schedLockEvidence, "Evidence-delivery", func() error {
					res, err := coreService.ExportComplianceEvidence(ctx, outputDir)
					if err != nil {
						log.Printf("Evidence-delivery error: %v", err)
						return err
					}
					if res.Degraded {
						// #136: a degraded pack must be loud in the operator-facing log, not
						// just embedded in the archived JSON — a collection failure means
						// this export is incomplete, not a clean point-in-time snapshot.
						log.Printf("Evidence pack exported DEGRADED (%d collection failure(s)): %d bytes -> %v; reasons: %s",
							len(res.DegradedReasons), res.Bytes, res.Targets, strings.Join(res.DegradedReasons, "; "))
					} else {
						log.Printf("Evidence pack exported: %d bytes -> %v", res.Bytes, res.Targets)
					}
					return nil
				})
			})
		}
	}

	// Start the audit-checkpoint scheduler (ADR-029). Periodically signs the verified
	// audit-chain head so tampering, tail-truncation, and genesis re-seed are
	// detectable. This is the trail's FORGERY-RESISTANCE layer: the per-row hash chain
	// is unkeyed, so a database-write attacker could otherwise edit/delete/reorder rows
	// and recompute a self-consistent chain undetected. It is therefore enabled BY
	// DEFAULT whenever a signing key is available (the key is DEK-derived → encryption
	// must be configured). HA-gated so one replica writes per tick.
	switch {
	case cfg.AuditCheckpoints.Disabled:
		log.Printf("WARNING: audit-checkpoint forgery-resistance is explicitly DISABLED; the audit trail is tamper-evident but a database-write attacker can recompute the hash chain undetected")
	case !coreService.AuditCheckpointsAvailable():
		log.Printf("WARNING: audit checkpointing is UNAVAILABLE (encryption/signing key not configured) — the audit trail is tamper-EVIDENT only, NOT forgery-resistant: a database-write attacker can edit/delete/reorder audit rows and recompute the chain. Enable encryption to activate forgery resistance.")
	default:
		interval := cfg.AuditCheckpoints.GetInterval()
		log.Printf("Audit-checkpoint scheduler enabled (forgery resistance active): every %s", interval)
		runScheduler(ctx, "audit_checkpoint", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockAuditCkpt, "Audit-checkpoint", func() error {
				cp, written, werr := coreService.WriteAuditCheckpoint(ctx)
				if werr != nil {
					log.Printf("Audit-checkpoint error: %v", werr)
					return werr
				}
				if written {
					log.Printf("Audit checkpoint written: #%d head=%d events=%d", cp.ID, cp.HeadID, cp.ChainedEvents)
				}
				return nil
			})
		})
	}

	// Start the JIT access-expiry sweeper — opt-in. Removes time-bound role grants
	// whose expiry has passed (auditing each as role.expired) and reclaims the rows.
	// Expired grants already stop authorizing immediately (the auth queries filter
	// on expiry); this just keeps the tables clean and writes the expiry audit trail.
	if cfg.JITAccessExpiry.Enabled {
		interval := cfg.JITAccessExpiry.GetInterval()
		log.Printf("JIT access-expiry sweeper enabled: every %s", interval)
		runScheduler(ctx, "jit_access_expiry", interval, func() middleware.SchedulerOutcome {
			// A legal hold preserves the grant rows (the auth queries still deny
			// expired grants immediately, so blocking the sweep loses no security).
			if legalHoldBlocks("JIT access-expiry sweep") {
				return middleware.SchedulerSkipped
			}
			// Single-replica-gated (ADR-039): one replica sweeps per tick.
			return lockedRun(ctx, coreService.Storage(), schedLockJITExpiry, "JIT access-expiry", func() error {
				now := time.Now()
				n, rerr := coreService.RemoveExpiredRoleGrants(ctx, now)
				if rerr != nil {
					log.Printf("JIT access-expiry sweep error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("JIT access-expiry sweep removed %d expired grant(s)", n)
				}
				// The same sweep reclaims expired time-bound secret shares (both already
				// stop authorizing immediately; this keeps the tables clean + audited).
				sn, serr := coreService.RemoveExpiredShares(ctx, now)
				if serr != nil {
					log.Printf("JIT access-expiry share-sweep error: %v", serr)
					return serr
				}
				if sn > 0 {
					log.Printf("JIT access-expiry sweep removed %d expired share(s)", sn)
				}
				return nil
			})
		})
	}

	// Start the dynamic-secrets auto-revoke sweeper (ADR-035) — opt-in. Revokes
	// every active lease past its expiry so credentials don't outlive their TTL.
	if cfg.DynamicSecrets.SweepEnabled {
		interval := cfg.DynamicSecrets.GetSweepInterval()
		log.Printf("Dynamic-secrets auto-revoke sweeper enabled: every %s", interval)
		runScheduler(ctx, "dynamic_secret_sweep", interval, func() middleware.SchedulerOutcome {
			// Single-replica-gated (ADR-039): one replica revokes per tick, so
			// replicas don't storm the target DBs revoking the same leases.
			return lockedRun(ctx, coreService.Storage(), schedLockDynamicSweep, "Dynamic-secrets sweep", func() error {
				n, rerr := coreService.RevokeExpiredLeases(ctx, time.Now())
				if rerr != nil {
					log.Printf("Dynamic-secrets sweep error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Dynamic-secrets sweep revoked %d expired lease(s)", n)
				}
				return nil
			})
		})
	}

	// Prune expired login-attempt records every 15 minutes (ADR-040). Single-replica-
	// gated and ALWAYS run — login_attempts are ephemeral rate-limit data (never legal
	// evidence), so this is deliberately NOT subject to legalHoldBlocks: a long-running
	// legal hold must not stop the prune, or the table grows unbounded (an attacker
	// failing logins from rotating IPs would exhaust disk). The rate-limit window is
	// 15 minutes, so a 15-minute cadence keeps the table at roughly one window of rows.
	runScheduler(ctx, "login_attempt_prune", 15*time.Minute, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockLoginPrune, "Login-attempt prune", func() error {
			_, perr := coreService.PruneLoginAttempts(ctx)
			return perr
		})
	})

	// Create HTTP server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Server.HTTP.Port),
		Handler: router,
		// ReadHeaderTimeout bounds how long a client can dribble in request headers one
		// byte at a time before the connection is dropped (gosec G112 / slowloris-style
		// DoS via a client that never finishes sending headers, holding the connection —
		// and a worker goroutine — open indefinitely). Shorter than ReadTimeout since
		// headers should arrive promptly even for a slow body upload.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
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
				// checkTransportTLSPosture already validated tls.allowed_ciphers at boot,
				// so this should never fail in practice; handled defensively anyway.
				autoCertTLSConfig, err := buildAutoCertTLSConfig(cfg.Server.HTTP.TLS.Domains, cfg.Server.HTTP.TLS)
				if err != nil {
					log.Printf("HTTP server error: %v", err)
					return
				}
				server.TLSConfig = autoCertTLSConfig
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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // NOSONAR
	defer cancel()

	log.Println("Shutting down HTTP server...")
	return server.Shutdown(shutdownCtx)
}

// checkTransportTLSPosture guards against silently serving credentials/secret values in
// cleartext. For each enabled listener without TLS it either fails closed (when
// security.require_transport_tls is set) or logs a prominent warning.
//
// It also fails closed when tls.allowed_ciphers names a cipher suite that isn't a
// recognized, secure TLS 1.2 suite (weak/deprecated suites like RC4/3DES/CBC-mode, or a
// plain typo) — allowed_ciphers is now genuinely wired into the HTTP and gRPC TLS
// builders (#333, applyTLSHardening in server/main.go and server/grpc/server.go), so a
// bad value here would otherwise only surface as a confusing runtime TLS handshake
// failure instead of a clear startup error.
//
// protocol_versions remains a separate, still-unwired tuning field (out of scope for
// #333 — the TLS 1.2 floor stays fixed in code) — it still only warns, not fails, so an
// operator isn't misled into thinking it took effect.
func checkTransportTLSPosture(cfg *config.Config) error {
	require := cfg.Security.RequireTransportTLS
	check := func(name string, inst config.ServerInstanceConfig) error {
		if !inst.Enabled {
			return nil
		}
		// allowed_ciphers is honored now (#333) — validate it up front so a
		// misspelled/weak/deprecated cipher name fails closed at startup instead of
		// only surfacing when a client fails to negotiate a TLS connection.
		if _, err := inst.TLS.ResolveCipherSuites(nil); err != nil {
			return fmt.Errorf("%s %w", name, err)
		}
		// protocol_versions is parsed but still not wired into the TLS builders — warn
		// whenever it's set (TLS on or off) so an operator isn't misled into thinking it
		// took effect.
		if len(inst.ProtocolVersions) > 0 {
			log.Printf("WARNING: %s protocol_versions is set but NOT honored — the TLS 1.2 minimum is fixed in code.", name)
		}
		if inst.TLS.Enabled {
			return nil
		}
		if require {
			return fmt.Errorf("%s listener has no TLS but security.require_transport_tls is set: refusing to serve credentials/secrets in cleartext (enable tls or front it with a TLS-terminating proxy and unset the requirement)", name)
		}
		log.Printf("WARNING: %s listener is serving CLEARTEXT (no TLS) — bearer tokens and secret values are unencrypted. Front it with a TLS-terminating proxy, enable tls, or set security.require_transport_tls to fail closed.", name)
		return nil
	}
	if err := check("HTTP", cfg.Server.HTTP); err != nil {
		return err
	}
	return check("gRPC", cfg.Server.GRPC)
}

// runStartupValidation runs internal/startup.ValidateStartup — the file-permission,
// encryption-key (DEK/salt existence + size), and database-reachability checks that were
// previously reachable ONLY via the manual `keyorix system validate` CLI subcommand,
// despite that command's own help text and SYSTEM_SETUP.md/docs/CONFIGURATION.md claiming
// they run automatically on every boot (#330).
//
// Gated behind security.enable_file_permission_check — the flag these checks are
// documented under and the one production.yaml/web-enabled.yaml explicitly turn on — so a
// deployment that hasn't opted in (the default: the flag defaults to false) is completely
// unaffected by wiring this in; enforceKeyFilePermissions below still runs unconditionally
// as the lighter-weight, always-on permission check it always was. When the flag is set,
// ValidateStartup itself decides warn-vs-fail-closed for a bad permission via
// allow_unsafe_file_permissions, and auto-fixes bad permissions when
// auto_fix_file_permissions is set (run first, before enforceKeyFilePermissions, so an
// auto-fix takes effect before that check re-inspects the same files) — any other failure
// (missing/undersized DEK or salt, unreachable local database) refuses to start, matching
// this being "the sole automated backstop for a world-readable master-key-material file."
func runStartupValidation(cfg *config.Config) error {
	if !cfg.Security.EnableFilePermissionCheck {
		return nil
	}
	configPath := config.ResolvedPath("")
	// Server startup has no --fix flag; remediation is governed solely by the
	// config's Security.AutoFixFilePermissions field, as before.
	result, err := startup.ValidateStartup(configPath, false)
	if result != nil {
		for _, w := range result.Warnings {
			log.Printf("startup validation warning: %s", w)
		}
		for _, e := range result.Errors {
			log.Printf("startup validation error: %s", e)
		}
	}
	if err != nil {
		return err
	}
	log.Printf("Startup validation passed (config, file permissions, encryption keys, database).")
	return nil
}

// enforceKeyFilePermissions refuses to start (or, by default, loudly warns) when sensitive
// key material on disk — the wrapped DEK, the KEK salt, and TLS private keys — is readable
// by group or other. Key writes are already 0600, but a file restored from a backup with a
// bad umask, or one left 0644 by an operator, would otherwise expose the wrapped DEK / TLS
// key to any local user with no signal. Fails closed only when
// security.enable_file_permission_check is set (and not overridden by
// allow_unsafe_file_permissions); otherwise it warns. A not-yet-created key file (first
// boot) is skipped — it is created at 0600.
func enforceKeyFilePermissions(cfg *config.Config) error { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(".", p)
	}
	var paths []string
	if cfg.Storage.Encryption.Enabled {
		paths = append(paths, resolve(cfg.Storage.Encryption.DEKPath), resolve(cfg.Storage.Encryption.SaltPath))
	}
	if cfg.Server.HTTP.TLS.Enabled {
		paths = append(paths, cfg.Server.HTTP.TLS.KeyFile)
	}
	if cfg.Server.GRPC.TLS.Enabled {
		paths = append(paths, cfg.Server.GRPC.TLS.KeyFile)
	}

	var insecure []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue // absent (e.g. created at 0600 on first boot) — nothing to check yet
		}
		if info.Mode().Perm()&0o077 != 0 {
			insecure = append(insecure, fmt.Sprintf("%s (mode %o)", p, info.Mode().Perm()))
		}
	}
	if len(insecure) == 0 {
		return nil
	}
	msg := fmt.Sprintf("key material is readable beyond its owner: %s", strings.Join(insecure, ", "))
	if cfg.Security.EnableFilePermissionCheck && !cfg.Security.AllowUnsafeFilePermissions {
		return fmt.Errorf("%s — refusing to start (chmod to 0600, or set security.allow_unsafe_file_permissions to override)", msg)
	}
	log.Printf("WARNING: %s — restrict to 0600. Set security.enable_file_permission_check to fail closed instead of warning.", msg)
	return nil
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
		// AutoCert mode builds its tls.Config separately, from the autocert.Manager
		// (see buildAutoCertTLSConfig) — it still gets the same hardening applied.
		return nil, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	if err := applyTLSHardening(tlsConfig, cfg.Server.HTTP.TLS); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// hardenedCipherSuites is the explicit AEAD-only cipher suite allowlist applied to
// every HTTP TLS listener, regardless of how its certificate is sourced, UNLESS the
// operator has explicitly configured tls.allowed_ciphers (#333) — in which case that
// configured list is honored instead (see applyTLSHardening).
var hardenedCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// applyTLSHardening layers the hardened MinVersion/CipherSuites onto tlsConfig in
// place. The protocol-version floor and cipher-suite allowlist are independent of how
// the certificate itself is sourced, so this must be applied uniformly whether
// tlsConfig came from a manually configured cert/key pair (createTLSConfig) or from an
// autocert.Manager (buildAutoCertTLSConfig) — AutoCert should only supply the
// certificate, not silently determine the rest of the TLS posture too (#172).
//
// CipherSuites is resolved from tlsCfg.AllowedCiphers (#333): when the operator has
// left tls.allowed_ciphers unset, the hardcoded hardenedCipherSuites default above
// applies unchanged (no regression for existing deployments); when they've set it,
// their configured suite list is honored instead — validated against
// config.SecureCipherSuiteNames, so a weak/deprecated/misspelled suite name fails
// closed at startup rather than being silently ignored (the previous behavior) or
// silently accepted. MinVersion stays fixed at TLS 1.2: TLS 1.3 has no equivalent
// per-suite selection, so there is nothing for allowed_ciphers to configure there.
func applyTLSHardening(tlsConfig *tls.Config, tlsCfg config.TLSConfig) error {
	tlsConfig.MinVersion = tls.VersionTLS12
	suites, err := tlsCfg.ResolveCipherSuites(hardenedCipherSuites)
	if err != nil {
		return fmt.Errorf("invalid TLS configuration: %w", err)
	}
	tlsConfig.CipherSuites = suites
	return nil
}

// buildAutoCertTLSConfig builds the tls.Config for HTTP AutoCert (Let's Encrypt-style
// automatic certificate management) mode: the autocert.Manager supplies the
// certificate (via GetCertificate/NextProtos), and the same hardened
// MinVersion/CipherSuites as the non-AutoCert path (createTLSConfig) are layered on
// top instead of being silently discarded (#172), honoring tls.allowed_ciphers the
// same way createTLSConfig does (#333).
func buildAutoCertTLSConfig(domains []string, tlsCfg config.TLSConfig) (*tls.Config, error) {
	m := &autocert.Manager{
		Cache:      autocert.DirCache("certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
	}
	tlsConfig := m.TLSConfig()
	if err := applyTLSHardening(tlsConfig, tlsCfg); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// resolveOutboundIP returns the machine's preferred outbound IP address.
func resolveOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80") // NOSONAR -- well-known UDP probe target; no data is sent, used only to resolve the local outbound interface
	if err != nil {
		return "127.0.0.1" // NOSONAR -- default bind address, not sensitive
	}
	defer conn.Close() //nolint:errcheck
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// oidcDiscovery is the subset of an OIDC discovery document we need.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// maxDiscoveryBytes caps the discovery document we read into memory.
const maxDiscoveryBytes = 1 << 20 // 1 MiB

// discoverOIDC fetches an issuer's /.well-known/openid-configuration and validates
// it. The issuer must use https (http only for loopback) so the document — which
// names the jwks_uri that ultimately supplies the token-signing keys — is not
// fetched over plaintext where a MITM could redirect key fetching to attacker keys.
// Per the OIDC spec the document's own issuer must equal the configured issuer, and
// the jwks_uri it advertises must live on the issuer's host, so a tampered/hostile
// discovery doc can't point key fetching at an unrelated host.
func discoverOIDC(issuer string) (*oidcDiscovery, error) {
	iss, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil || iss.Host == "" {
		return nil, fmt.Errorf("invalid issuer %q", issuer)
	}
	if err := requireSecureOrLoopback(iss, "issuer"); err != nil {
		return nil, err
	}

	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: noDiscoveryCrossOriginRedirect,
	}
	resp, err := client.Get(u) // #nosec G107 -- issuer is operator-configured and https-validated above
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %s", resp.Status)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryBytes)).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document is missing required endpoints")
	}
	if d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("discovery issuer %q does not match configured issuer %q", d.Issuer, issuer)
	}
	jwksURL, err := url.Parse(d.JWKSURI)
	if err != nil || jwksURL.Host == "" {
		return nil, fmt.Errorf("discovery jwks_uri %q is invalid", d.JWKSURI)
	}
	if !strings.EqualFold(jwksURL.Hostname(), iss.Hostname()) {
		return nil, fmt.Errorf("discovery jwks_uri host %q does not match issuer host %q", jwksURL.Hostname(), iss.Hostname())
	}
	return &d, nil
}

// requireSecureOrLoopback rejects a non-https URL unless its host is loopback.
func requireSecureOrLoopback(u *url.URL, label string) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHostname(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s %q must use https (http is allowed only for localhost)", label, u.Redacted())
}

func isLoopbackHostname(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// noDiscoveryCrossOriginRedirect rejects a discovery redirect that changes host or
// downgrades the scheme, so a redirect can't pull the document from an unexpected host.
func noDiscoveryCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	if !strings.EqualFold(req.URL.Hostname(), prev.Hostname()) {
		return fmt.Errorf("discovery: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("discovery: refusing scheme downgrade to %q", req.URL.Scheme)
	}
	return nil
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
func buildSSOProviders(sso config.SSOConfig) (map[string]*core.SSOProvider, core.JWKSResolver, int) { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	providers := map[string]*core.SSOProvider{}
	jwksURIs := map[string]string{}
	for i := range sso.Providers {
		pc := sso.Providers[i]
		if pc.Name == "" {
			log.Printf("SSO provider with no name; skipping")
			continue
		}
		// SAML providers are built from their own block (no OIDC discovery).
		if strings.EqualFold(pc.Type, "saml") {
			sp, err := buildSAMLProvider(pc)
			if err != nil {
				log.Printf("SSO provider %q (saml) misconfigured: %v; skipping", pc.Name, err)
				continue
			}
			completeURL, err := ssoCompleteURL(pc.SAML.ACSURL)
			if err != nil {
				log.Printf("SSO provider %q (saml): %v; skipping", pc.Name, err)
				continue
			}
			providers[pc.Name] = &core.SSOProvider{
				Name: pc.Name, Type: "saml", SAML: sp, CompleteURL: completeURL,
				AutoProvision: pc.AutoProvision, DefaultRole: pc.DefaultRole,
				TrustAssertedEmail: pc.TrustAssertedEmail,
				GroupSync:          pc.GroupSync, GroupRoleMap: pc.GroupRoleMap,
			}
			continue
		}
		if pc.Issuer == "" || pc.ClientID == "" || pc.RedirectURL == "" {
			log.Printf("SSO provider %q misconfigured (issuer/client_id/redirect_url required); skipping", pc.Name)
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
			GroupSync:     pc.GroupSync,
			GroupsClaim:   pc.GroupsClaim,
			GroupRoleMap:  pc.GroupRoleMap,
		}
		jwksURIs[pc.Issuer] = disc.JWKSURI
	}
	if len(providers) == 0 {
		return nil, nil, 0
	}
	// A JWKS resolver is only needed for OIDC providers; a SAML-only deployment has none.
	if len(jwksURIs) == 0 {
		return providers, nil, len(providers)
	}
	resolver, err := core.NewHTTPJWKSResolver(jwksURIs)
	if err != nil {
		log.Printf("SSO disabled: jwks resolver init failed: %v", err)
		return nil, nil, 0
	}
	return providers, resolver, len(providers)
}

// buildSAMLProvider constructs a SAML Service Provider from its config block, reading
// the IdP metadata inline or from a file.
func buildSAMLProvider(pc config.SSOProviderConfig) (*samlpkg.Provider, error) {
	if pc.SAML == nil {
		return nil, fmt.Errorf("missing saml config block")
	}
	metaXML := []byte(pc.SAML.IDPMetadataXML)
	if len(metaXML) == 0 && pc.SAML.IDPMetadataFile != "" {
		b, err := os.ReadFile(pc.SAML.IDPMetadataFile) // #nosec G304 -- operator-provided metadata path
		if err != nil {
			return nil, fmt.Errorf("read idp_metadata_file: %w", err)
		}
		metaXML = b
	}
	return samlpkg.NewProvider(samlpkg.Config{
		Name:              pc.Name,
		IDPMetadataXML:    metaXML,
		SPEntityID:        pc.SAML.SPEntityID,
		ACSURL:            pc.SAML.ACSURL,
		AllowIDPInitiated: pc.SAML.AllowIDPInitiated,
		EmailAttr:         pc.SAML.EmailAttribute,
		NameAttr:          pc.SAML.NameAttribute,
		GroupsAttr:        pc.SAML.GroupsAttribute,
	})
}
