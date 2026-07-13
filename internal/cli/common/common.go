package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// cliActorEnvVar lets an operator self-assert their own Keyorix user ID for local
// CLI mutations (#150). Local mode has no authenticated session — every core
// mutation it drives is otherwise stamped actorID=0 ("no authenticated
// principal") in the audit trail, including against a SHARED backend
// (InitializeCoreService honors storage.type=postgres, not just the embedded
// SQLite default), which weakens accountability in exactly the highest-blast-
// radius pathway: someone who already holds the deployment's DB credentials.
// This is self-asserted, not cryptographically verified — local mode already
// has no authentication layer to verify against — but a self-asserted operator
// ID beats an anonymous 0 for post-incident forensic reconstruction.
const cliActorEnvVar = "KEYORIX_CLI_ACTOR"

// ResolveActorID returns the operator-asserted actor ID from KEYORIX_CLI_ACTOR
// (#150), or 0 (the existing "no authenticated principal" convention) if unset
// or unparseable.
func ResolveActorID() uint {
	raw := os.Getenv(cliActorEnvVar)
	if raw == "" {
		return 0
	}
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint(id)
}

// InitializeCoreService creates a core service instance using the storage factory
// This function should be used by all CLI commands instead of directly creating storage
func InitializeCoreService() (*core.KeyorixCore, error) {
	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		// If no config file exists, use default local storage
		cfg = &config.Config{
			Locale: config.LocaleConfig{
				Language:         "en",
				FallbackLanguage: "en",
			},
			Storage: config.StorageConfig{
				Type: "local",
				Database: config.DatabaseConfig{
					Path: "./secrets.db",
				},
			},
		}
	}

	// Initialize i18n system
	if err := i18n.Initialize(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize i18n: %w", err)
	}

	// Create storage using factory
	factory := storage.NewStorageFactory()
	storageImpl, err := factory.CreateStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// #150: local mode against a SHARED (non-embedded-SQLite) backend bypasses every
	// HTTP-layer authz gate AND, without an explicit actor, attributes every
	// mutation to nobody. Warn loudly rather than silently degrading the audit
	// trail's accountability for what's already the highest-blast-radius pathway.
	if cfg.Storage.Type != "" && cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" && ResolveActorID() == 0 {
		fmt.Fprintf(os.Stderr, "WARNING: local CLI mode is writing directly to a shared %q backend with no operator identifier set — audit events for these actions will show actorID=0 (\"no authenticated principal\"). Set %s=<your-keyorix-user-id> to attribute them to yourself.\n",
			cfg.Storage.Type, cliActorEnvVar)
	}

	// Create core service and wire credential delivery (ADR-028) so a CLI admin can
	// provision / resend setup links. Best-effort: a delivery misconfig (e.g.
	// mode=smtp with no host) must not break unrelated CLI commands, so on a New
	// error we leave delivery unset — core then falls back to out-of-band (returns
	// the link), which is exactly what a CLI admin wants anyway.
	svc := core.NewKeyorixCore(storageImpl)

	// Wire at-rest secret-value encryption for direct-storage (embedded) mode, so a
	// CLI `secret create/rotate` encrypts exactly like the server does instead of
	// writing plaintext into the same database. Fail-closed: an encryption misconfig
	// aborts the command rather than silently degrading to plaintext.
	if err := wireSecretEncryption(svc, cfg); err != nil {
		return nil, err
	}

	svc.SetSetupTokenTTL(cfg.CredentialDelivery.GetSetupTokenTTL())
	cd := cfg.CredentialDelivery
	if deliverer, derr := delivery.New(cd.DeliveryConfig()); derr == nil {
		svc.SetCredentialDelivery(deliverer, cd.BaseURL)
	} else {
		svc.SetCredentialDelivery(nil, cd.BaseURL)
	}
	return svc, nil
}

// wireSecretEncryption initializes at-rest secret-value encryption for a CLI command
// that has DIRECT storage access (local/postgres embedded mode) and wires it into the
// core service. No-op when encryption is disabled or when storage.type is remote —
// there the upstream server owns encryption and the CLI merely proxies, so encrypting
// here would double-encrypt.
//
// It takes the SHARED key lock (#196): any number of short-lived CLI commands can run
// concurrently, but every one is refused while a live server (holding the exclusive
// lifetime lock) or an in-progress rotation holds the key directory — so an embedded
// CLI write can never race a DEK that's being replaced. The lock and the in-memory DEK
// are released when the short-lived CLI process exits.
//
// Fail-closed for a security product: if encryption is enabled but the key can't be
// derived, locked, or the encryptor doesn't actually engage, the command errors rather
// than writing (or reading) secret values in plaintext.
func wireSecretEncryption(svc *core.KeyorixCore, cfg *config.Config) error {
	if !cfg.Storage.Encryption.Enabled {
		return nil
	}
	if cfg.Storage.Type == "remote" {
		return nil // upstream server encrypts; the CLI proxies to it
	}

	providerType := cfg.Storage.Encryption.KeyProvider.Type
	passphrase := strings.TrimSpace(os.Getenv("KEYORIX_MASTER_PASSWORD"))
	if (providerType == "" || providerType == "password") && passphrase == "" {
		return fmt.Errorf("storage.encryption is enabled but KEYORIX_MASTER_PASSWORD is not set; set it (or configure storage.encryption.key_provider) so the CLI can encrypt/decrypt secret values")
	}

	baseDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to resolve working directory for encryption key files: %w", err)
	}
	encSvc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := encSvc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize encryption (KEK derivation): %w", err)
	}
	if err := encSvc.AcquireSharedKeyLock(); err != nil {
		encSvc.Shutdown()
		return fmt.Errorf("%w — a live server or an in-progress rotation is using this key directory; use client mode, or stop it and retry", err)
	}

	svc.SetSecretValueEncryptor(encSvc)
	svc.SetAuthEncryptor(encSvc)
	if !svc.SecretValueEncryptionActive() {
		return fmt.Errorf("storage.encryption is enabled but secret-value encryption did not engage; refusing to run to avoid storing secrets in plaintext")
	}
	return nil
}

// InitializeStorage builds a storage.Storage from the resolved configuration via
// the storage factory, so the backend is selected by cfg.Storage.Type
// (local/postgres/remote) instead of being hardwired. CLI commands that need
// storage — directly, or wrapped in a core service via core.NewKeyorixCore — must
// use this instead of opening the database with a GORM driver themselves
// (ADR-049). Config is resolved through the same config.Load("") path
// (KEYORIX_CONFIG_PATH-based) that the rest of the CLI and the server use, so a
// command and the server read identical configuration.
func InitializeStorage() (corestorage.Storage, error) {
	cfg, err := config.Load("")
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}
	return st, nil
}

// PrintProvisionResult prints how a setup link was delivered (ADR-028). In out-of-band
// mode it prints the link for the admin to relay; in SMTP mode it confirms the send.
// Shared by `user create --setup-link`, `user resend-setup-link`, `invite send`, and
// `invite resend`.
func PrintProvisionResult(prov *core.ProvisionSetupResult) {
	if prov == nil {
		return
	}
	if prov.Delivered {
		fmt.Printf("Setup link delivered to %s via %s.\n", prov.Email, prov.Channel)
		return
	}
	fmt.Printf("Setup link (relay this to %s securely — it is single-use and expires):\n  %s\n", prov.Email, prov.LinkForAdmin)
}

// PrintOneTimePasswordResult prints the out-of-band one-time password for the admin to
// relay (ADR-028 Part E). It is shown once and the account must change it on first login.
// Shared by `user create --one-time-password`.
func PrintOneTimePasswordResult(otp *core.OneTimePasswordResult) {
	if otp == nil {
		return
	}
	fmt.Printf("One-time password for %s (relay securely — it must be changed on first login):\n  %s\n", otp.Email, otp.OneTimePassword) // lgtm[go/clear-text-logging]
}
