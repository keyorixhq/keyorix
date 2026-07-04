package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// migrationMu serializes migrateDatabase across goroutines IN THIS PROCESS (#266).
// startHTTPServer and startGRPCServer each independently call CreateStorage →
// migrateDatabase as separate goroutines when both HTTP and gRPC are enabled (a
// documented example config) — without this, both goroutines can observe a fresh
// database (`projectsExists == false`) and race the same CREATE TABLE/CREATE INDEX
// statements, with the loser erroring out and its server silently never starting
// listening (no crash, no alert). This does NOT protect against multiple separate
// OS processes/replicas migrating a shared Postgres concurrently — see
// postgresMigrationLockKey below for that.
var migrationMu sync.Mutex

// postgresMigrationLockKey is an arbitrary, fixed application-specific key for
// Postgres's session-level advisory lock (pg_advisory_lock/pg_advisory_unlock),
// used to serialize migrateDatabase ACROSS PROCESSES when running against
// Postgres (e.g. multiple replicas booting against a shared, fresh database).
// SQLite has no analogous multi-process advisory-lock primitive, but SQLite
// deployments are single-process-per-file by construction, so migrationMu alone
// is sufficient there; only Postgres needs the additional cross-process lock.
const postgresMigrationLockKey = 872341

// withMigrationLock runs fn while holding migrationMu (always) and, when db is a
// Postgres connection, an additional Postgres session-level advisory lock (closing
// the cross-replica race #266 describes, not just the in-process one). The
// advisory lock is released in the same session it was acquired in, so this must
// run on a single connection for the duration — acquired/released via db.Exec on
// the same *gorm.DB, which GORM services from one checked-out *sql.Conn per call
// only within an explicit transaction; to guarantee same-connection acquire/
// release without depending on that, this wraps fn in db.Transaction.
func withMigrationLock(db *gorm.DB, isPostgres bool, fn func(*gorm.DB) error) error {
	migrationMu.Lock()
	defer migrationMu.Unlock()

	if !isPostgres {
		return fn(db)
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_lock(?)", postgresMigrationLockKey).Error; err != nil {
			return fmt.Errorf("acquire migration advisory lock: %w", err)
		}
		defer tx.Exec("SELECT pg_advisory_unlock(?)", postgresMigrationLockKey)
		return fn(tx)
	})
}

// defaultMaxOpenConns bounds the DB connection pool when the operator hasn't set
// max_open_conns — Go's own default is unlimited, which lets a request flood exhaust the
// backing database's connection limit. A conservative cap is safer out of the box.
const defaultMaxOpenConns = 25

// gormConfig returns the *gorm.Config shared by every gorm.Open call in this
// package. GORM's zero-value Config leaves its default Warn-level logger active,
// which interpolates bound query-parameter VALUES into the logged SQL statement
// whenever a query errors or exceeds the slow-query threshold — meaning secret
// ciphertext, token hashes, and other sensitive bound parameters would otherwise
// get written to stdout/logs on any query error or slow query. Silence it here
// so that never happens by default (#464).
func gormConfig() *gorm.Config {
	return &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
}

// StorageFactory creates storage instances based on configuration
type StorageFactory interface {
	CreateStorage(config *config.Config) (storage.Storage, error)
}

// DefaultStorageFactory is the default implementation of StorageFactory
type DefaultStorageFactory struct{}

// NewStorageFactory creates a new storage factory
func NewStorageFactory() StorageFactory {
	return &DefaultStorageFactory{}
}

// CreateStorage creates a storage instance based on the configuration
func (f *DefaultStorageFactory) CreateStorage(cfg *config.Config) (storage.Storage, error) {
	switch cfg.Storage.Type {
	case "remote":
		return f.createRemoteStorage(cfg)
	case "postgres", "postgresql":
		return f.createPostgresStorage(cfg)
	case "local", "":
		return f.createLocalStorage(cfg)
	default:
		// #463: defense in depth. Config.Validate() rejects an unrecognized
		// storage.type at boot, but this factory can also be invoked directly
		// (e.g. by tests or other code paths that don't call Validate() first)
		// — a typo like "postgress" must never silently fall back to SQLite,
		// since in a multi-replica HA deployment intending shared Postgres/
		// remote storage that produces per-replica split-brain SQLite
		// instances with no operator-visible signal.
		return nil, fmt.Errorf("invalid storage.type %q: must be one of \"local\", \"postgres\", \"postgresql\", or \"remote\"", cfg.Storage.Type)
	}
}

// createLocalStorage creates a SQLite-backed local storage instance
func (f *DefaultStorageFactory) createLocalStorage(cfg *config.Config) (storage.Storage, error) {
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}

	db, err := gorm.Open(sqlite.Open(dbPath), gormConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
		return nil, err
	}

	if err := withMigrationLock(db, false, f.migrateDatabase); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return store.NewLocalStorage(db), nil
}

// createPostgresStorage creates a PostgreSQL-backed local storage instance
func (f *DefaultStorageFactory) createPostgresStorage(cfg *config.Config) (storage.Storage, error) {
	dsn := config.BuildPostgresDSN(&cfg.Storage.Database)
	if dsn == "" {
		return nil, fmt.Errorf("postgres storage requires a DSN or host/name/user fields")
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
		return nil, err
	}

	if err := withMigrationLock(db, true, f.migrateDatabase); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return store.NewLocalStorage(db), nil
}

// applyPoolSettings configures the connection pool on the underlying *sql.DB
func applyPoolSettings(db *gorm.DB, dbCfg *config.DatabaseConfig) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	// Always cap open connections. Go's default is UNLIMITED, so without a cap a flood of
	// concurrent requests (even unauthenticated ones like /readyz, which pings the DB) can
	// open connections without bound and exhaust the backing database's max_connections.
	if dbCfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(dbCfg.MaxOpenConns)
	} else {
		sqlDB.SetMaxOpenConns(defaultMaxOpenConns)
	}
	if dbCfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(dbCfg.MaxIdleConns)
	}
	if dbCfg.ConnMaxLifetimeMinutes > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(dbCfg.ConnMaxLifetimeMinutes) * time.Minute)
	}
	return nil
}

// createRemoteStorage creates a remote storage instance
func (f *DefaultStorageFactory) createRemoteStorage(cfg *config.Config) (storage.Storage, error) {
	if cfg.Storage.Remote == nil {
		return nil, fmt.Errorf("remote storage configuration is required")
	}

	remoteConfig := &remote.Config{
		BaseURL:        cfg.Storage.Remote.BaseURL,
		APIKey:         cfg.Storage.Remote.GetAPIKey(),
		TimeoutSeconds: cfg.Storage.Remote.TimeoutSeconds,
		RetryAttempts:  cfg.Storage.Remote.RetryAttempts,
		TLSVerify:      cfg.Storage.Remote.VerifyTLS(), // secure-by-default resolution
	}

	return store.NewRemoteStorage(remoteConfig)
}

func columnExists(db *gorm.DB, table, column string) bool {
	var count int64
	db.Raw("SELECT COUNT(*) FROM information_schema.columns WHERE table_name = ? AND column_name = ?", table, column).Scan(&count)
	return count > 0
}

// tableExists checks whether a table exists without relying on GORM's HasTable
// (which can fail with "insufficient arguments" on some Postgres driver versions).
func tableExists(db *gorm.DB, table string) bool {
	var count int64
	db.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ?", table).Scan(&count)
	return count > 0
}

// migrateDatabase performs database migrations via GORM AutoMigrate.
// Idempotent: safe to run on both fresh and existing databases.
// On a fresh DB, AutoMigrate creates all tables. On an existing DB,
// it adds missing columns and indexes without dropping anything.
func (f *DefaultStorageFactory) migrateDatabase(db *gorm.DB) error {
	// Additive column migration for existing databases (no-op on fresh DBs).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "last_rotated_at") {
		db.Exec("ALTER TABLE secret_nodes ADD COLUMN last_rotated_at TIMESTAMP WITH TIME ZONE")
	}
	// ADR-033: secrets soft-delete. Additive deleted_at (nil = live).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "deleted_at") {
		db.Exec("ALTER TABLE secret_nodes ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE")
	}
	// Data classification (ISO A.5.12). Additive classification ("" = unclassified).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "classification") {
		db.Exec("ALTER TABLE secret_nodes ADD COLUMN classification TEXT DEFAULT ''")
	}
	// ADR-046: automated rotation opt-in. Additive auto_rotate (false = off).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "auto_rotate") {
		db.Exec("ALTER TABLE secret_nodes ADD COLUMN auto_rotate BOOLEAN NOT NULL DEFAULT false")
	}
	// ADR-046: per-secret generated-value shape. Additive (0/'' = defaults).
	if tableExists(db, "secret_nodes") {
		if !columnExists(db, "secret_nodes", "rotation_length") {
			db.Exec("ALTER TABLE secret_nodes ADD COLUMN rotation_length INTEGER NOT NULL DEFAULT 0")
		}
		if !columnExists(db, "secret_nodes", "rotation_charset") {
			db.Exec("ALTER TABLE secret_nodes ADD COLUMN rotation_charset TEXT NOT NULL DEFAULT ''")
		}
		// ADR-047: backend rotation wiring. Additive ('' = regenerate-in-Keyorix).
		if !columnExists(db, "secret_nodes", "rotation_backend") {
			db.Exec("ALTER TABLE secret_nodes ADD COLUMN rotation_backend TEXT NOT NULL DEFAULT ''")
		}
		if !columnExists(db, "secret_nodes", "rotation_ref") {
			db.Exec("ALTER TABLE secret_nodes ADD COLUMN rotation_ref TEXT NOT NULL DEFAULT ''")
		}
		// ADR-056: cached certificate expiry. Additive (nil = not yet evaluated).
		if !columnExists(db, "secret_nodes", "cert_not_after") {
			db.Exec("ALTER TABLE secret_nodes ADD COLUMN cert_not_after TIMESTAMP WITH TIME ZONE")
		}
	}
	// Anomaly alerting: additive `alerted` flag (false = not yet pushed out).
	if tableExists(db, "anomaly_alerts") && !columnExists(db, "anomaly_alerts", "alerted") {
		db.Exec("ALTER TABLE anomaly_alerts ADD COLUMN alerted BOOLEAN DEFAULT FALSE")
	}

	// Track last successful login per user (nil = never logged in).
	if tableExists(db, "users") && !columnExists(db, "users", "last_login_at") {
		db.Exec("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP WITH TIME ZONE")
	}

	// Track when the current password was set, for max-age expiry (ADR-025).
	if tableExists(db, "users") && !columnExists(db, "users", "password_changed_at") {
		db.Exec("ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP WITH TIME ZONE")
	}

	// Account lifecycle state (ADR-025). Existing rows default to active.
	if tableExists(db, "users") && !columnExists(db, "users", "account_state") {
		db.Exec("ALTER TABLE users ADD COLUMN account_state TEXT NOT NULL DEFAULT 'active'")
	}

	// MFA/TOTP opt-in flag. Existing rows default to false (MFA off).
	if tableExists(db, "users") && !columnExists(db, "users", "mfa_enabled") {
		db.Exec("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false")
	}

	// SCIM external ID (RFC 7644). Additive; empty for locally-created users.
	if tableExists(db, "users") && !columnExists(db, "users", "external_id") {
		db.Exec("ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT ''")
	}

	// Per-account login lockout (brute-force protection). Additive; safe on existing DBs.
	if tableExists(db, "users") {
		if !columnExists(db, "users", "failed_login_attempts") {
			db.Exec("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")
		}
		if !columnExists(db, "users", "last_failed_login_at") {
			db.Exec("ALTER TABLE users ADD COLUMN last_failed_login_at TIMESTAMP WITH TIME ZONE")
		}
		if !columnExists(db, "users", "login_locked_until") {
			db.Exec("ALTER TABLE users ADD COLUMN login_locked_until TIMESTAMP WITH TIME ZONE")
		}
		if !columnExists(db, "users", "login_lockout_count") {
			db.Exec("ALTER TABLE users ADD COLUMN login_lockout_count INTEGER NOT NULL DEFAULT 0")
		}
	}

	// Enrich sessions for the My Account "active sessions" view (device/IP/last-active).
	if tableExists(db, "sessions") {
		if !columnExists(db, "sessions", "user_agent") {
			db.Exec("ALTER TABLE sessions ADD COLUMN user_agent TEXT")
		}
		if !columnExists(db, "sessions", "ip_address") {
			db.Exec("ALTER TABLE sessions ADD COLUMN ip_address TEXT")
		}
		if !columnExists(db, "sessions", "last_seen_at") {
			db.Exec("ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMP WITH TIME ZONE")
		}
		// Absolute session-lifetime ceiling (short-lived tokens): set at login,
		// carried through refresh, never extended. nil on legacy rows = uncapped.
		if !columnExists(db, "sessions", "absolute_expires_at") {
			db.Exec("ALTER TABLE sessions ADD COLUMN absolute_expires_at TIMESTAMP WITH TIME ZONE")
		}
	}

	// Audit-design block: diff payload + impersonation attribution on audit rows.
	if tableExists(db, "audit_events") {
		if !columnExists(db, "audit_events", "diff") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN diff TEXT")
		}
		if !columnExists(db, "audit_events", "impersonated_by") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN impersonated_by INTEGER")
		}
		if !columnExists(db, "audit_events", "acting_as") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN acting_as INTEGER")
		}
		if !columnExists(db, "audit_events", "impersonation") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN impersonation BOOLEAN NOT NULL DEFAULT false")
		}
		// ADR-023: actor kind (user vs machine_identity) on every event.
		if !columnExists(db, "audit_events", "actor_type") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'user'")
		}
		// ADR-029: tamper-evidence hash chain. Empty on legacy rows (the chain
		// begins at the first event written after these columns exist).
		if !columnExists(db, "audit_events", "prev_hash") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
		}
		if !columnExists(db, "audit_events", "entry_hash") {
			db.Exec("ALTER TABLE audit_events ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''")
		}
	}

	// Impersonation sessions carry the initiating admin + start time.
	if tableExists(db, "sessions") {
		if !columnExists(db, "sessions", "impersonated_by") {
			db.Exec("ALTER TABLE sessions ADD COLUMN impersonated_by INTEGER")
		}
		if !columnExists(db, "sessions", "impersonation_started_at") {
			db.Exec("ALTER TABLE sessions ADD COLUMN impersonation_started_at TIMESTAMP WITH TIME ZONE")
		}
	}

	// RBAC Phase 2: scope role assignments by environment as well as project.
	// project_id already exists (nullable on pre-008 DBs); add environment_id and
	// normalise NULL project_id rows to the 0 = global sentinel the queries expect.
	for _, tbl := range []string{"user_roles", "group_roles"} {
		if !tableExists(db, tbl) {
			continue
		}
		if !columnExists(db, tbl, "environment_id") {
			db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0", tbl))
		}
		if columnExists(db, tbl, "project_id") {
			db.Exec(fmt.Sprintf("UPDATE %s SET project_id = 0 WHERE project_id IS NULL", tbl))
		}
	}

	// Snapshot all table-existence checks UP FRONT, before any AutoMigrate runs.
	// AutoMigrate creating a new table poisons the pgx connection's prepared-statement
	// cache, so a subsequent parameterized information_schema query (tableExists) can
	// spuriously return false ("insufficient arguments") — which would then re-run the
	// full AutoMigrate against an existing DB and fail. Capturing the flags first means
	// no existence query runs after a creation. (Both rotation_policies and
	// personal_access_tokens are kept out of the full AutoMigrate list below for the
	// same pgx reason — see the NOTE there.)
	projectsExists := tableExists(db, "projects")
	rotationExists := tableExists(db, "rotation_policies")
	patExists := tableExists(db, "personal_access_tokens")
	invitationsExists := tableExists(db, "project_invitations")
	accessReqExists := tableExists(db, "access_requests")
	accessReqApprovalsExists := tableExists(db, "access_request_approvals")
	campaignExists := tableExists(db, "access_review_campaigns")
	breakGlassExists := tableExists(db, "break_glass_activations")
	legalHoldExists := tableExists(db, "legal_holds")
	riskExceptionExists := tableExists(db, "risk_exceptions")
	ssoLoginStateExists := tableExists(db, "sso_login_states")
	sodExists := tableExists(db, "sod_policies")
	secretDepExists := tableExists(db, "secret_dependencies")
	pwHistExists := tableExists(db, "password_histories")
	machineExists := tableExists(db, "machine_identities")
	machineCredExists := tableExists(db, "machine_identity_credentials")
	machineRoleExists := tableExists(db, "machine_identity_roles")
	machineOIDCExists := tableExists(db, "machine_identity_oidc_bindings")
	membershipExists := tableExists(db, "project_memberships")
	setupTokenExists := tableExists(db, "setup_tokens")
	notificationsExists := tableExists(db, "notifications")
	mfaSecretExists := tableExists(db, "mfa_secrets")
	mfaRecoveryExists := tableExists(db, "mfa_recovery_codes")
	mfaChallengeExists := tableExists(db, "mfa_challenges")
	dynConfigExists := tableExists(db, "dynamic_secret_configs")
	dynLeaseExists := tableExists(db, "dynamic_secret_leases")
	webauthnCredExists := tableExists(db, "web_authn_credentials")
	webauthnSessExists := tableExists(db, "web_authn_sessions")
	loginAttemptExists := tableExists(db, "login_attempts")
	auditCkptExists := tableExists(db, "audit_checkpoints")
	connectRefGrantExists := tableExists(db, "connect_ref_grants")
	groupsExists := tableExists(db, "groups")

	// Create rotation_policies if missing (additive, safe on existing DBs).
	if !rotationExists {
		if err := db.AutoMigrate(&models.RotationPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate rotation_policies table: %w", err)
		}
	}

	// Create personal_access_tokens if missing (ADR-027, additive, safe on existing DBs);
	// otherwise add only the ADR-042 per-token scoping columns via the Migrator (same
	// pgx hazard as the notifications/invitations blocks — never full-AutoMigrate an
	// existing table here). Defaults leave existing tokens unrestricted (back-compat).
	if !patExists {
		if err := db.AutoMigrate(&models.PersonalAccessToken{}); err != nil {
			return fmt.Errorf("failed to migrate personal_access_tokens table: %w", err)
		}
	} else {
		m := db.Migrator()
		for _, col := range []string{"Scopes", "ProjectScope", "EnvironmentScope"} {
			if !m.HasColumn(&models.PersonalAccessToken{}, col) {
				if err := m.AddColumn(&models.PersonalAccessToken{}, col); err != nil {
					return fmt.Errorf("failed to add personal_access_tokens.%s column: %w", col, err)
				}
			}
		}
	}

	// Create the MFA tables if missing (TOTP MFA, additive, safe on existing DBs).
	if !mfaSecretExists {
		if err := db.AutoMigrate(&models.MFASecret{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_secrets table: %w", err)
		}
	}
	if !mfaRecoveryExists {
		if err := db.AutoMigrate(&models.MFARecoveryCode{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_recovery_codes table: %w", err)
		}
	}
	if !mfaChallengeExists {
		if err := db.AutoMigrate(&models.MFAChallenge{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_challenges table: %w", err)
		}
	}

	// Create the dynamic-secrets tables if missing (ADR-035, additive); otherwise add
	// only the newer max-TTL column via the Migrator (same pgx hazard — never
	// full-AutoMigrate an existing table here).
	if !dynConfigExists {
		if err := db.AutoMigrate(&models.DynamicSecretConfig{}); err != nil {
			return fmt.Errorf("failed to migrate dynamic_secret_configs table: %w", err)
		}
	} else {
		m := db.Migrator()
		if !m.HasColumn(&models.DynamicSecretConfig{}, "MaxTTLSeconds") {
			if err := m.AddColumn(&models.DynamicSecretConfig{}, "MaxTTLSeconds"); err != nil {
				return fmt.Errorf("failed to add dynamic_secret_configs.max_ttl_seconds column: %w", err)
			}
		}
		// Data classification (ISO A.5.12). Additive ("" = unclassified).
		if tableExists(db, "dynamic_secret_configs") && !columnExists(db, "dynamic_secret_configs", "classification") {
			db.Exec("ALTER TABLE dynamic_secret_configs ADD COLUMN classification TEXT DEFAULT ''")
		}
		// Disabled (#369): refuses new leases once the owning project is soft-deleted.
		// Additive (defaults false = every pre-existing config stays enabled).
		if !m.HasColumn(&models.DynamicSecretConfig{}, "Disabled") {
			if err := m.AddColumn(&models.DynamicSecretConfig{}, "Disabled"); err != nil {
				return fmt.Errorf("failed to add dynamic_secret_configs.disabled column: %w", err)
			}
		}
	}
	if !dynLeaseExists {
		if err := db.AutoMigrate(&models.DynamicSecretLease{}); err != nil {
			return fmt.Errorf("failed to migrate dynamic_secret_leases table: %w", err)
		}
	}
	// At most one dynamic-secret config may exist per (project, environment, name)
	// (#462), matching DynamicSecretConfig's own doc comment. The struct carries no
	// unique-index tag (same reason as the max-TTL/Disabled columns above: this table
	// is never re-AutoMigrated once it exists), so the index must be created
	// explicitly here to also reach pre-existing databases. Close the gap at the DB
	// layer regardless of whether the table pre-existed.
	if tableExists(db, "dynamic_secret_configs") {
		if err := ensureDynamicSecretConfigNameIndex(db); err != nil {
			return err
		}
	}

	// Create the WebAuthn tables if missing (ADR-036, additive, safe on existing DBs).
	if !webauthnCredExists {
		if err := db.AutoMigrate(&models.WebAuthnCredential{}); err != nil {
			return fmt.Errorf("failed to migrate web_authn_credentials table: %w", err)
		}
	}
	if !webauthnSessExists {
		if err := db.AutoMigrate(&models.WebAuthnSession{}); err != nil {
			return fmt.Errorf("failed to migrate web_authn_sessions table: %w", err)
		}
	}

	// Create the login_attempts table if missing (ADR-040 rate limiting, additive).
	if !loginAttemptExists {
		if err := db.AutoMigrate(&models.LoginAttempt{}); err != nil {
			return fmt.Errorf("failed to migrate login_attempts table: %w", err)
		}
	}

	// Create the audit_checkpoints table if missing (ADR-029 signed checkpoints,
	// additive, safe on existing DBs).
	if !auditCkptExists {
		if err := db.AutoMigrate(&models.AuditCheckpoint{}); err != nil {
			return fmt.Errorf("failed to migrate audit_checkpoints table: %w", err)
		}
	} else {
		// Add only the newer external-notary anchor columns on an existing table
		// (additive; same pgx hazard as elsewhere — never full-AutoMigrate here).
		m := db.Migrator()
		for _, col := range []string{"AnchorToken", "AnchoredAt", "AnchorProvider"} {
			if !m.HasColumn(&models.AuditCheckpoint{}, col) {
				if err := m.AddColumn(&models.AuditCheckpoint{}, col); err != nil {
					return fmt.Errorf("failed to add audit_checkpoints column %s: %w", col, err)
				}
			}
		}
	}

	// Create connect_ref_grants if missing (ADR-045 per-reference Connect RBAC,
	// additive, safe on existing DBs).
	if !connectRefGrantExists {
		if err := db.AutoMigrate(&models.ConnectRefGrant{}); err != nil {
			return fmt.Errorf("failed to migrate connect_ref_grants table: %w", err)
		}
	}

	// Create project_invitations if missing (ADR-024, additive); otherwise add only
	// the newer global-invite columns via the Migrator (same pgx hazard as the
	// notifications block below — never full-AutoMigrate an existing table here).
	if !invitationsExists {
		if err := db.AutoMigrate(&models.ProjectInvitation{}); err != nil {
			return fmt.Errorf("failed to migrate project_invitations table: %w", err)
		}
	} else {
		m := db.Migrator()
		for _, col := range []string{"SystemRole", "AssignmentsJSON"} {
			if !m.HasColumn(&models.ProjectInvitation{}, col) {
				if err := m.AddColumn(&models.ProjectInvitation{}, col); err != nil {
					return fmt.Errorf("failed to add project_invitations.%s column: %w", col, err)
				}
			}
		}
	}
	if !accessReqExists {
		if err := db.AutoMigrate(&models.AccessRequest{}); err != nil {
			return fmt.Errorf("failed to migrate access_requests table: %w", err)
		}
	}

	// Create the access-request approvals table if missing (N-of-M dual control).
	if !accessReqApprovalsExists {
		if err := db.AutoMigrate(&models.AccessRequestApproval{}); err != nil {
			return fmt.Errorf("failed to migrate access_request_approvals table: %w", err)
		}
	}

	// Create the access-review campaign tables if missing (A.5.18, additive).
	if !campaignExists {
		if err := db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}); err != nil {
			return fmt.Errorf("failed to migrate access_review_campaign tables: %w", err)
		}
	}

	// Create the break-glass activations table if missing (additive).
	if !breakGlassExists {
		if err := db.AutoMigrate(&models.BreakGlassActivation{}); err != nil {
			return fmt.Errorf("failed to migrate break_glass_activations table: %w", err)
		}
	}
	// Enforce at most one ACTIVE break-glass activation per (project, user), even
	// under a race — see ensureBreakGlassActiveIndex. Runs whether the table was just
	// created above or already existed on an older DB (additive, idempotent).
	if err := ensureBreakGlassActiveIndex(db); err != nil {
		return err
	}

	// Create the legal-holds table if missing (additive).
	if !legalHoldExists {
		if err := db.AutoMigrate(&models.LegalHold{}); err != nil {
			return fmt.Errorf("failed to migrate legal_holds table: %w", err)
		}
	}
	// At most one legal hold may be active (released = false) at a time — a plain
	// check-then-insert in core.PlaceLegalHold has a TOCTOU window (#305): two
	// concurrent placements can both observe "no active hold" and both insert one,
	// orphaning a row that GetActiveLegalHold's highest-id lookup never surfaces
	// again, so lifting the hold an operator sees leaves purges permanently blocked.
	// Close the race at the DB layer regardless of whether the table pre-existed.
	if err := ensureLegalHoldActiveIndex(db); err != nil {
		return err
	}

	// Create the risk-exceptions table if missing (A.5.8 risk treatment, additive).
	if !riskExceptionExists {
		if err := db.AutoMigrate(&models.RiskException{}); err != nil {
			return fmt.Errorf("failed to migrate risk_exceptions table: %w", err)
		}
	}

	// Create the SSO-login-state table if missing (OIDC human SSO, additive).
	if !ssoLoginStateExists {
		if err := db.AutoMigrate(&models.SSOLoginState{}); err != nil {
			return fmt.Errorf("failed to migrate sso_login_states table: %w", err)
		}
	}

	// Create the separation-of-duties policy table if missing (additive).
	if !sodExists {
		if err := db.AutoMigrate(&models.SoDPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate sod_policies table: %w", err)
		}
	}

	// Create the secret-dependency edge table if missing (ADR-052, additive).
	if !secretDepExists {
		if err := db.AutoMigrate(&models.SecretDependency{}); err != nil {
			return fmt.Errorf("failed to migrate secret_dependencies table: %w", err)
		}
	}

	// Create password_histories if missing (ADR-025 history_count, additive).
	if !pwHistExists {
		if err := db.AutoMigrate(&models.PasswordHistory{}); err != nil {
			return fmt.Errorf("failed to migrate password_histories table: %w", err)
		}
	}

	// Create machine_identities if missing (ADR-023, additive, safe on existing DBs).
	if !machineExists {
		if err := db.AutoMigrate(&models.MachineIdentity{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identities table: %w", err)
		}
	} else if !columnExists(db, "machine_identities", "classification") {
		// Data classification (ISO A.5.12). Additive ("" = unclassified).
		db.Exec("ALTER TABLE machine_identities ADD COLUMN classification TEXT DEFAULT ''")
	}

	// Create machine-token tables if missing (ADR-030, additive, safe on existing DBs).
	if !machineCredExists {
		if err := db.AutoMigrate(&models.MachineIdentityCredential{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_credentials table: %w", err)
		}
	} else if !columnExists(db, "machine_identity_credentials", "classification") {
		db.Exec("ALTER TABLE machine_identity_credentials ADD COLUMN classification TEXT DEFAULT ''")
	}
	if !machineRoleExists {
		if err := db.AutoMigrate(&models.MachineIdentityRole{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_roles table: %w", err)
		}
	}
	// ADR-031: OIDC federation bindings.
	if !machineOIDCExists {
		if err := db.AutoMigrate(&models.MachineIdentityOIDCBinding{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_oidc_bindings table: %w", err)
		}
	}

	// Create project_memberships if missing (ADR-022 membership lifecycle, additive).
	if !membershipExists {
		if err := db.AutoMigrate(&models.ProjectMembership{}); err != nil {
			return fmt.Errorf("failed to migrate project_memberships table: %w", err)
		}
	}
	if tableExists(db, "project_memberships") {
		if err := ensureProjectMembershipIndex(db); err != nil {
			return err
		}
	}

	// Create setup_tokens if missing (ADR-028 credential delivery, additive).
	if !setupTokenExists {
		if err := db.AutoMigrate(&models.SetupToken{}); err != nil {
			return fmt.Errorf("failed to migrate setup_tokens table: %w", err)
		}
	}

	// Notifications (ADR-024). Create the table if absent; otherwise add only the
	// newer ProjectID/Title/Link columns via the Migrator. We must NOT run a full
	// AutoMigrate on an already-existing table here — on Postgres that re-inspect
	// trips the pgx "insufficient arguments" prepared-statement bug mid-boot (the
	// same hazard handled for the other additive tables above).
	if !notificationsExists {
		if err := db.AutoMigrate(&models.Notification{}); err != nil {
			return fmt.Errorf("failed to migrate notifications table: %w", err)
		}
	} else {
		m := db.Migrator()
		for _, col := range []string{"ProjectID", "Title", "Link", "Severity"} {
			if !m.HasColumn(&models.Notification{}, col) {
				if err := m.AddColumn(&models.Notification{}, col); err != nil {
					return fmt.Errorf("failed to add notifications.%s column: %w", col, err)
				}
			}
		}
	}

	// Groups gained soft-delete (DeletedAt) + a partial unique index on name. On an
	// existing DB add the column and swap the plain unique index for the partial one
	// (additive, idempotent); the full AutoMigrate below covers fresh DBs.
	if groupsExists {
		if m := db.Migrator(); !m.HasColumn(&models.Group{}, "DeletedAt") {
			if err := m.AddColumn(&models.Group{}, "DeletedAt"); err != nil {
				return fmt.Errorf("failed to add groups.deleted_at column: %w", err)
			}
		}
		if err := ensureGroupNameIndex(db); err != nil {
			return err
		}
	}

	// Swap the plain unique index on users.username for a partial one (live rows only),
	// so a SCIM-deprovisioned username can be re-provisioned. Additive + idempotent; the
	// full AutoMigrate below covers fresh DBs.
	if tableExists(db, "users") {
		if err := ensureUserNameIndex(db); err != nil {
			return err
		}
		// Add a DB-level, case-insensitive, live-rows-only unique index on users.email
		// (#117): CreateUser/signup/invite-accept/SCIM provisioning previously enforced
		// email uniqueness only via a check-then-act read, letting concurrent creates for
		// the identical email all succeed and leaving GetUserByEmail to resolve to an
		// arbitrary one of the resulting rows. Additive + idempotent; the full AutoMigrate
		// below covers fresh DBs.
		if err := ensureUserEmailIndex(db); err != nil {
			return err
		}
		// Same DB-level protection for users.external_id (#117): the SCIM/IdP-asserted
		// identifier was indexed but NOT unique, so two different users could share the
		// same non-empty external_id — an ambiguity GetUserByExternalID (SSO/SCIM login
		// resolution) must not tolerate. Additive + idempotent; the full AutoMigrate
		// below covers fresh DBs.
		if err := ensureUserExternalIDIndex(db); err != nil {
			return err
		}
	}

	// Close the share-create race (#136): a partial unique index on live rows so two
	// concurrent CreateShareRecord calls for the same (secret, recipient, is_group)
	// can no longer both succeed as separate rows. Additive + idempotent; the full
	// AutoMigrate below covers fresh DBs (which get the index further down too).
	if tableExists(db, "share_records") {
		if err := ensureShareRecordUniqueIndex(db); err != nil {
			return err
		}
	}

	// Close the secret-version TOCTOU (#121): a unique index on (secret_node_id,
	// version_number) so two concurrent RotateSecret calls for the same secret can no
	// longer both write the same next version number. Additive + idempotent; the full
	// AutoMigrate below covers fresh DBs.
	if tableExists(db, "secret_versions") {
		if err := ensureSecretVersionIndex(db); err != nil {
			return err
		}
	}

	// Swap the plain unique index on projects.name for a case-insensitive, live-rows-
	// only partial one (#385): "Production"/"production" previously landed as two
	// distinct, all-succeeding rows, and the CLI's project name resolution
	// (resolveProjectID) is case-insensitive and returns the first match — so a
	// same-name-different-case shadow project the exact-match index didn't block could
	// silently hijack a later `keyorix secret import/export --project production`.
	// Additive + idempotent; the full AutoMigrate below covers fresh DBs.
	if projectsExists {
		if err := ensureProjectNameIndex(db); err != nil {
			return err
		}
	}

	// Skip full AutoMigrate if already initialised (projects table present).
	if projectsExists {
		return nil
	}
	if err := db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.SecretAccessLog{},
		&models.SecretMetadataHistory{},
		&models.ShareRecord{},
		&models.Session{},
		&models.PasswordReset{},
		&models.Tag{},
		&models.SecretTag{},
		// NOTE: Notification is intentionally NOT listed here — it is migrated by the
		// dedicated block above (create-if-absent / add-columns-if-present). Listing
		// it again re-inspects the just-created table and trips the pgx "insufficient
		// arguments" bug on a fresh Postgres first boot (same hazard as RotationPolicy).
		&models.AuditEvent{},
		&models.AuditCheckpoint{},
		&models.Setting{},
		&models.SystemMetadata{},
		&models.APIClient{},
		&models.APIToken{},
		&models.RateLimit{},
		&models.APICallLog{},
		&models.GRPCService{},
		&models.IdentityProvider{},
		&models.ExternalIdentity{},
		&models.AnomalyAlert{},
		// NOTE: RotationPolicy is intentionally NOT listed here. It is migrated
		// by the standalone block above (which runs before this guarded full
		// AutoMigrate and also covers existing DBs that predate the rotation
		// feature). Including it here too made the full AutoMigrate re-inspect
		// the already-created rotation_policies table, tripping the pgx
		// "insufficient arguments" bug on a fresh DB's first boot.
	); err != nil {
		return err
	}
	// The Group, User, and Project models carry no plain unique tag on
	// name/username/name; enforce uniqueness only among live rows via partial indexes
	// (so a soft-deleted name/username can be reused, e.g. on SCIM re-provisioning).
	if err := ensureGroupNameIndex(db); err != nil {
		return err
	}
	if err := ensureUserNameIndex(db); err != nil {
		return err
	}
	if err := ensureUserEmailIndex(db); err != nil {
		return err
	}
	if err := ensureUserExternalIDIndex(db); err != nil {
		return err
	}
	if err := ensureProjectNameIndex(db); err != nil {
		return err
	}
	if err := ensureShareRecordUniqueIndex(db); err != nil {
		return err
	}
	return ensureSecretVersionIndex(db)
}

// ensureShareRecordUniqueIndex creates a partial unique index on share_records
// (secret_id, recipient_id, is_group), scoped to live rows (#136). ShareRecord
// carried no DB constraint preventing two active share rows for the same
// (secret, recipient, is_group) tuple: CreateShareRecord's check-then-create is a
// read-then-write race, and a revoke-by-ID only ever removed one of the resulting
// duplicates, leaving access live after what looked like a successful single-share
// revoke. Idempotent; works on SQLite and Postgres.
func ensureShareRecordUniqueIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_share_records_active ON share_records (secret_id, recipient_id, is_group) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create partial share_records unique index: %w", err)
	}
	return nil
}

// ensureSecretVersionIndex creates a unique index on secret_versions
// (secret_node_id, version_number) closing the #121 TOCTOU: RotateSecret's
// GetLatestSecretVersion -> +1 -> storeSecretVersion sequence is a read-then-write
// race, empirically reproduced (100% of runs, 15 concurrent rotations) producing
// multiple rows sharing one version_number under the same secret_id. Idempotent;
// works on SQLite and Postgres.
func ensureSecretVersionIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_secret_versions_node_version ON secret_versions (secret_node_id, version_number)").Error; err != nil {
		return fmt.Errorf("failed to create secret_versions unique index: %w", err)
	}
	return nil
}

// ensureDynamicSecretConfigNameIndex creates a unique index on
// dynamic_secret_configs (project_id, environment_id, name), matching
// DynamicSecretConfig's doc comment ("one per (project, env, name)", #462).
// DynamicSecretConfig has no soft-delete column, so — unlike the partial indexes
// above — this is a plain (non-partial) unique index. Idempotent; works on SQLite
// and Postgres.
func ensureDynamicSecretConfigNameIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_dynamic_secret_configs_project_env_name ON dynamic_secret_configs (project_id, environment_id, name)").Error; err != nil {
		return fmt.Errorf("failed to create dynamic_secret_configs unique index: %w", err)
	}
	return nil
}

// ensureGroupNameIndex replaces any plain unique index on groups.name with a
// partial unique index scoped to non-deleted rows, so a soft-deleted group's name
// is freed for reuse while the group stays restorable. Idempotent; works on both
// SQLite and Postgres (both support partial indexes and IF [NOT] EXISTS).
func ensureGroupNameIndex(db *gorm.DB) error {
	// Drop the legacy plain unique index from the old `unique` tag, if present.
	if err := db.Exec("DROP INDEX IF EXISTS uni_groups_name").Error; err != nil {
		return fmt.Errorf("failed to drop legacy groups name index: %w", err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_groups_name_active ON groups (name) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create partial groups name index: %w", err)
	}
	return nil
}

// ensureProjectMembershipIndex creates a partial unique index enforcing at most one
// non-revoked ProjectMembership per (project, user) at the DB layer. InviteMember's
// own check-then-create ("one active onboarding per (project, user)") is a TOCTOU:
// two concurrent invites for the same pair can both pass the "no active membership"
// read before either commits its Create, producing two non-revoked rows (#309). The
// index makes the second concurrent Create fail with a constraint violation instead,
// which CreateProjectMembership/InviteMember translate into the same clean
// "already has a membership" error a sequential caller would get. Idempotent; mirrors
// ensureGroupNameIndex/ensureUserNameIndex (partial unique index, live rows only).
func ensureProjectMembershipIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active " +
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error; err != nil {
		return fmt.Errorf("failed to create partial project_memberships index: %w", err)
	}
	return nil
}

// ensureBreakGlassActiveIndex creates a partial unique index on
// break_glass_activations (project_id, user_id) WHERE state='active', so at most one
// ACTIVE break-glass activation can exist per project+user even under a race —
// ActivateBreakGlass's own "no existing active activation" check is a list-and-scan
// that two concurrent callers could both pass before either inserts; this index makes
// the database the actual source of truth. Scoped to state='active' (not a plain
// unique index) so a user can activate break-glass again after a prior activation
// expires or is revoked. Idempotent; works on both SQLite and Postgres.
func ensureBreakGlassActiveIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error; err != nil {
		return fmt.Errorf("failed to create partial break_glass_activations active index: %w", err)
	}
	return nil
}

// ensureUserNameIndex replaces the plain unique index on users.username (from the old
// `uniqueIndex` tag) with a partial unique index scoped to non-deleted rows. Without
// this a SCIM-deprovisioned (soft-deleted) user keeps occupying the username in the
// unique index, so re-provisioning the same userName collides on INSERT and the IdP's
// provisioning run errors indefinitely. Idempotent; works on SQLite and Postgres.
func ensureUserNameIndex(db *gorm.DB) error {
	// Drop the legacy plain unique index. GORM's `uniqueIndex` tag names it
	// idx_users_username; the older `unique` tag would be uni_users_username. Drop both.
	for _, idx := range []string{"idx_users_username", "uni_users_username"} {
		if err := db.Exec("DROP INDEX IF EXISTS " + idx).Error; err != nil {
			return fmt.Errorf("failed to drop legacy users username index %q: %w", idx, err)
		}
	}
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_username_active ON users (username) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create partial users username index: %w", err)
	}
	return nil
}

// ensureUserEmailIndex creates a partial, case-insensitive unique index on users.email
// scoped to live (non-deleted) rows with a non-empty email (#117). Without a DB-level
// constraint, email uniqueness was enforced only by a check-then-act read
// (GetUserByEmail) before each create/update, which is racy: two concurrent
// CreateUser/signup/invite-accept/SCIM-provision calls for the identical email could
// both pass their pre-check before either write landed, producing multiple rows sharing
// one email that GetUserByEmail then resolves to an arbitrary one of — an ambiguous
// login/identity-resolution bug, empirically reproduced at a 100% rate under
// concurrency. The index is on LOWER(email) to match GetUserByEmail's own
// case-insensitive lookup (`LOWER(email) = LOWER(?)`) — an exact-match index would let
// the race slip through on a case variant (Bob@x vs bob@x). Scoped to
// `deleted_at IS NULL` so a soft-deleted (e.g. SCIM-deprovisioned) user's email is freed
// for reuse on re-provisioning, mirroring ensureUserNameIndex; `email <> ”` so any
// legacy rows with no email recorded don't collide with each other. Idempotent; works on
// both SQLite and Postgres (both support expression indexes, partial indexes, and
// IF [NOT] EXISTS).
func ensureUserEmailIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error; err != nil {
		return fmt.Errorf("failed to create partial users email index: %w", err)
	}
	return nil
}

// ensureUserExternalIDIndex creates a partial unique index on users.external_id,
// scoped to live rows with a non-empty external_id (#117). external_id (the
// SCIM/IdP-asserted identifier) was indexed but NOT unique, explicitly
// documented as allowing "legacy/blank rows [to] coexist" — but two DIFFERENT
// users sharing the same non-empty external_id is exactly the ambiguity SSO/
// SCIM identity resolution (GetUserByExternalID) must not tolerate: which one
// does a federated login authenticate as? Empty external_id (every locally-
// created account) is excluded so native users never collide with each other.
// Idempotent; works on SQLite and Postgres.
func ensureUserExternalIDIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_external_id_active ON users (external_id) WHERE deleted_at IS NULL AND external_id != ''").Error; err != nil {
		return fmt.Errorf("failed to create partial users external_id index: %w", err)
	}
	return nil
}

// ensureProjectNameIndex creates a partial, case-insensitive unique index on
// projects.name scoped to live (non-deleted) rows with a non-empty name (#385).
// Project.Name previously carried only a plain, case-sensitive `uniqueIndex` tag, so
// "Production"/"production" (and any other case variant) were distinct, both-succeeding
// rows — and the CLI's project name resolution (resolveProjectID, import.go) resolves by
// case-insensitive comparison over an unordered project list, returning the FIRST match.
// A secrets.write holder could therefore plant a same-name-different-case shadow project
// the old index didn't block, and a later `keyorix secret import/export --project
// production` could silently resolve against the shadow project instead of the intended
// one. The index is on LOWER(name) so it catches every case variant, mirroring
// ensureUserEmailIndex's treatment of users.email (#117) for the identical
// shadow-identity class of bug. Scoped to `deleted_at IS NULL` so a soft-deleted
// project's name is freed for reuse on re-creation, mirroring ensureGroupNameIndex/
// ensureUserNameIndex; `name <> ”` so any legacy rows with no name recorded don't
// collide with each other. Idempotent; works on both SQLite and Postgres.
//
// Known residual limitation: this closes the case-folding gap but not the
// Unicode-homoglyph one — "Prοduction" (Greek omicron, U+03BF) still normalizes to a
// distinct LOWER() value from "production" and would still create a separate row. Full
// NFKC normalization plus homoglyph/confusable detection is a materially harder problem
// (Unicode Technical Standard #39) and is intentionally out of scope here.
func ensureProjectNameIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_projects_name_active ON projects (LOWER(name)) WHERE deleted_at IS NULL AND name <> ''").Error; err != nil {
		return fmt.Errorf("failed to create partial projects name index: %w", err)
	}
	return nil
}

// ensureLegalHoldActiveIndex creates a partial unique index that permits at most one
// un-released (released = false) row in legal_holds at a time, closing the
// place-hold TOCTOU race (#305): since every row matching the predicate shares the
// same released=false value, uniqueness on that column caps the table at one such
// row, and a second concurrent INSERT is rejected by the DB instead of silently
// creating an orphaned duplicate hold. Idempotent; works on both SQLite and Postgres
// (both support partial indexes and IF NOT EXISTS).
func ensureLegalHoldActiveIndex(db *gorm.DB) error {
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active ON legal_holds (released) WHERE released = false").Error; err != nil {
		return fmt.Errorf("failed to create partial legal_holds active index: %w", err)
	}
	return nil
}
