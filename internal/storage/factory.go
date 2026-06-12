package storage

import (
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

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
	default: // "local", "" or any other value defaults to SQLite
		return f.createLocalStorage(cfg)
	}
}

// createLocalStorage creates a SQLite-backed local storage instance
func (f *DefaultStorageFactory) createLocalStorage(cfg *config.Config) (storage.Storage, error) {
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
		return nil, err
	}

	if err := f.migrateDatabase(db); err != nil {
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

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
		return nil, err
	}

	if err := f.migrateDatabase(db); err != nil {
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
	if dbCfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(dbCfg.MaxOpenConns)
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

	// Create rotation_policies if missing (additive, safe on existing DBs).
	if !rotationExists {
		if err := db.AutoMigrate(&models.RotationPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate rotation_policies table: %w", err)
		}
	}

	// Create personal_access_tokens if missing (ADR-027, additive, safe on existing DBs).
	if !patExists {
		if err := db.AutoMigrate(&models.PersonalAccessToken{}); err != nil {
			return fmt.Errorf("failed to migrate personal_access_tokens table: %w", err)
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

	// Create the dynamic-secrets tables if missing (ADR-035, additive).
	if !dynConfigExists {
		if err := db.AutoMigrate(&models.DynamicSecretConfig{}); err != nil {
			return fmt.Errorf("failed to migrate dynamic_secret_configs table: %w", err)
		}
	}
	if !dynLeaseExists {
		if err := db.AutoMigrate(&models.DynamicSecretLease{}); err != nil {
			return fmt.Errorf("failed to migrate dynamic_secret_leases table: %w", err)
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
	}

	// Create machine-token tables if missing (ADR-030, additive, safe on existing DBs).
	if !machineCredExists {
		if err := db.AutoMigrate(&models.MachineIdentityCredential{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_credentials table: %w", err)
		}
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
		for _, col := range []string{"ProjectID", "Title", "Link"} {
			if !m.HasColumn(&models.Notification{}, col) {
				if err := m.AddColumn(&models.Notification{}, col); err != nil {
					return fmt.Errorf("failed to add notifications.%s column: %w", col, err)
				}
			}
		}
	}

	// Skip full AutoMigrate if already initialised (projects table present).
	if projectsExists {
		return nil
	}
	return db.AutoMigrate(
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
	)
}
