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
		TLSVerify:      cfg.Storage.Remote.TLSVerify,
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

	// Create project_invitations / access_requests if missing (ADR-024, additive).
	if !invitationsExists {
		if err := db.AutoMigrate(&models.ProjectInvitation{}); err != nil {
			return fmt.Errorf("failed to migrate project_invitations table: %w", err)
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
		&models.Notification{},
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
