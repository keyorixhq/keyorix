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

	// Create rotation_policies table if it doesn't exist yet (additive, safe on existing DBs).
	if !tableExists(db, "rotation_policies") {
		if err := db.AutoMigrate(&models.RotationPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate rotation_policies table: %w", err)
		}
	}

	// Skip full AutoMigrate if already initialised (projects table present).
	if tableExists(db, "projects") {
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
