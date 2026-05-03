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

// migrateDatabase performs database migrations
func (f *DefaultStorageFactory) migrateDatabase(db *gorm.DB) error {
	// Always run additive migrations for new tables (safe on existing DBs)
	createStatsTable := `CREATE TABLE IF NOT EXISTS stats_snapshots (
		id BIGSERIAL PRIMARY KEY,
		user_id BIGINT,
		total_secrets BIGINT DEFAULT 0,
		shared_secrets INTEGER DEFAULT 0,
		secrets_shared_with_me INTEGER DEFAULT 0,
		snapshot_date TIMESTAMP WITH TIME ZONE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	)`
	// Use raw SQL for cross-db compatibility check
	if db.Migrator().HasTable("stats_snapshots") {
		// Table exists, nothing to do
	} else {
		if err := db.Exec(createStatsTable).Error; err != nil {
			return fmt.Errorf("failed to migrate stats_snapshots table: %w", err)
		}
		// Create indexes
		db.Exec("CREATE INDEX IF NOT EXISTS idx_stats_snapshots_user_id ON stats_snapshots(user_id)")
		db.Exec("CREATE INDEX IF NOT EXISTS idx_stats_snapshots_snapshot_date ON stats_snapshots(snapshot_date)")
	}

	// Add LastRotatedAt to secret_nodes if not present
	if !columnExists(db, "secret_nodes", "last_rotated_at") {
		db.Exec("ALTER TABLE secret_nodes ADD COLUMN last_rotated_at TIMESTAMP WITH TIME ZONE")
	}

	// Check if namespaces table exists — if so, skip full migration (already initialized)
	// Always create new tables that may have been added after initial setup
	if !db.Migrator().HasTable("anomaly_alerts") {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id BIGSERIAL PRIMARY KEY,
            secret_node_id BIGINT,
            secret_name TEXT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            accessed_by TEXT,
            ip_address TEXT,
            detected_at TIMESTAMP WITH TIME ZONE,
            acknowledged BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )`).Error; err != nil {
			return fmt.Errorf("failed to create anomaly_alerts table: %w", err)
		}
		db.Exec("CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_secret_node_id ON anomaly_alerts(secret_node_id)")
		db.Exec("CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_detected_at ON anomaly_alerts(detected_at)")
	}

	if db.Migrator().HasTable("namespaces") {
		return nil
	}
	return db.AutoMigrate(
		&models.Namespace{},
		&models.Zone{},
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
	)
}
