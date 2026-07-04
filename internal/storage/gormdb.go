package storage

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// OpenGormDB opens a raw *gorm.DB for the configured local backend, switching on
// cfg.Storage.Type with the same mapping the factory uses (postgres/postgresql →
// Postgres, local/"" → SQLite, anything else rejected — #463) and applying the
// same connection-pool settings via applyPoolSettings.
//
// Unlike the factory's CreateStorage, it deliberately does NOT run migrations: it
// exists for the handful of CLI admin commands that need a raw *gorm.DB the
// storage.Storage interface cannot provide — the DEK rotation sweep, which owns
// its own transaction (ADR-010), and the auth-encryption statistics counters.
// Those commands operate on an already-initialized database and must not trigger
// schema changes as a side effect, so migration stays CreateStorage's job. This
// keeps every GORM driver import inside internal/storage rather than in the CLI
// command files (ADR-049).
//
// Remote storage has no local *gorm.DB; these are host-local admin commands and
// require a non-remote backend.
func OpenGormDB(cfg *config.Config) (*gorm.DB, error) {
	switch cfg.Storage.Type {
	case "remote":
		return nil, fmt.Errorf("this command needs direct database access and cannot run against a remote backend; run it on the server host")
	case "postgres", "postgresql":
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
		return db, nil
	case "local", "":
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		db, err := gorm.Open(sqlite.Open(sqliteDSN(dbPath)), gormConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
			return nil, err
		}
		return db, nil
	default:
		// #463: defense in depth, mirroring the factory's own hardening — these
		// CLI admin commands run without going through Config.Validate() first,
		// so a typo'd storage.type must not silently open a local SQLite file
		// disconnected from the operator's intended (e.g. shared Postgres) backend.
		return nil, fmt.Errorf("invalid storage.type %q: must be one of \"local\", \"postgres\", \"postgresql\", or \"remote\"", cfg.Storage.Type)
	}
}
