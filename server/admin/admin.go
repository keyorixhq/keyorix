// Package admin implements `keyorix-server admin <cmd>` (ADR-108 §B, PR 11):
// offline, host-side operations that need direct access to the database and
// key files on the server host, run as subcommands of the server binary
// rather than a third binary (the server binary already links core and
// storage). No admin command ever starts an HTTP or gRPC listener.
package admin

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// adminActorType tags every audit event an admin command writes, so a reader
// can tell a host-side `keyorix-server admin` action apart from an ordinary
// "system" (scheduler/startup) event or a "user"/"machine_identity" one.
const adminActorType = "admin_cli"

var rootCmd = &cobra.Command{
	Use:   "admin",
	Short: "Host-side operations that need direct database and key-file access",
	Long: `keyorix-server admin -- operations that must not, or cannot, go through the
network API (ADR-108 §B): the server can't start, everyone is locked out, or
the operation needs the database to itself. These need shell access on the
server host, plus the database and key files -- owning the host is the
authority. No admin command starts an HTTP or gRPC listener.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var (
	configPathFlag string
	forceFlag      bool
)

func init() {
	rootCmd.PersistentFlags().StringVar(&configPathFlag, "config", "", "Path to config file (defaults to $KEYORIX_CONFIG_PATH or keyorix.yaml)")
	rootCmd.PersistentFlags().BoolVar(&forceFlag, "force", false, "Run even if a live server appears to be attached to this database")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(diagnoseCmd)
	rootCmd.AddCommand(migrateCmd)
}

// Execute runs the admin command tree against args (os.Args[2:] -- the
// portion after "admin") and returns a process exit code.
func Execute(args []string) int {
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

// loadConfig resolves and loads the config file the same way every other
// admin command does: --config (persistent flag), else
// config.ResolvedPath's own KEYORIX_CONFIG_PATH/keyorix.yaml resolution.
//
// Unlike internal/cli/common's CLI-side loaders, a blank storage.type IS
// defaulted to "local" here -- mirroring server/main.go's own
// #G-blank-storage-default boot behavior, not the CLI's. This package is
// part of the SERVER binary and operates on the same on-prem, no-`storage:`-
// block deployment shape the plain server boots against; a CLI command
// reached through a *different* binary is not this caller.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(configPathFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	return cfg, nil
}

// refuseIfServerRunning is the shared guard every admin command runs before
// doing anything: refuse to proceed if a live server appears to be attached
// to cfg's database, unless the operator passed --force. See
// internal/serverguard's package doc for the detection mechanism and its
// limits.
func refuseIfServerRunning(cfg *config.Config) error {
	if forceFlag {
		return nil
	}
	running, detail, err := serverguard.ProbeRunning(cfg)
	if err != nil {
		return fmt.Errorf("could not determine whether a server is running against this database: %w", err)
	}
	if running {
		return fmt.Errorf("a Keyorix server appears to be running against this database (%s) — admin commands must not run concurrently with a live server; stop it first, or pass --force if you are certain this is safe", detail)
	}
	return nil
}

// withUsableStorage opens cfg's database via the same storage factory the
// server itself uses (which also applies any pending migration as a normal
// side effect of opening -- see internal/storage/factory.go's
// migrateDatabase, idempotent on an already-migrated database) and runs fn
// against it. Used by state-changing admin commands to write their audit
// event "where the DB is usable" (task requirement): a database that cannot
// even be opened is, by definition, not usable, and callers report that
// distinctly from the admin action's own success/failure rather than fail
// the whole command over it.
func withUsableStorage(cfg *config.Config, fn func(store corestorage.Storage) error) error {
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		return fmt.Errorf("database not usable: %w", err)
	}
	return fn(st)
}

// recordAdminAction writes an audit-chain event for a state-changing admin
// command and prints what it did (both parts of the task-2 requirement).
// Best-effort on the audit write: if the database isn't usable yet (e.g.
// `admin init` running against a brand-new, not-yet-migrated database on a
// backend the factory then fails to open for some unrelated reason), the
// command's own outcome is not affected -- this only ever downgrades to a
// printed note, never a hard failure, since the primary action already
// happened (or didn't) on its own terms before this is called.
func recordAdminAction(cfg *config.Config, eventType, description string, success bool) {
	fmt.Println(description)
	err := withUsableStorage(cfg, func(st corestorage.Storage) error {
		ok := success
		return st.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType:   eventType,
			Description: description,
			Success:     &ok,
			ActorType:   adminActorType,
			EventTime:   time.Now(),
		})
	})
	if err != nil {
		fmt.Printf("note: could not record this action to the audit chain (%v)\n", err)
	}
}

// closeGormDB closes a raw *gorm.DB opened via storage.OpenGormDB. Best
// effort: a close failure on a short-lived CLI-style process is not worth
// failing an otherwise-successful command over.
func closeGormDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
