package admin

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
)

// migrate is NEW (not a port): explicitly runs pending migrations, reusing
// the SAME migration code the server itself runs at every boot
// (internal/storage/factory.go's migrateDatabase, via CreateStorage) rather
// than a separate implementation -- per ADR-108 §B1's "migrate" bullet and
// this repo's "prefer the machine-checked over the asserted" principle: one
// migration implementation, not two that could drift. Idempotent: safe to
// run against an already-up-to-date database. Never starts a listener.
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply pending database migrations",
	Long: `Opens the database via the same storage factory the server uses at boot,
which applies any pending migration as an ordinary, idempotent side effect
of opening. Does not start a listener.`,
	RunE: runAdminMigrate,
}

func runAdminMigrate(cmd *cobra.Command, args []string) error {
	fmt.Println("Keyorix Server Admin: migrate")
	fmt.Println("==============================")

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := refuseIfServerRunning(cfg); err != nil {
		return err
	}

	fmt.Println("Applying pending migrations (idempotent — safe to re-run)...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	recordAdminAction(cfg, "admin.migrate", "ran `keyorix-server admin migrate` — database migrated successfully", true)
	return nil
}
