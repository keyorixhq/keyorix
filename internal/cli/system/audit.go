package system

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit critical files for permissions and ownership",
	Run: func(cmd *cobra.Command, args []string) {
		runAudit()
	},
}

// auditCmd is now added to SystemCmd in system.go

func runAudit() {
	cfg, err := config.Load("keyorix.yaml") // Use default config file name
	if err != nil {
		fmt.Println("Failed to load config:", err)
		os.Exit(1)
	}

	files := []securefiles.FilePermSpec{
		{Path: "keyorix.yaml", Mode: 0600},
		{Path: cfg.Storage.Encryption.KEKPath, Mode: 0600},
		{Path: cfg.Storage.Encryption.DEKPath, Mode: 0600},
	}

	err = securefiles.FixFilePerms(files, false) // false = audit only
	if err != nil {
		fmt.Println("\nAudit finished with warnings/errors. Please fix the issues.")
		os.Exit(1)
	}

	fmt.Println("✅ Audit passed: all critical files have correct permissions and ownership.")
}
