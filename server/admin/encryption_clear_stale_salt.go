package admin

// encryption_clear_stale_salt.go implements `keyorix-server admin encryption
// clear-stale-salt-pending` (#4105): the explicit operator action that removes
// a KEK salt staging file (<salt_path>.pending) an interrupted rotate-kek left
// and a successful server start proved unused. Until it is gone every
// `admin backup` is refused. Boot never removes it, and `admin backup` never
// does either; this command is the only place that does, and only when it has
// proved again, itself, that the file is unused.
//
// It never removes, moves or writes a DEK's staging file (<dek_path>.pending):
// that can be the only copy of the new DEK, so its presence is a refusal.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

const clearStaleSaltCmdName = "clear-stale-salt-pending"

// clearStaleSaltEventType is the audit event of a removal.
const clearStaleSaltEventType = "admin.encryption.clear_stale_salt_pending"

var encClearStaleSaltDryRun bool

var encClearStaleSaltCmd = &cobra.Command{
	Use:   "clear-stale-salt-pending", // a literal: cmd/statemapgen reads Use only as one (clearStaleSaltCmdName)
	Short: "Remove an unused KEK salt staging file that blocks every admin backup",
	Long: `Removes <salt_path>.pending (kek.salt.pending), the KEK salt staging file an
interrupted rotate-kek can leave when it stopped before it changed the active
keys. A server start that succeeds leaves the file in place with a warning, and
every later 'admin backup' is refused while it exists (exit status 4).

The file is removed only when ALL of these hold, each checked by this command
itself while it holds this tree's exclusive database lock and the exclusive key
lock rotate-kek holds for its whole run (so no rotate-kek, server or other admin
command runs beside it):
  - no DEK staging file (<dek_path>.pending) is present: that one can be the
    only copy of the new DEK and is never removed, by this or any command;
  - the key-set manifest does not need the file (no interrupted operation boot
    would still finish from it);
  - the active key set opens with the current master passphrase without the
    file: the DEK is unwrapped under the active KEK, the same proof a server
    start makes.
In every other case it refuses, says why, and changes nothing. A removal is
recorded in the audit chain (` + clearStaleSaltEventType + `).

Idempotent: with no salt staging file present it prints that there is nothing
to do and exits 0. --dry-run makes every check and prints the decision without
removing anything or writing an audit event. Stop the server first.`,
	RunE: runEncClearStaleSalt,
}

func init() {
	encClearStaleSaltCmd.Flags().BoolVar(&encClearStaleSaltDryRun, "dry-run", false,
		"make every check and print the decision without removing anything")
	encryptionCmd.AddCommand(encClearStaleSaltCmd)
}

func runEncClearStaleSalt(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	removed, err := clearStaleSaltPending(cfg, encClearStaleSaltDryRun)
	if err != nil || removed == "" || encClearStaleSaltDryRun {
		return err
	}
	recordAdminAction(cfg, clearStaleSaltEventType, fmt.Sprintf(
		"ran `keyorix-server admin encryption clear-stale-salt-pending`: removed %s, a KEK salt staging file left by an "+
			"interrupted rotate-kek (no DEK staging file present, the active key set opened with the current passphrase without it)",
		removed), true)
	return nil
}

// clearStaleSaltRefusal prefixes every refusal, so each says that nothing changed.
func clearStaleSaltRefusal(format string, a ...any) error {
	return fmt.Errorf("%s refused, nothing was removed: %s", clearStaleSaltCmdName, fmt.Sprintf(format, a...))
}

// clearStaleSaltPending runs the checks and, unless dryRun, removes the salt
// staging file. It returns the path removed (or, with dryRun, the path that
// would be), "" when there is nothing to do.
func clearStaleSaltPending(cfg *config.Config, dryRun bool) (string, error) {
	enc := &cfg.Storage.Encryption
	if !enc.Enabled {
		return "", clearStaleSaltRefusal("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return "", clearStaleSaltRefusal("it must run on the server host, against the key directory")
	}
	if err := restorejournal.RefuseIfPresent(cfg); err != nil {
		return "", clearStaleSaltRefusal("%v", err)
	}
	// The locks rotate-kek holds for its whole run, in its order: the database
	// lock (a live server, rotate-kek or another admin command refuses it),
	// then the exclusive key-directory lock (dek.lock), which --force does not
	// bypass.
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return "", clearStaleSaltRefusal("%v", err)
	}
	defer lock.Release() //nolint:errcheck
	svc := encryption.NewService(enc, ".")
	defer svc.Shutdown()
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return "", clearStaleSaltRefusal("%v", encryption.WithLockContentionHint(err,
			"a server or a key operation such as `admin encryption rotate-kek` is using this key directory; stop it or let it finish, then run this again"))
	}

	salt, err := keyfiles.StaleSaltPendingCandidate(enc, ".")
	if err != nil {
		return "", clearStaleSaltRefusal("%v", err)
	}
	if salt == "" {
		fmt.Println("nothing to do: no KEK salt staging file is present, and `admin backup` is not refused for one")
		return "", nil
	}
	fmt.Printf("Found %s. Checking that the active key set opens with the current passphrase without it...\n", salt)

	// The proof: unwrap the DEK under the active KEK (the active salt and the
	// passphrase), as a server start does. Never against a set it would have
	// to generate: StaleSaltPendingCandidate refused a fresh or partial one.
	if !svc.WrappedDEKExists() {
		return "", clearStaleSaltRefusal("the wrapped DEK is not present, so nothing proves %s unused", salt)
	}
	passphrase, err := encryptionops.MasterPassphrase(cfg, encPassphraseSource)
	if err != nil {
		return "", clearStaleSaltRefusal("%v", err)
	}
	if err := svc.Initialize(passphrase); err != nil {
		return "", clearStaleSaltRefusal("the active key set does not open with the current passphrase without %s (%v). "+
			"The file may be the salt an interrupted rotate-kek needs, so it is left in place: if the server does not start "+
			"either, follow \"Interrupted rotate-kek or migrate-provider\" in docs/operator/key-rotation-runbook.md", salt, err)
	}

	// Once more, still under both locks: nothing may have appeared since.
	again, err := keyfiles.StaleSaltPendingCandidate(enc, ".")
	if err != nil {
		return "", clearStaleSaltRefusal("%v", err)
	}
	if again != salt {
		return "", clearStaleSaltRefusal("the key directory changed while it was checked (%q, then %q)", salt, again)
	}
	if dryRun {
		fmt.Printf("dry run: would remove %s (no DEK staging file is present, and the active key set opens with the current "+
			"passphrase without it); nothing was removed\n", salt)
		return salt, nil
	}
	if err := removeStaleSaltPending(salt); err != nil {
		return "", err
	}
	fmt.Printf("removed %s. Run `keyorix-server admin backup` again.\n", salt)
	return salt, nil
}

// removeStaleSaltPending removes path, the salt staging file and nothing else,
// and makes the removal durable. A symlink is removed as a link, never followed.
func removeStaleSaltPending(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return clearStaleSaltRefusal("%s disappeared while it was checked", path)
		}
		return fmt.Errorf("%s: remove %s: %w", clearStaleSaltCmdName, path, err)
	}
	if err := securefiles.SyncDir(filepath.Dir(path)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removed %s, but could not fsync %s: %v; the removal may not survive a power loss\n",
			path, filepath.Dir(path), err)
	}
	return nil
}
