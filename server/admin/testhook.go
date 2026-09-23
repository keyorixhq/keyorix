package admin

// testhook.go: a TEST-ONLY hidden command that holds this database's
// exclusive lock (internal/serverguard.AcquireExclusive) until stdin closes,
// signalling readiness on stdout first. It exists so integration tests can
// deterministically hold the lock across a concurrent server-startup
// attempt, without racing a real command's own (often sub-second) actual
// work. Hidden from `admin --help`; never documented for operator use;
// never a security boundary of its own (holding a lock is not a mutation).

import (
	"bufio"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/spf13/cobra"
)

var holdLockForTestCmd = &cobra.Command{
	Use:    "__hold-lock-for-test",
	Hidden: true,
	RunE:   runHoldLockForTest,
}

func init() {
	rootCmd.AddCommand(holdLockForTestCmd)
}

func runHoldLockForTest(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := serverguard.AcquireExclusive(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	fmt.Println("LOCKED")
	// Block until the parent test either closes our stdin or writes a line
	// to it -- either way, ReadString returns and we release on defer.
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return nil
}
