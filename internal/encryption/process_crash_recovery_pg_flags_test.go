//go:build !windows

package encryption_test

// process_crash_recovery_pg_flags_test.go holds the options of the PostgreSQL
// crash-recovery sweeps, passed after -args. Unset, every sweep skips and the
// default go test run does only the calibration and red-proof tests.

import "flag"

var (
	pcrashFlagExhaustive    = flag.Bool("pcrash.exhaustive", false, "run the kill-point sweeps")
	pcrashFlagOps           = flag.String("pcrash.ops", "", "comma list of operations to sweep (default all)")
	pcrashFlagMode          = flag.String("pcrash.mode", pcrashPGModeKill, "kill or cut")
	pcrashFlagOutcomes      = flag.String("pcrash.outcomes", "", "directory for one TSV line per exec")
	pcrashFlagDropLeftovers = flag.String("pcrash.drop-leftovers", "", "drop leftover generated w5_ databases: exec (clones only) or all")
	pcrashFlagWorld         = flag.String("pcrash.world", "", "directory that keeps the template install and calibrations between runs")
	pcrashFlagBudget        = flag.Duration("pcrash.budget", 0, "start no new exec this long after the sweep began (0: no limit)")
	pcrashFlagMaxPer        = flag.Int("pcrash.maxper", 0, "cap the non-essential kill points per operation, evenly spaced (0: keep all)")
)
