// Package toy is a self-contained fixture module for oraclehealth's own
// red/green proof. It has one tiny function under test and two fuzz targets
// over it: a WEAK oracle that only checks a necessary-but-insufficient property
// and a STRONG oracle that checks the function against an independent reference.
// A behaviour-changing mutant (negate-cond on Max's branch) must SURVIVE the
// weak oracle and be KILLED by the strong one. That gap is exactly what
// oraclehealth exists to measure, so the fixture doubles as the tool's own test.
package toy

// Max returns the larger of a and b. The `if a > b` branch is the mutation
// site the proof targets: negating it turns Max into min, which still returns
// one of its inputs (weak oracle cannot tell) but is no longer the maximum
// (strong oracle can).
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
