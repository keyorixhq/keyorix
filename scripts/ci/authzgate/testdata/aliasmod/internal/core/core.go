// Package core is the calibration fixture of
// TestEveryRootReferenceIsInTheTriggerSet: Direct and newChecker name the
// root and are in the trigger set by name; Gate and viaParam reach it only
// through a function value and must be reported.
package core

type KeyorixCore struct{}

func (c *KeyorixCore) Authorize() bool { return true }

type checker struct{ check func() bool }

func newChecker(c *KeyorixCore) checker { return checker{check: c.Authorize} }

func (k checker) Gate() bool { return k.check() }

func Direct(c *KeyorixCore) bool { return c.Authorize() }

func viaParam(f func() bool) bool { return f() }

func Caller(c *KeyorixCore) bool { return viaParam(c.Authorize) }
