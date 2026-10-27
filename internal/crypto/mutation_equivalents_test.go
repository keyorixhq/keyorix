package crypto

// Mutants that gremlins (v0.6.0) still reports on internal/crypto after the
// #3612 work, and why no test can (or should) kill them. Re-run with
// `gremlins unleash --workers 2 ./internal/crypto`; the expected leftover set is
// exactly the list below. A mutant that shows up and is NOT listed here is a new
// survivor and needs an assertion.
//
// EQUIVALENT (the mutated program behaves identically for every input):
//
//   - multi_provider.go:69:43  `i > 0` -> `i >= 0`. At i == 0 the provider is
//     providers[0], whose tier initialises maxTier, so `tier < maxTier` is false
//     for it regardless of the `i > 0` guard. The guard is only a readability
//     short-cut. (Observable only if Name() returned different tiers on two
//     consecutive calls, which no provider here does.)
//   - multi_provider.go:85:39  `t > maxTier` -> `t >= maxTier`. On equality the
//     assignment `maxTier = t` stores the value maxTier already has.
//   - provider_tier.go:114:8   the same `t > maxTier` -> `t >= maxTier` in
//     DetectFallbackDowngrade; same reason.
//
// NON-TERMINATING (reported TIMED OUT, which gremlins counts neither as killed
// nor lived; the run is cut off by the timeout rather than by an assertion):
//
//   - shamir.go:40:8  `e > 0` -> `e >= 0` in gfPow: e is shifted right until it
//     reaches 0, so with `>= 0` the loop never ends.
//
// NOT COVERED BY CONSTRUCTION (gremlins decides "covered" from the Go coverage
// profile, which has no block for a const declaration or for a `case` expression).
// No test can move these out of the NOT COVERED count; each was instead applied by
// hand to a scratch copy (MUTANT-RESIDUAL-1) and the named test fails under it:
//
//   - exec_provider.go:16:27, kms_provider.go:48:27  `30 * time.Second`
//     (TestTimeoutConstants pins both values).
//   - shamir_provider.go:39:40, :44  kekFrameLen (TestKEKFrameLen pins it, and
//     every SplitKEK/combineKEK test depends on it).
//   - passphrase.go:76:20, :111:20  `case src.FilePath != ""` in
//     ResolvePassphrase / Describe. Both behaviours are asserted
//     (TestResolvePassphrase_File*, TestPassphraseSource_Describe); the case
//     expression is simply not a coverage block.
//   - shamir_provider.go:39:44  `+ KEKSize` -> `- KEKSize` makes the const
//     negative, so the package no longer compiles (gremlins: not viable).
//
// NOT COVERED, REACHABLE ONLY WITH A TERMINAL:
//
//   - passphrase.go:181:10, :184:13  the term.ReadPassword error / empty-input
//     branches of readPassphraseStdin run only when stdin is a TTY. Exercising
//     them needs a pty. MUTANT-RESIDUAL-1 tried one (no new dependency: x/sys
//     is already direct): opening /dev/ptmx fails with "operation not permitted"
//     in the macOS sandbox these sessions run in, so no pty test is committed
//     (an unrun test proves nothing). A pty test is the way to kill them where
//     /dev/ptmx opens: type "s3cret\n", "\n" and Ctrl-D on the master with the
//     slave as os.Stdin and expect the passphrase, "no passphrase entered" and
//     "reading passphrase from terminal: ...".
