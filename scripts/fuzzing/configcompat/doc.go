// Package configcompat is a config COMPATIBILITY fuzzer across releases.
//
// Operators upgrade Keyorix by pointing a new release at their existing config
// file. A new release must either load that file with the same meaning, or
// refuse it with an error that NAMES the offending key — it must fail closed,
// never silently change a security posture. This harness takes config files
// that were valid for earlier releases (the real shipped example files pulled
// from old git tags, plus the deprecated key names reconstructed from the
// schema's own history and the committed alias table) and differentially
// checks them against HEAD.
//
// It reuses, rather than copies, the configspace fuzzer: the posture model
// (configspace.LoadModel / Model.PostureHolds / PostureRule.Explicit), the
// masked-refusal signature idea (refusal.go), and the config package's own
// alias table (config.DeprecatedSettingAliasPaths) and insecure-settings
// registry (config.InsecureSettingsRegistry) as the "security-relevant
// effective values" it compares.
//
// Three invariants (each independently plantable, see compat_test.go):
//
//	I1  fail-closed load & named refusal — Load never panics, the verdict is
//	    deterministic, and a refusal of a file that carries a key must name a
//	    key; no canary value leaks in an error.
//	I2  no silently-weakened posture — a posture predicate that holds must be
//	    explained by an explicit opt-in key (old or new name) or be a
//	    documented default (default_posture.tsv). A weakened default is a
//	    FINDING.
//	I3  deprecated-alias meaning preserved — a config using a deprecated old
//	    key loads at HEAD, records a warning that names the old key, and has a
//	    security fingerprint identical to the same config written with the new
//	    key name. A genuinely unknown key must be refused by name.
//
// The fuzz target is FuzzConfigCompat. RULES.md and README.md document the
// oracle and, per oracle, what it does NOT verify.
package configcompat
