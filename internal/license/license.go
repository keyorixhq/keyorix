// Package license re-exports pkg/licenseverify's offline license API (ADR-065, ADR-062
// Phase 2) so the server (Gate) and the old CLI (internal/cli/license) keep compiling
// unchanged after FINISH-SPLIT step 2 (docs/cli-split-inventory.md §7 PR 10) moved the
// actual issue/evaluate logic to pkg/licenseverify, a public leaf package the separate cli/
// module can import without pulling in internal/core, internal/storage, internal/config, or
// any cloud SDK. Every symbol below is the SAME code as pkg/licenseverify's, not a
// duplicate -- see that package for the real implementation and its tests.
package license

import "github.com/keyorixhq/keyorix/pkg/licenseverify"

type License = licenseverify.License
type State = licenseverify.State
type Status = licenseverify.Status
type Gate = licenseverify.Gate

const (
	StateActive       = licenseverify.StateActive
	StateExpiringSoon = licenseverify.StateExpiringSoon
	StateExpired      = licenseverify.StateExpired
	StateInvalid      = licenseverify.StateInvalid
	StateNone         = licenseverify.StateNone

	FeatureAirgapUpdates = licenseverify.FeatureAirgapUpdates
	FeatureBilling       = licenseverify.FeatureBilling
)

var (
	Issue              = licenseverify.Issue
	Evaluate           = licenseverify.Evaluate
	ParsePrivateKeyPEM = licenseverify.ParsePrivateKeyPEM
	NewGate            = licenseverify.NewGate
)
