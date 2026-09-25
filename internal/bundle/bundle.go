// Package bundle re-exports pkg/bundleverify's air-gapped update-bundle API (ADR-064,
// ADR-062 Phase 1a) so the old CLI (internal/cli/bundle) keeps compiling unchanged after
// FINISH-SPLIT step 2 (docs/cli-split-inventory.md §7 PR 10) moved the actual
// build/sign/verify/extract logic to pkg/bundleverify, a public leaf package the separate
// cli/ module can import without pulling in internal/core, internal/storage,
// internal/config, or any cloud SDK. Every symbol below is the SAME code as
// pkg/bundleverify's, not a duplicate -- see that package for the real implementation and
// its tests.
package bundle

import "github.com/keyorixhq/keyorix/pkg/bundleverify"

type Manifest = bundleverify.Manifest
type Component = bundleverify.Component

var (
	ErrNoManifest         = bundleverify.ErrNoManifest
	ErrDigestMismatch     = bundleverify.ErrDigestMismatch
	ErrUnlistedComponent  = bundleverify.ErrUnlistedComponent
	ErrMissingComponent   = bundleverify.ErrMissingComponent
	ErrNotUpgrade         = bundleverify.ErrNotUpgrade
	ErrUpgradeSkipped     = bundleverify.ErrUpgradeSkipped
	ErrEntryTooLarge      = bundleverify.ErrEntryTooLarge
	ErrTooManyEntries     = bundleverify.ErrTooManyEntries
	ErrDuplicateComponent = bundleverify.ErrDuplicateComponent
	ErrInstallStateReset  = bundleverify.ErrInstallStateReset

	BuildManifest                          = bundleverify.BuildManifest
	WriteBundle                            = bundleverify.WriteBundle
	Sign                                   = bundleverify.Sign
	ParsePrivateKeyPEM                     = bundleverify.ParsePrivateKeyPEM
	Verify                                 = bundleverify.Verify
	Extract                                = bundleverify.Extract
	ExtractAllowingStateReset              = bundleverify.ExtractAllowingStateReset
	PersistedInstalledVersion              = bundleverify.PersistedInstalledVersion
	PersistedInstalledVersionAllowingReset = bundleverify.PersistedInstalledVersionAllowingReset
)
