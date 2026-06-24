package license

// Commercial feature keys gated by an offline license. These are the canonical strings that
// appear in a license's Features list and in HasFeature / HasLicensedFeature checks — use
// the constants, never bare strings, so the gated set stays discoverable in one place.
const (
	// FeatureAirgapUpdates gates `keyorix bundle import` — staging a signed update bundle
	// for an air-gapped rollout (ADR-064). Bundle *verification* is always free; only the
	// import (delivery) action is commercial. This is the first designated commercial
	// feature (ADR-065 Phase 2c). Gating it strips nothing from community source builds:
	// import already requires the embedded update-signing key that only release builds
	// carry, so a plain `go build` cannot import regardless.
	FeatureAirgapUpdates = "airgap_updates"
)
