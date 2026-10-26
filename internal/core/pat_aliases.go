package core

import "github.com/keyorixhq/keyorix/internal/core/rules"

// PATRestriction (ADR-042) lives in internal/core/rules, a pure leaf, so
// FuzzPATRestrictionAllows runs against that package's small coverage map.
type PATRestriction = rules.PATRestriction
