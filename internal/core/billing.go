package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/license"
)

// GenerateBillingReport returns a per-project usage breakdown for the half-open
// interval [from, to). Requires the "billing" license feature.
//
// projectIDs filters the report to specific projects; pass nil for all projects.
func (c *KeyorixCore) GenerateBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*storage.BillingReport, error) {
	if !c.HasLicensedFeature(license.FeatureBilling) {
		return nil, fmt.Errorf("billing reports require a commercial license (feature: %s)", license.FeatureBilling)
	}
	if !from.Before(to) {
		return nil, fmt.Errorf("billing report: from (%s) must be before to (%s)", from.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	if to.Sub(from) > 366*24*time.Hour {
		return nil, fmt.Errorf("billing report window exceeds the maximum of 366 days")
	}
	return c.storage.GetBillingReport(ctx, from.UTC(), to.UTC(), projectIDs)
}
