// remote_billing.go — Billing report stub for RemoteStorage.
//
// The billing report aggregates data from secret_nodes + audit_events, both
// of which live server-side. Admin callers use GET /api/v1/admin/billing/report
// directly instead of going through RemoteStorage.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetBillingReport is not supported in remote mode; billing report queries
// run server-side against the live database.
func (rs *RemoteStorage) GetBillingReport(_ context.Context, _, _ time.Time, _ []uint) (*storage.BillingReport, error) {
	return nil, remoteUnsupported("GetBillingReport")
}
