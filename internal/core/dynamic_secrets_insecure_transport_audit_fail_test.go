// dynamic_secrets_insecure_transport_audit_fail_test.go — AUDIT-DISCLOSURE-NOV-1 item 2
// red/green proof.
//
// checkAdminDSNTransportOnIssue discarded the result of its
// dynamic_lease.insecure_transport audit write, so a credential issued over a
// connection that does not verify the server certificate went out with no record
// of that. It now fails closed like dynamic_lease.issued (#4716): the event is
// written before engine.Issue, and when it was not committed nothing is minted on
// the target, no lease row exists and no credential is returned.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
)

const insecureTransportEvent = "dynamic_lease.insecure_transport"

func TestIssueLease_InsecureTransportAuditFails_NoCredentialNothingMinted(t *testing.T) {
	t.Parallel()
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panics=%v", panics), func(t *testing.T) {
			t.Parallel()
			c, db := newSQLTransportCore(t, true) // the operator allows insecure transport
			pg := dynamictest.StartFakePostgres(t)
			cfg, err := createSQLConfig(c, "weak", "postgres",
				fmt.Sprintf("postgres://admin:s3cret@%s:%s/app?sslmode=disable&connect_timeout=5", pg.Host, pg.Port))
			require.NoError(t, err)
			ctx := context.Background()
			stmtsBefore := pg.Statements()

			base := c.storage
			if panics {
				c.storage = panicLogAuditEventStorage(base, insecureTransportEvent)
			} else {
				c.storage = failLogAuditEventStorage(base, insecureTransportEvent)
			}
			issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)
			c.storage = base

			require.Error(t, err, "a credential must not be issued over a weak transport without its audit record")
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			assert.Nil(t, issued)
			assert.Equal(t, stmtsBefore, pg.Statements(), "nothing may be minted on the target")
			assert.Empty(t, listLeases(t, c, cfg.ID), "no lease row for a refused issue")
			assert.EqualValues(t, 0, countIssueAuditEvents(t, db, insecureTransportEvent))
			assert.EqualValues(t, 0, countIssueAuditEvents(t, db, issuedEvent))

			// With the audit log back, the same issue goes through and is recorded.
			issued, err = c.IssueLease(ctx, cfg.ID, 0, 7)
			require.NoError(t, err)
			require.NotNil(t, issued)
			assert.EqualValues(t, 1, countIssueAuditEvents(t, db, insecureTransportEvent))
		})
	}
}
