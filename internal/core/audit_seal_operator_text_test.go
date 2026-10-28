// audit_seal_operator_text_test.go — the operator name and reason a seal
// stores are plain, bounded text (REVIEW-3757-DEEP-1 L2). Every case runs on
// SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// (4) The operator name and reason go into the record and the in-chain event
// description: control and format characters and oversized values are
// refused (REVIEW-3757-DEEP-1 L2).
func TestAuditSeal_RefusesUnsafeOperatorText(t *testing.T) {
	for name, mut := range map[string]func(*AuditLossRequest){
		"operator-newline":  func(r *AuditLossRequest) { r.Operator = "ops\nseal #2 accepted" },
		"reason-escape":     func(r *AuditLossRequest) { r.Reason = "INC-42 \x1b[2K" },
		"reason-bidi":       func(r *AuditLossRequest) { r.Reason = "INC-42 \u202e" },
		"reason-line-sep":   func(r *AuditLossRequest) { r.Reason = "INC-42\u2028seal #2 accepted" },
		"operator-para-sep": func(r *AuditLossRequest) { r.Operator = "ops\u2029seal #2 accepted" },
		"operator-long":     func(r *AuditLossRequest) { r.Operator = strings.Repeat("o", 257) },
		"reason-long":       func(r *AuditLossRequest) { r.Reason = strings.Repeat("r", 1025) },
		"reason-not-utf8":   func(r *AuditLossRequest) { r.Reason = "INC-42 \xff" },
	} {
		t.Run(name, func(t *testing.T) {
			fcRun(t, func(t *testing.T, e *fcEnv) {
				fcCertify(t, e)
				req := sealReq(sealDeleteRow(t, e, e.c, 3))
				mut(&req)
				sealRefused(t, e.restart(), req, "--")
			})
		})
	}
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		req := sealReq(sealDeleteRow(t, e, e.c, 3))
		req.Operator, req.Reason = strings.Repeat("o", 256), strings.Repeat("r", 1024)
		_, err := e.restart().PlanAuditLossAcceptance(context.Background(), req)
		require.NoError(t, err, "values at the limits are accepted")
	})
}
