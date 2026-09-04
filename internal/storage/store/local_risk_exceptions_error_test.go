// local_risk_exceptions_error_test.go — DB-error branch sweep for
// local_risk_exceptions.go, following the newBrokenDB pattern established in
// store_s35_test.go.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRiskException_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetRiskException(context.Background(), 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "ErrorNotFound")
}

func TestRevokeRiskExceptionIfNotRevoked_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.RevokeRiskExceptionIfNotRevoked(context.Background(), &models.RiskException{ID: 1})
	require.Error(t, err)
}

func TestApproveRiskExceptionIfPending_DBError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ApproveRiskExceptionIfPending(context.Background(), &models.RiskException{ID: 1})
	require.Error(t, err)
}
