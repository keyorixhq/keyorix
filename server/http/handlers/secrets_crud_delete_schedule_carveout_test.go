// secrets_crud_delete_prefetch_error_test.go — pins a real invariant:
// deleting a secret is not gated by its access schedule.
//
// A SecretAccessSchedule pins a READ window (secret_schedule.go's own doc
// comment: "reads outside the window are rejected") and
// DeleteSecretWithPermissionCheck never enforces it — deletion is
// intentionally not schedule-gated. This test locks that in directly rather
// than leaving it as an implicit property of the current code shape.
package handlers

import (
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestDeleteSecret_NotBlockedByAccessSchedule(t *testing.T) {
	handler, db := newPanicTestHandler(t)
	created, err := handler.coreService.CreateSecret(t.Context(), &core.CreateSecretRequest{
		Name: "scheduled", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10, Type: "static",
		CreatedBy: "alice", OwnerID: 1,
	})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&models.SecretAccessSchedule{}))
	// StartHour == EndHour == 0 denies every hour of every day (hour >=
	// EndHour is always true), AllowedDays "*" skips the day check — this
	// schedule denies reads at any wall-clock time the test happens to run.
	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: created.ID,
		AllowedDays:  "*",
		StartHour:    0,
		EndHour:      0,
		Timezone:     "UTC",
	}).Error)

	r := withIDParam(userReq("DELETE", "/api/v1/secrets/"+strconv.FormatUint(uint64(created.ID), 10), nil), created.ID)
	rr := httptest.NewRecorder()
	handler.DeleteSecret(rr, r)

	assert.Equal(t, 204, rr.Code, rr.Body.String())
	_, getErr := handler.coreService.GetSecret(t.Context(), created.ID)
	assert.Error(t, getErr, "secret should have actually been deleted, not just reported as deleted")
}
