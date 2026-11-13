package handlers

// machine_refusals_text_test.go — sendMachineRefusal echoes a refusal's own text only
// for the sentinels core words for the client; any other classified not-found or
// conflict (here a sentinel wrapped around driver text) answers the class's fixed text.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestSendMachineRefusal_DriverTextNeverEchoed(t *testing.T) {
	rec := httptest.NewRecorder()
	err := fmt.Errorf("%w: pq: duplicate key value violates unique constraint \"idx_secret_internal\"", storage.ErrDuplicateActiveMembership)
	require.True(t, sendMachineRefusal(rec, err))
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.NotContains(t, rec.Body.String(), "pq:")
	assert.NotContains(t, rec.Body.String(), "idx_secret_internal")
	assert.Contains(t, rec.Body.String(), "Conflict with the current state")
}

func TestSendMachineRefusal_CoreWordedTextEchoed(t *testing.T) {
	rec := httptest.NewRecorder()
	err := fmt.Errorf("machine identity 7 already holds this role: %w", storage.ErrRoleAlreadyAssigned)
	require.True(t, sendMachineRefusal(rec, err))
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "machine identity 7 already holds this role")
}
