package handlers

// IDENTITY-INPUT-BOUNDS-1 item 2: expires_in_days <= 0 used to mint a non-expiring
// token with no error, and a huge value overflowed time.AddDate. 0 stays "never
// expires"; a negative value or one above core.MaxMachineTokenLifetimeDays is 400.

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestIssueMachineToken_ExpiresInDaysBounds(t *testing.T) {
	for _, tc := range []struct {
		days       int64
		wantStatus int
		wantExpiry bool // a 201 that must carry an expiry about days from now
	}{
		{-1, http.StatusBadRequest, false},
		{0, http.StatusCreated, false},
		{36500, http.StatusCreated, true},
		{36501, http.StatusBadRequest, false},
		{math.MaxInt32, http.StatusBadRequest, false},
		{math.MinInt32, http.StatusBadRequest, false},
	} {
		t.Run(strconv.FormatInt(tc.days, 10), func(t *testing.T) {
			h, projID := machineHandlerWithProjectS13(t)
			machine, err := h.coreService.Storage().CreateMachineIdentity(context.Background(), &models.MachineIdentity{
				ProjectID: projID, Name: "lifetime-bounds", State: "active",
			})
			require.NoError(t, err)

			body := []byte(`{"name":"lt","expires_in_days":` + strconv.FormatInt(tc.days, 10) + `}`)
			req := withUserCtx(withChiParams(
				httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
				map[string]string{"id": machineUintToStr(projID), "machineId": machineUintToStr(machine.ID)},
			))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.IssueMachineToken(w, req)
			require.Equal(t, tc.wantStatus, w.Code, w.Body.String())

			// Effect, read from storage: a refused request mints nothing; an accepted
			// one stores the expiry the request asked for (none for 0).
			creds, err := h.coreService.Storage().ListMachineIdentityCredentials(context.Background(), machine.ID)
			require.NoError(t, err)
			if tc.wantStatus != http.StatusCreated {
				assert.Empty(t, creds, "a refused lifetime must not mint a token")
				return
			}
			require.Len(t, creds, 1)
			if !tc.wantExpiry {
				assert.Nil(t, creds[0].ExpiresAt, "0 = never expires")
				return
			}
			require.NotNil(t, creds[0].ExpiresAt)
			want := time.Now().AddDate(0, 0, int(tc.days))
			assert.WithinDuration(t, want, *creds[0].ExpiresAt, time.Hour)
		})
	}
}
