package handlers

// writeSCIMWriteError's classes, pinned on wrapped sentinels directly (#3494). The
// end-to-end fault-injection tests are in scim_storage_error_status_test.go.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

// TestSCIMWriteErrorStatus_Classes pins the classifier on wrapped sentinels directly,
// including the last-admin refusal (a deliberate, permanent refusal: 409, never a
// 404 the IdP would read as "already gone", never a 5xx it would retry forever).
func TestSCIMWriteErrorStatus_Classes(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("outer: %w", e) }
	cases := []struct {
		err      error
		status   int
		scimType string
	}{
		{wrap(corestorage.ErrUserNotFound), http.StatusNotFound, ""},
		{wrap(core.ErrNotSCIMManaged), http.StatusNotFound, ""},
		{wrap(core.ErrEmailInUse), http.StatusConflict, "uniqueness"},
		{wrap(corestorage.ErrDuplicateEmail), http.StatusConflict, "uniqueness"},
		{wrap(core.ErrSCIMUserExists), http.StatusConflict, "uniqueness"},
		{wrap(core.ErrLastAdminDeactivation), http.StatusConflict, ""},
		{wrap(core.ErrInvalidInput), http.StatusBadRequest, "invalidValue"},
		// Groups (#3620).
		{wrap(corestorage.ErrGroupNotFound), http.StatusNotFound, ""},
		{wrap(corestorage.ErrDuplicateGroupName), http.StatusConflict, "uniqueness"},
		{wrap(core.ErrSCIMMemberNotManaged), http.StatusBadRequest, "invalidValue"},
		{wrap(core.ErrSCIMGroupConfersAdmin), http.StatusForbidden, ""},
		{wrap(core.ErrLastAdminGroupGuard), http.StatusConflict, ""},
		{wrap(corestorage.ErrWouldStrandLastAdmin), http.StatusConflict, ""},
		{wrap(corestorage.ErrSQLiteWriteContention), http.StatusServiceUnavailable, ""},
		{wrap(core.ErrUserActiveStateConflict), http.StatusServiceUnavailable, ""},
		{wrap(core.ErrUserAccountStateConflict), http.StatusServiceUnavailable, ""},
		{context.Canceled, http.StatusInternalServerError, ""},
		{context.DeadlineExceeded, http.StatusInternalServerError, ""},
		{errors.New("anything else"), http.StatusInternalServerError, ""},
		// A storage failure while the last-admin guard reads roles is NOT the refusal.
		{fmt.Errorf("retrieval failed: %w", errors.New("conn reset")), http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			w := httptest.NewRecorder()
			writeSCIMWriteError(w, httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/1", nil), "patching SCIM user 1", tc.err)
			body := assertSCIMErrorBody(t, w, tc.status)
			if tc.scimType == "" {
				assert.Nil(t, body["scimType"])
			} else {
				assert.Equal(t, tc.scimType, body["scimType"])
			}
		})
	}
}
