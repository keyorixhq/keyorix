// groups_handler_identifier_test.go — regression tests for #189: Group.Name is
// wired to the `identifier` validator so a name carrying an invisible or
// visually-deceptive character is rejected rather than silently accepted and
// later shown, apparently-legitimate, in an access-review UI or audit log.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newGroupHandlerForTest(t *testing.T) *GroupHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{}, &models.Role{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewGroupHandler(c)
	require.NoError(t, err)
	return h
}

func postCreateGroup(t *testing.T, h *GroupHandler, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"name": name})
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	return w
}

func TestCreateGroup_RejectsDangerousNames(t *testing.T) {
	cases := map[string]string{
		"zero-width space":       "prod\u200bteam", // U+200B ZERO WIDTH SPACE
		"RTL override":           "prod\u202eteam", // U+202E RIGHT-TO-LEFT OVERRIDE
		"cyrillic homograph 'a'": "prodаpi",        // U+0430 CYRILLIC SMALL LETTER A
	}
	for name, dangerous := range cases {
		t.Run(name, func(t *testing.T) {
			h := newGroupHandlerForTest(t)
			w := postCreateGroup(t, h, dangerous)
			require.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		})
	}
}

func TestCreateGroup_AcceptsLegitimateNames(t *testing.T) {
	legit := []string{"ops", "platform-admins", "Group_One", "sales team"}
	for _, name := range legit {
		t.Run(name, func(t *testing.T) {
			h := newGroupHandlerForTest(t)
			w := postCreateGroup(t, h, name)
			require.Equal(t, http.StatusCreated, w.Code, "response body: %s", w.Body.String())
		})
	}
}

// UpdateGroup's Name is optional (omitempty) but must still reject a dangerous
// value when one is supplied.
func TestUpdateGroup_RejectsDangerousName(t *testing.T) {
	h := newGroupHandlerForTest(t)
	createW := postCreateGroup(t, h, "ops")
	require.Equal(t, http.StatusCreated, createW.Code)

	body, err := json.Marshal(map[string]string{"name": "prod\u200bteam"}) // zero-width space
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/groups/1", bytes.NewReader(body)), "id", "1"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
}
