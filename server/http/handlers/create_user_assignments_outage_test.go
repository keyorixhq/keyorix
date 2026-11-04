package handlers

// create_user_assignments_outage_test.go — CORE-HANDLER-TAILS-4 item 3: the
// roles.assign checks CreateUser makes for the system role and each project
// assignment (authorizeUserCreationAssignments) used to fold a lookup error into the
// same refusal as a denial, so a storage outage while the permission was read
// answered 403. It is 503 + Retry-After now, and nothing is created either way.

import (
	"fmt"
	"net/http"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCreateUser_AssignmentPermissionLookupOutageIs503(t *testing.T) {
	bodies := map[string]func(projectID uint) string{
		"system role": func(uint) string {
			return `{"username":"provisioned","email":"prov@x.io","display_name":"Prov","password":"Str0ng#Pass!word","role":"system_viewer"}`
		},
		"project assignment": func(pid uint) string {
			return fmt.Sprintf(`{"username":"provisioned","email":"prov@x.io","display_name":"Prov","password":"Str0ng#Pass!word","project_assignments":[{"project_id":%d,"role":"project_developer"}]}`, pid)
		},
	}
	cases := []struct {
		name       string
		ferr       error
		wantStatus int
	}{
		{"storage outage", fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED), http.StatusServiceUnavailable},
		{"unrecognised error stays a fail-closed refusal", fmt.Errorf("injected: role resolution returned no result"), http.StatusForbidden},
	}
	for bodyName, body := range bodies {
		for _, tc := range cases {
			t.Run(bodyName+"/"+tc.name, func(t *testing.T) {
				_, db := setupCreateUserAssignmentsTest(t)
				var proj models.Project
				require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError, Err: tc.ferr,
				})
				h, err := NewUserHandler(core.NewKeyorixCore(faulty))
				require.NoError(t, err)

				w := postCreateUser(t, h, body(proj.ID))

				require.True(t, faulty.Fired(), "CreateUser must reach the permission lookup")
				require.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
				if tc.wantStatus == http.StatusServiceUnavailable {
					assert.Equal(t, "2", w.Header().Get("Retry-After"))
					assert.Contains(t, w.Body.String(), "authorization temporarily unavailable, please retry")
				} else {
					assert.Empty(t, w.Header().Get("Retry-After"))
				}
				var n int64
				require.NoError(t, db.Model(&models.User{}).Where("username = ?", "provisioned").Count(&n).Error)
				assert.Zero(t, n, "a refused create wrote the user")
			})
		}
	}
}
