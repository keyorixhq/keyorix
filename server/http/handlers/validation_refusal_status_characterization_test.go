// validation_refusal_status_characterization_test.go — what the REST layer answers today
// for the i18n "ErrorValidation" refusals of the users, versions, env-clone, account,
// break-glass and access-review families (VALIDATION-TYPED-NOV-1 item 1).
//
// Core builds these refusals as bare errors worded "Validation error: ..."; several
// handlers classify them by that translated text. This table drives each refusal through
// the REAL handler over the real core and SQLite, once in English and once under a
// translated locale, and pins the status and envelope code main answers. It is the safety
// net for the typing commits that follow: a status that is already right must not move,
// and a case that answers 500 (or a status that depends on the language) is a finding,
// marked FINDING below.
//
// Refusals not in the table are unreachable through a handler (the route or the request
// validator stops the request first); the list is in refusalSitesNotDrivenByHandler.
//
// The localizer is process-global: these tests are deliberately NOT t.Parallel().
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// refusalFixture is the world a case runs in: user 1 (the withUserCtx caller) is a global
// admin, project 1 with environments 1 and 2 exists, and break-glass is enabled with a
// contained emergency role.
type refusalFixture struct {
	cs *core.KeyorixCore
	db *gorm.DB
}

func newRefusalFixture(t *testing.T) refusalFixture {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "refusal-p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{Name: "refusal-e1", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Environment{Name: "refusal-e2", ProjectID: 1}).Error)
	return refusalFixture{cs: cs, db: db}
}

// breakGlassMember makes user 1 a member of project 1 and sets the break-glass policy.
func (f refusalFixture) breakGlassMember(t *testing.T, emergencyRole string) {
	t.Helper()
	dev := &models.Role{Name: "refusal_developer", NameFolded: "refusal_developer", Description: "Developer"}
	require.NoError(t, f.db.Create(dev).Error)
	require.NoError(t, f.db.Create(&models.UserRole{UserID: 1, RoleID: dev.ID, ProjectID: 1}).Error)
	f.cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: emergencyRole, DefaultTTL: time.Hour, MaxTTL: time.Hour,
	})
}

type refusalCase struct {
	family string
	name   string
	// call drives one request through the real handler.
	call func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder
	// en and xx are the status under English and under the translated locale; xx 0 means
	// "same as en". code is the envelope "error" field in English ("" = not pinned).
	en, xx int
	code   string
}

func refusalBody(s string) *strings.Reader { return strings.NewReader(s) }

func userHandlerFor(t *testing.T, f refusalFixture) *UserHandler {
	t.Helper()
	uh, err := NewUserHandler(f.cs)
	require.NoError(t, err)
	return uh
}

func newAuthHandlerForRefusals(t *testing.T, f refusalFixture) *AuthHandler {
	t.Helper()
	return NewAuthHandler(f.cs, false)
}

// withBaselineRole seeds the system_viewer baseline role a user creation grants, so the
// request reaches the project-assignment refusals instead of the system-role one.
func withBaselineRole(next func(*testing.T, refusalFixture) *httptest.ResponseRecorder) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		require.NoError(t, f.db.Create(&models.Role{Name: "system_viewer", NameFolded: "system_viewer", Description: "baseline"}).Error)
		return next(t, f)
	}
}

// callChangePassword changes the password of a user whose current password is current.
func callChangePassword(current, next string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		u, err := f.cs.CreateUser(t.Context(), &core.CreateUserRequest{
			Username: "refusal-pw", Email: "refusal-pw@x.com", DisplayName: "Refusal PW", Password: current,
		})
		require.NoError(t, err)
		req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/auth/change-password",
			refusalBody(`{"current_password":"`+current+`","new_password":"`+next+`"}`)), u.ID, "refusal-pw")
		w := httptest.NewRecorder()
		newAuthHandlerForRefusals(t, f).ChangePassword(w, req)
		return w
	}
}

func callCreateUser(body string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", refusalBody(body)))
		w := httptest.NewRecorder()
		userHandlerFor(t, f).CreateUser(w, req)
		return w
	}
}

func callUserByID(method, id, body string, h func(*UserHandler) http.HandlerFunc) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withChiParam(withUserCtx(httptest.NewRequest(method, "/api/v1/users/"+id, refusalBody(body))), "id", id)
		w := httptest.NewRecorder()
		h(userHandlerFor(t, f))(w, req)
		return w
	}
}

func callUserQuery(query string, h func(*UserHandler) http.HandlerFunc) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/lookup?"+query, nil))
		w := httptest.NewRecorder()
		h(userHandlerFor(t, f))(w, req)
		return w
	}
}

func callSecretVersions(secretID string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		sh, err := NewSecretHandler(f.cs)
		require.NoError(t, err)
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/"+secretID+"/versions", nil)), "id", secretID)
		w := httptest.NewRecorder()
		sh.GetSecretVersions(w, req)
		return w
	}
}

func callCloneEnv(src, dst string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPost, "/", refusalBody(`{"destination_environment_id":`+dst+`}`))),
			map[string]string{"id": "1", "envId": src})
		w := httptest.NewRecorder()
		NewCatalogHandler(f.cs).CloneEnvironment(w, req)
		return w
	}
}

func callAuth(method, path, body string, h func(*AuthHandler) http.HandlerFunc, params map[string]string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withUserCtx(httptest.NewRequest(method, path, refusalBody(body)))
		if params != nil {
			req = withChiParams(req, params)
		}
		w := httptest.NewRecorder()
		h(newAuthHandlerForRefusals(t, f))(w, req)
		return w
	}
}

func callBreakGlassActivate(project, body string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		return doActivateBreakGlass(t, NewCatalogHandler(f.cs), project, body)
	}
}

func callBreakGlassList(project string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": project}))
		w := httptest.NewRecorder()
		NewCatalogHandler(f.cs).ListBreakGlassActivations(w, req)
		return w
	}
}

func callBreakGlassRevoke(project, activation string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		return doRevokeBreakGlass(t, NewCatalogHandler(f.cs), project, activation)
	}
}

func callBreakGlassReview(project, activation, body string) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", refusalBody(body)),
			map[string]string{"id": project, "activationId": activation}))
		w := httptest.NewRecorder()
		NewCatalogHandler(f.cs).ReviewBreakGlass(w, req)
		return w
	}
}

func callCampaign(method, project, campaign, item, body string, h func(*CatalogHandler) http.HandlerFunc) func(*testing.T, refusalFixture) *httptest.ResponseRecorder {
	return func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
		params := map[string]string{"id": project}
		if campaign != "" {
			params["campaignId"] = campaign
		}
		if item != "" {
			params["itemId"] = item
		}
		req := withUserCtx(withChiParams(httptest.NewRequest(method, "/", refusalBody(body)), params))
		w := httptest.NewRecorder()
		h(NewCatalogHandler(f.cs))(w, req)
		return w
	}
}

func refusalCases() []refusalCase {
	const ok = "Tr1cky-Passphrase-For-Tests!"
	create := func(extra string) string {
		return `{"username":"refusal-new","email":"refusal-new@x.com","display_name":"Refusal New","password":"` + ok + `"` + extra + `}`
	}
	return []refusalCase{
		// ── users ────────────────────────────────────────────────────────────────
		{family: "users", name: "create/username charset", en: http.StatusBadRequest, code: "ValidationError",
			call: callCreateUser(`{"username":"bad/name","email":"b@x.com","display_name":"B","password":"` + ok + `"}`)},
		{family: "users", name: "create/unknown system role", en: http.StatusBadRequest, code: "ValidationError",
			call: callCreateUser(create(`,"role":"no_such_role"`))},
		{family: "users", name: "create/unknown project", en: http.StatusBadRequest, code: "ValidationError",
			call: withBaselineRole(callCreateUser(create(`,"project_assignments":[{"project_id":99999,"role":"no_such_role"}]`)))},
		{family: "users", name: "create/unknown project role", en: http.StatusBadRequest, code: "ValidationError",
			call: withBaselineRole(callCreateUser(create(`,"project_assignments":[{"project_id":1,"role":"no_such_role"}]`)))},
		{family: "users", name: "create/assignment without project", en: http.StatusBadRequest, code: "ValidationError",
			call: withBaselineRole(callCreateUser(create(`,"project_assignments":[{"project_id":0,"role":""}]`)))},
		// The setup-link path asks for credential_delivery.base_url before it validates
		// the fields, and answers it with its own code.
		{family: "users", name: "create/setup link without base_url", en: http.StatusBadRequest, code: "ConfigError",
			call: callCreateUser(`{"username":"bad/name","email":"b@x.com","display_name":"B","deliver_setup_link":true}`)},
		{family: "users", name: "create/one-time password, username charset", en: http.StatusBadRequest, code: "ValidationError",
			call: callCreateUser(`{"username":"bad/name","email":"b@x.com","display_name":"B","generate_one_time_password":true}`)},
		{family: "users", name: "update/username charset", en: http.StatusBadRequest, code: "ValidationError",
			call: callUserByID(http.MethodPut, "1", `{"username":"bad/name"}`, func(uh *UserHandler) http.HandlerFunc { return uh.UpdateUser })},
		{family: "users", name: "lookup by email without email", en: http.StatusBadRequest, code: "InvalidParameter",
			call: callUserQuery("email=", func(uh *UserHandler) http.HandlerFunc { return uh.GetUserByEmail })},
		{family: "users", name: "lookup by username without username", en: http.StatusBadRequest, code: "InvalidParameter",
			call: callUserQuery("username=", func(uh *UserHandler) http.HandlerFunc { return uh.GetUserByUsername })},
		{family: "users", name: "lookup by external id without id", en: http.StatusBadRequest, code: "InvalidParameter",
			call: callUserQuery("external_id=", func(uh *UserHandler) http.HandlerFunc { return uh.GetUserByExternalID })},
		// FINDING: a user-id refusal ("user ID is required") answers 500 on main: the
		// handler has no arm for it.
		{family: "users", name: "delete user 0", en: http.StatusInternalServerError, code: "InternalError",
			call: callUserByID(http.MethodDelete, "0", "", func(uh *UserHandler) http.HandlerFunc { return uh.DeleteUser })},
		{family: "users", name: "restore user 0", en: http.StatusInternalServerError, code: "InternalError",
			call: callUserByID(http.MethodPost, "0", "", func(uh *UserHandler) http.HandlerFunc { return uh.RestoreUser })},
		{family: "users", name: "reissue one-time password for user 0", en: http.StatusBadRequest,
			call: callUserByID(http.MethodPost, "0", "", func(uh *UserHandler) http.HandlerFunc { return uh.ReissueOneTimePassword })},

		// ── versions ─────────────────────────────────────────────────────────────
		// FINDING: "secret ID is required" answers 500 on main (no arm for it in
		// GetSecretVersions; secrets_versions.go is not owned by another session).
		{family: "versions", name: "list versions of secret 0", en: http.StatusInternalServerError, code: "InternalError",
			call: callSecretVersions("0")},

		// ── env clone (handler is catalog.go: owned by ERRMAP-CATALOG-NOV-1) ─────
		{family: "env_clone", name: "same source and destination", en: http.StatusBadRequest,
			call: callCloneEnv("1", "1")},
		// A missing environment is worded "Validation error: source environment:
		// environment not found" and the handler answers it 404 by the substring
		// "not found" (CloneEnvironment lives in catalog.go: ERRMAP-CATALOG-NOV-1).
		{family: "env_clone", name: "source environment missing", en: http.StatusNotFound,
			call: callCloneEnv("999", "2")},
		{family: "env_clone", name: "destination environment missing", en: http.StatusNotFound,
			call: callCloneEnv("1", "999")},
		{family: "env_clone", name: "environments of another project", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				require.NoError(t, f.db.Create(&models.Project{Name: "refusal-p2"}).Error)
				require.NoError(t, f.db.Create(&models.Environment{Name: "refusal-e3", ProjectID: 2}).Error)
				return callCloneEnv("1", "3")(t, f)
			}},

		// ── account (self-service profile, password, sessions: auth.go) ──────────
		{family: "account", name: "profile/display name too long", en: http.StatusBadRequest,
			call: callAuth(http.MethodPut, "/auth/profile", `{"display_name":"`+strings.Repeat("x", 200)+`"}`,
				func(h *AuthHandler) http.HandlerFunc { return h.UpdateProfile }, nil)},
		{family: "account", name: "password/new equals current", en: http.StatusBadRequest,
			call: callChangePassword(ok, ok)},
		{family: "account", name: "password/too weak", en: http.StatusBadRequest,
			call: callChangePassword(ok, "a")},
		{family: "account", name: "revoke session 0", en: http.StatusNotFound,
			call: callAuth(http.MethodDelete, "/auth/sessions/0", "", func(h *AuthHandler) http.HandlerFunc { return h.RevokeSession },
				map[string]string{"id": "0"})},

		// ── break-glass ──────────────────────────────────────────────────────────
		{family: "break_glass", name: "activate/project 0", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				return callBreakGlassActivate("0", `{"justification":"prod incident, db is down"}`)(t, f)
			}},
		{family: "break_glass", name: "activate/justification too short", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				return callBreakGlassActivate("1", `{"justification":"short"}`)(t, f)
			}},
		{family: "break_glass", name: "activate/no emergency role configured", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "")
				return callBreakGlassActivate("1", `{"justification":"prod incident, db is down"}`)(t, f)
			}},
		{family: "break_glass", name: "activate/emergency role unknown", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "no_such_role")
				return callBreakGlassActivate("1", `{"justification":"prod incident, db is down"}`)(t, f)
			}},
		{family: "break_glass", name: "activate/ttl not a duration", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				return callBreakGlassActivate("1", `{"justification":"prod incident, db is down","ttl":"soon"}`)(t, f)
			}},
		// FINDING: both emergency-role guards answer 500 on main (no sentinel, so the
		// handler's default arm); "no emergency role is configured", the sibling, is 400.
		{family: "break_glass", name: "activate/emergency role is install-wide admin", en: http.StatusInternalServerError,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "system_admin")
				return callBreakGlassActivate("1", `{"justification":"prod incident, db is down"}`)(t, f)
			}},
		{family: "break_glass", name: "activate/emergency role can assign roles", en: http.StatusInternalServerError,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_assigner")
				assigner := &models.Role{Name: "refusal_assigner", NameFolded: "refusal_assigner", Description: "assigns"}
				require.NoError(t, f.db.Create(assigner).Error)
				perm := &models.Permission{Name: "roles.assign"}
				require.NoError(t, f.db.Where("name = ?", perm.Name).FirstOrCreate(perm).Error)
				require.NoError(t, f.db.Create(&models.RolePermission{RoleID: assigner.ID, PermissionID: perm.ID}).Error)
				return callBreakGlassActivate("1", `{"justification":"prod incident, db is down"}`)(t, f)
			}},
		{family: "break_glass", name: "list/project 0", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				return callBreakGlassList("0")(t, f)
			}},
		{family: "break_glass", name: "revoke/project 0", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				return callBreakGlassRevoke("0", "1")(t, f)
			}},
		{family: "break_glass", name: "revoke/activation not active", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				seedBreakGlassActivationS13(t, f.db, 1, "revoked")
				return callBreakGlassRevoke("1", "1")(t, f)
			}},
		{family: "break_glass", name: "review/project 0", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				f.breakGlassMember(t, "refusal_developer")
				return callBreakGlassReview("0", "1", `{"note":"reviewed after the incident"}`)(t, f)
			}},

		// ── access review ────────────────────────────────────────────────────────
		{family: "access_review", name: "open campaign/project 0", en: http.StatusBadRequest,
			call: callCampaign(http.MethodPost, "0", "", "", `{"name":"q"}`, func(h *CatalogHandler) http.HandlerFunc { return h.OpenAccessReviewCampaign })},
		{family: "access_review", name: "list campaigns/project 0", en: http.StatusBadRequest,
			call: callCampaign(http.MethodGet, "0", "", "", "", func(h *CatalogHandler) http.HandlerFunc { return h.ListAccessReviewCampaigns })},
		{family: "access_review", name: "decide/campaign missing", en: http.StatusNotFound,
			call: callCampaign(http.MethodPost, "1", "1", "1", `{"action":"maybe"}`, func(h *CatalogHandler) http.HandlerFunc { return h.DecideAccessReviewCampaignItem })},
		{family: "access_review", name: "decide/action neither attest nor revoke", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				opened, err := f.cs.OpenAccessReviewCampaign(t.Context(), 1, 0, 1, "refusal-campaign")
				require.NoError(t, err)
				item := seedPendingReviewItem(t, f, opened.Campaign.ID)
				return callCampaign(http.MethodPost, "1", uitoa(opened.Campaign.ID), uitoa(item), `{"action":"maybe"}`, func(h *CatalogHandler) http.HandlerFunc { return h.DecideAccessReviewCampaignItem })(t, f)
			}},
		// FINDING (read from campaignStatusForError, pinned below): "this item has already
		// been decided" matches none of the handler's text arms and answers 500, while its
		// sibling "campaign is closed" answers 400.
		{family: "access_review", name: "decide/item already decided", en: http.StatusInternalServerError,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				opened, err := f.cs.OpenAccessReviewCampaign(t.Context(), 1, 0, 1, "refusal-campaign")
				require.NoError(t, err)
				item := seedPendingReviewItem(t, f, opened.Campaign.ID)
				require.NoError(t, f.db.Model(&models.AccessReviewItem{}).Where("id = ?", item).Update("decision", core.ReviewItemAttested).Error)
				return callCampaign(http.MethodPost, "1", uitoa(opened.Campaign.ID), uitoa(item), `{"action":"attest"}`, func(h *CatalogHandler) http.HandlerFunc { return h.DecideAccessReviewCampaignItem })(t, f)
			}},
		{family: "access_review", name: "close/campaign already closed", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				opened, err := f.cs.OpenAccessReviewCampaign(t.Context(), 1, 0, 1, "refusal-campaign")
				require.NoError(t, err)
				_, err = f.cs.CloseAccessReviewCampaign(t.Context(), 1, 0, 1, opened.Campaign.ID, true)
				require.NoError(t, err)
				id := opened.Campaign.ID
				return callCampaign(http.MethodPost, "1", uitoa(id), "", `{"force":true}`, func(h *CatalogHandler) http.HandlerFunc { return h.CloseAccessReviewCampaign })(t, f)
			}},
		{family: "access_review", name: "close/items still pending without force", en: http.StatusBadRequest,
			call: func(t *testing.T, f refusalFixture) *httptest.ResponseRecorder {
				opened, err := f.cs.OpenAccessReviewCampaign(t.Context(), 1, 0, 1, "refusal-campaign")
				require.NoError(t, err)
				seedPendingReviewItem(t, f, opened.Campaign.ID)
				return callCampaign(http.MethodPost, "1", uitoa(opened.Campaign.ID), "", `{"force":false}`, func(h *CatalogHandler) http.HandlerFunc { return h.CloseAccessReviewCampaign })(t, f)
			}},
	}
}

// seedPendingReviewItem gives a campaign one undecided item (the shape the core
// concurrency tests use) and returns its id.
func seedPendingReviewItem(t *testing.T, f refusalFixture, campaignID uint) uint {
	t.Helper()
	item := &models.AccessReviewItem{CampaignID: campaignID, PrincipalType: "role", PrincipalID: 999, RoleID: 1,
		Source: "role", Decision: core.ReviewItemPending}
	require.NoError(t, f.db.Create(item).Error)
	return item.ID
}

func uitoa(u uint) string {
	b, _ := json.Marshal(u)
	return string(b)
}

// refusalSitesNotDrivenByHandler names the ErrorValidation sites no handler request
// reaches, and why. The typing commits still cover them through core tests.
var refusalSitesNotDrivenByHandler = map[string]string{
	"users.go: user ID is required (GetUser, DeleteUser, RestoreUser)": "the handler parses the id and the route gate runs first; id 0 is driven above where it reaches core",
	"versions.go: user ID is required for permission checking":         "the authenticated user id is never 0 for a user principal; machine principals take the unchecked path",
	"versions.go: version number must be positive":                     "the handlers reject version <= 0 before core",
	"account.go: user ID is required (profile, password, sessions)":    "the authenticated user id is never 0 for a user principal",
	"break_glass.go: activation is not active (revoke race)":           "needs a concurrent revoke between the handler's read and core's re-read",
	"access_review_campaign.go: independent reviewer refusals":         "authorization refusals (permissionDeniedf): AUTHZ-CORE-WAIVERS-1 owns them, only their typing is checked",
}

func TestValidationRefusalStatusCharacterization(t *testing.T) {
	require.NotEmpty(t, refusalSitesNotDrivenByHandler)
	for _, lang := range errorClassLocales {
		for _, tc := range refusalCases() {
			t.Run(lang+"/"+tc.family+"/"+tc.name, func(t *testing.T) {
				withErrorTextLocale(t, lang)
				f := newRefusalFixture(t)
				w := tc.call(t, f)
				want := tc.en
				if lang != "en" && tc.xx != 0 {
					want = tc.xx
				}
				assert.Equal(t, want, w.Code, "body: %s", w.Body.String())
				if lang == "en" && tc.code != "" {
					var env struct {
						Error string `json:"error"`
					}
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
					assert.Equal(t, tc.code, env.Error, "body: %s", w.Body.String())
				}
			})
		}
	}
}
