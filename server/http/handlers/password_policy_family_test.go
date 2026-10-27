package handlers

// PASSWORD-POLICY-FAMILY-1: the family guard. Every HTTP route that accepts a new
// password answers a policy violation the same way: 400, the broken rule named,
// no "internal error", and no trace of the candidate. #3543 fixed this for
// POST /auth/change-password only; its siblings answered 403 (/system/init) or a
// dead-link message (invitation accept) for the same mistake.
//
// The table is keyed by the OpenAPI operationId. TestPasswordPolicyFamily_
// EveryPasswordOperationIsListed fails when openapi.yaml gains an operation whose
// request body has a password-ish field that is neither in the table nor excused
// with a reason, so a new password route cannot ship unguarded. The gRPC half is
// server/grpc/services/password_policy_family_test.go.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// policyFamilyCase sends a policy-violating password to one route and returns the
// response plus the candidate it sent.
type policyFamilyCase struct {
	route string
	send  func(t *testing.T) (w *httptest.ResponseRecorder, candidate string)
}

// policyFamilyCases are the routes that accept a NEW password, by operationId.
// Several operations have more than one way in; they get one row per way.
var policyFamilyCases = map[string][]policyFamilyCase{
	"changePassword": {{"POST /auth/change-password", sendChangePasswordViolation}},
	"systemInit":     {{"POST /system/init", sendInitSystemViolation}},
	"authConsumeSetup": {
		{"POST /auth/setup/consume (account setup link)", sendConsumeSetupViolation},
		{"POST /auth/setup/consume (invitation accept)", sendConsumeInvitationViolation},
	},
	"createUser": {{"POST /api/v1/users (admin-set password)", sendCreateUserViolation}},
}

// policyFamilyNotNewPassword are operations whose password field proves an
// existing credential and sets nothing.
var policyFamilyNotNewPassword = map[string]string{
	"authLogin":                  "credential check; sets no password",
	"activateMFA":                "re-proof of the current password",
	"disableMFA":                 "re-proof of the current password",
	"regenerateMFARecoveryCodes": "re-proof of the current password",
}

func TestPasswordPolicyFamily_RefusalIsA400NamingTheRule(t *testing.T) {
	for opID, cases := range policyFamilyCases {
		for _, tc := range cases {
			t.Run(opID+"/"+tc.route, func(t *testing.T) {
				w, candidate := tc.send(t)
				body := w.Body.String()
				require.Equal(t, http.StatusBadRequest, w.Code, body)
				assert.Contains(t, body, "not contain your username, email, or display name", "the broken rule must be named")
				assert.NotContains(t, strings.ToLower(body), "internal error")
				assert.NotContains(t, body, candidate, "the response must not echo the candidate")
				assert.NotContains(t, body, "$2a$")
			})
		}
	}
}

// It sweeps every OpenAPI operation, so it reports through guardrules.Rollout
// (docs/guard-rollout-contract.md rule 2): report-only on pull requests while
// docs/guard-rollout.d/TestPasswordPolicyFamily_EveryPasswordOperationIsListed.tsv
// exists, blocking on main.
func TestPasswordPolicyFamily_EveryPasswordOperationIsListed(t *testing.T) {
	g := guardrules.Rollout(t)
	raw, err := os.ReadFile("openapi.yaml")
	require.NoError(g, err)
	var doc struct {
		Paths      map[string]map[string]yaml.Node `yaml:"paths"`
		Components struct {
			Schemas map[string]yaml.Node `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(g, yaml.Unmarshal(raw, &doc))

	var found []string
	for path, methods := range doc.Paths {
		for method, opNode := range methods {
			var op struct {
				OperationID string `yaml:"operationId"`
				RequestBody struct {
					Content map[string]struct {
						Schema yaml.Node `yaml:"schema"`
					} `yaml:"content"`
				} `yaml:"requestBody"`
			}
			if opNode.Decode(&op) != nil || op.OperationID == "" {
				continue
			}
			for _, c := range op.RequestBody.Content {
				if schemaHasPasswordProperty(&c.Schema, doc.Components.Schemas, 0) {
					found = append(found, op.OperationID)
					_, listed := policyFamilyCases[op.OperationID]
					_, excused := policyFamilyNotNewPassword[op.OperationID]
					assert.True(g, listed || excused,
						"%s %s (%s) takes a password but is not in policyFamilyCases: add a row that sends a policy-violating password (or excuse it in policyFamilyNotNewPassword with the reason)",
						strings.ToUpper(method), path, op.OperationID)
				}
			}
		}
	}
	sort.Strings(found)
	for opID := range policyFamilyCases {
		assert.Contains(g, found, opID, "%s is in policyFamilyCases but openapi.yaml has no such operation with a password field", opID)
	}
	for opID := range policyFamilyNotNewPassword {
		assert.Contains(g, found, opID, "%s is excused but no longer has a password field: remove the entry", opID)
	}
}

// schemaHasPasswordProperty reports whether the schema (following local $refs and
// allOf/oneOf/anyOf) declares a password, new_password or current_password property.
func schemaHasPasswordProperty(n *yaml.Node, components map[string]yaml.Node, depth int) bool {
	if n == nil || n.Kind != yaml.MappingNode || depth > 6 {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		switch key {
		case "$ref":
			name := val.Value[strings.LastIndex(val.Value, "/")+1:]
			if ref, ok := components[name]; ok && schemaHasPasswordProperty(&ref, components, depth+1) {
				return true
			}
		case "properties":
			for j := 0; j+1 < len(val.Content); j += 2 {
				switch val.Content[j].Value {
				case "password", "new_password", "current_password":
					return true
				}
			}
		case "allOf", "oneOf", "anyOf":
			for _, sub := range val.Content {
				if schemaHasPasswordProperty(sub, components, depth+1) {
					return true
				}
			}
		}
	}
	return false
}

func sendChangePasswordViolation(t *testing.T) (*httptest.ResponseRecorder, string) {
	db := openCurrentPasswordDB(t)
	h := newLoginBudgetHandler(db)
	return changePasswordAs(t, h, lockoutOracleTestPassword, policyMsgPersonal), policyMsgPersonal
}

func sendInitSystemViolation(t *testing.T) (*httptest.ResponseRecorder, string) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxpolicyfamilyinit")
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetBootstrapToken("family-boot")
	const candidate = "Rootadmin-Str0ng-Passw0rd!x" // contains the username
	body := fmt.Sprintf(`{"username":"rootadmin","email":"rootadmin@example.com","password":%q}`, candidate)
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	req.Header.Set("X-Keyorix-Bootstrap-Token", "family-boot")
	w := httptest.NewRecorder()
	NewAuthHandler(c, false).InitSystem(w, req)
	return w, candidate
}

func postPolicyFamilyConsume(h *AuthHandler, token, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"token":%q,"password":%q}`, token, password)
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body)))
	return w
}

func sendConsumeSetupViolation(t *testing.T) (*httptest.ResponseRecorder, string) {
	h, c, _, _, adminID := newUndeliveredSetupFixture(t)
	token := issueSetupTokenForUserS11(t, c, adminID, "famuser@example.com", "famuser")
	const candidate = "Famuser-Str0ng-Passw0rd!x"
	return postPolicyFamilyConsume(h, token, candidate), candidate
}

func sendConsumeInvitationViolation(t *testing.T) (*httptest.ResponseRecorder, string) {
	h, _, _, st, adminID := newUndeliveredSetupFixture(t)
	ctx := context.Background()
	const email = "invitee@example.com"
	const rawToken = "kx_setup_policy-family-invite-http"

	proj, err := st.CreateProject(ctx, &models.Project{Name: "policy-family", Description: "d"})
	require.NoError(t, err)
	future := time.Now().Add(24 * time.Hour)
	inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: proj.ID, Email: email, Role: "project_developer", State: core.InvitationPending,
		InvitedBy: adminID, ValidationModeAtInvite: core.ValidationModeOpen, ExpiresAt: &future, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(rawToken))
	_, err = st.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: hex.EncodeToString(sum[:]), Purpose: core.SetupPurposeInvitationAccept, SubjectEmail: email,
		InvitationID: &inv.ID, State: core.SetupTokenActive, ExpiresAt: future, CreatedBy: adminID,
	})
	require.NoError(t, err)

	const candidate = "Invitee-Str0ng-Passw0rd!x" // contains the email local part
	return postPolicyFamilyConsume(h, rawToken, candidate), candidate
}

func sendCreateUserViolation(t *testing.T) (*httptest.ResponseRecorder, string) {
	h, _ := setupCreateUserAssignmentsTest(t)
	const candidate = "Newbie-Str0ng-Passw0rd!x"
	body := fmt.Sprintf(`{"username":"newbie","email":"newbie@x.io","display_name":"Newbie","password":%q}`, candidate)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader([]byte(body))))
	w := httptest.NewRecorder()
	h.CreateUser(w, req)
	return w, candidate
}
