package accessreview

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessReview_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"entries":[],"count":0}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 3
	require.NoError(t, AccessReviewCmd.RunE(AccessReviewCmd, nil))
}

func TestAccessReview_WithSourceEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"entries":[
			{"principal_type":"user","principal_name":"bob","email":"bob@x.io","source":"direct_share","access_level":"read","secret_name":"db-pass"},
			{"principal_type":"group","principal_name":"devs","source":"group_share","access_level":"write","secret_name":"api-key"}
		],"count":2}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 5
	require.NoError(t, AccessReviewCmd.RunE(AccessReviewCmd, nil))
}

func TestAccessReview_WithRoleEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"entries":[
			{"principal_type":"user","principal_name":"alice","email":"a@x.io","source":"role","role_name":"editor","access_level":"write","environment_id":2}
		],"count":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 7
	require.NoError(t, AccessReviewCmd.RunE(AccessReviewCmd, nil))
}

func TestRunDecision_Revoke_WithStubServer(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origSource, origPrincipalID, origRoleID, origPrincipalType :=
		dProject, dSource, dPrincipalID, dRoleID, dPrincipalType
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dRoleID = origRoleID
		dPrincipalType = origPrincipalType
	}()
	dProject = 4
	dSource = "role"
	dPrincipalType = "user"
	dPrincipalID = 10
	dRoleID = 5

	require.NoError(t, runDecision("revoke"))
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/projects/4/access-review/revoke", gotPath)
}

func TestRunDecision_Attest_WithStubServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origSource, origPrincipalID, origRoleID, origPrincipalType :=
		dProject, dSource, dPrincipalID, dRoleID, dPrincipalType
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dRoleID = origRoleID
		dPrincipalType = origPrincipalType
	}()
	dProject = 4
	dSource = "role"
	dPrincipalType = "group"
	dPrincipalID = 7
	dRoleID = 3

	require.NoError(t, runDecision("attest"))
	assert.Equal(t, "/api/v1/projects/4/access-review/attest", gotPath)
}

func TestRunDecision_ShareSource_WithSecretID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origSource, origPrincipalID, origSecretID, origRoleID :=
		dProject, dSource, dPrincipalID, dSecretID, dRoleID
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dSecretID = origSecretID
		dRoleID = origRoleID
	}()
	dProject = 4
	dSource = "direct_share"
	dPrincipalID = 8
	dSecretID = 12
	dRoleID = 0

	require.NoError(t, runDecision("revoke"))
}

func TestRunDecision_NoServerConnection(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject, origSource, origPrincipalID, origRoleID :=
		dProject, dSource, dPrincipalID, dRoleID
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dRoleID = origRoleID
	}()
	dProject = 4
	dSource = "role"
	dPrincipalID = 1
	dRoleID = 2

	err := runDecision("revoke")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// Campaign subcommand tests

func TestCampaignListCmd_RequiresProjectID(t *testing.T) {
	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 0

	err := campaignListCmd.RunE(campaignListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id is required")
}

func TestCampaignListCmd_WithStubServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"campaigns":[{"campaign":{"id":1,"project_id":5,"name":"Q1 Review","state":"open"},"progress":{"total":5,"pending":3,"attested":1,"revoked":1}}],"count":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 5

	require.NoError(t, campaignListCmd.RunE(campaignListCmd, nil))
	assert.Equal(t, "/api/v1/projects/5/access-review/campaigns", gotPath)
}

func TestCampaignListCmd_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaigns":[],"count":0}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 5

	require.NoError(t, campaignListCmd.RunE(campaignListCmd, nil))
}

func TestCampaignShowCmd_RequiresBothIDs(t *testing.T) {
	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()

	cProject = 0
	cCampaign = 0
	err := campaignShowCmd.RunE(campaignShowCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id and --campaign-id are required")

	cProject = 5
	cCampaign = 0
	err = campaignShowCmd.RunE(campaignShowCmd, nil)
	require.Error(t, err)
}

func TestCampaignShowCmd_WithStubServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":3,"project_id":5,"name":"Q1","state":"open"},"items":[{"id":1,"principal_type":"user","principal_name":"alice","source":"role","role_name":"editor","access_level":"write","decision":"pending"}],"progress":{"total":1,"pending":1}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 5
	cCampaign = 3

	require.NoError(t, campaignShowCmd.RunE(campaignShowCmd, nil))
	assert.Equal(t, "/api/v1/projects/5/access-review/campaigns/3", gotPath)
}

func TestCampaignOpenCmd_RequiresProjectID(t *testing.T) {
	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 0

	err := campaignOpenCmd.RunE(campaignOpenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id is required")
}

func TestCampaignOpenCmd_WithStubServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":10,"project_id":5,"name":"Test Campaign","state":"open"},"progress":{"total":3,"pending":3,"attested":0,"revoked":0}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origName := cProject, cName
	defer func() { cProject = origProject; cName = origName }()
	cProject = 5
	cName = "Test Campaign"

	require.NoError(t, campaignOpenCmd.RunE(campaignOpenCmd, nil))
}

func TestCampaignDecideCmd_RequiresAllIDs(t *testing.T) {
	origProject, origCampaign, origItem, origAction :=
		cProject, cCampaign, cItem, cAction
	defer func() {
		cProject = origProject
		cCampaign = origCampaign
		cItem = origItem
		cAction = origAction
	}()

	cProject = 0
	cCampaign = 1
	cItem = 1
	cAction = "attest"
	err := campaignDecideCmd.RunE(campaignDecideCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id, --campaign-id and --item-id are required")
}

func TestCampaignDecideCmd_BadAction(t *testing.T) {
	origProject, origCampaign, origItem, origAction :=
		cProject, cCampaign, cItem, cAction
	defer func() {
		cProject = origProject
		cCampaign = origCampaign
		cItem = origItem
		cAction = origAction
	}()
	cProject = 5
	cCampaign = 3
	cItem = 1
	cAction = "approve" // invalid

	err := campaignDecideCmd.RunE(campaignDecideCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--action must be attest or revoke")
}

func TestCampaignDecideCmd_WithStubServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origCampaign, origItem, origAction, origReason :=
		cProject, cCampaign, cItem, cAction, cReason
	defer func() {
		cProject = origProject
		cCampaign = origCampaign
		cItem = origItem
		cAction = origAction
		cReason = origReason
	}()
	cProject = 5
	cCampaign = 3
	cItem = 7
	cAction = "attest"
	cReason = "reviewed and approved"

	require.NoError(t, campaignDecideCmd.RunE(campaignDecideCmd, nil))
	assert.Equal(t, "/api/v1/projects/5/access-review/campaigns/3/items/7/decide", gotPath)
}

func TestCampaignCloseCmd_RequiresBothIDs(t *testing.T) {
	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 0
	cCampaign = 0

	err := campaignCloseCmd.RunE(campaignCloseCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id and --campaign-id are required")
}

func TestCampaignCloseCmd_WithStubServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":3,"project_id":5,"name":"Q1","state":"closed"},"progress":{"total":3,"pending":0,"attested":2,"revoked":1}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origCampaign, origForce := cProject, cCampaign, cForce
	defer func() { cProject = origProject; cCampaign = origCampaign; cForce = origForce }()
	cProject = 5
	cCampaign = 3
	cForce = false

	require.NoError(t, campaignCloseCmd.RunE(campaignCloseCmd, nil))
	assert.Equal(t, "/api/v1/projects/5/access-review/campaigns/3/close", gotPath)
}

func TestCampaignListCmd_DegradedFlagRendered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaigns":[
			{"campaign":{"id":1,"project_id":5,"name":"Q1","state":"open","degraded":true,"degraded_reasons":["secret 42 unreadable"]},"progress":{"total":2,"pending":2}}
		],"count":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 5
	require.NoError(t, campaignListCmd.RunE(campaignListCmd, nil))
}

func TestProgressStr(t *testing.T) {
	p := progressView{Total: 10, Pending: 5, Attested: 3, Revoked: 2}
	got := progressStr(p)
	assert.Contains(t, got, "10 total")
	assert.Contains(t, got, "5 pending")
	assert.Contains(t, got, "3 attested")
	assert.Contains(t, got, "2 revoked")
}
