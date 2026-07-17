package accessreview

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureOutput redirects os.Stdout during fn, returning what was printed.
func captureOutput(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(fmt.Sprintf("captureOutput: os.Pipe: %v", err))
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// --- printCampaignDegradedWarning ---

func TestPrintCampaignDegradedWarning_NotDegraded(t *testing.T) {
	out := captureOutput(func() {
		printCampaignDegradedWarning(campaignView{Degraded: false})
	})
	assert.Empty(t, out, "no output expected when Degraded=false")
}

func TestPrintCampaignDegradedWarning_DegradedNoReasons(t *testing.T) {
	out := captureOutput(func() {
		printCampaignDegradedWarning(campaignView{Degraded: true})
	})
	assert.Contains(t, out, "DEGRADED SNAPSHOT")
}

func TestPrintCampaignDegradedWarning_DegradedWithReasons(t *testing.T) {
	out := captureOutput(func() {
		printCampaignDegradedWarning(campaignView{
			Degraded:        true,
			DegradedReasons: []string{"secret 42 unreadable", "secret 99 unreadable"},
		})
	})
	assert.Contains(t, out, "DEGRADED SNAPSHOT")
	assert.Contains(t, out, "secret 42 unreadable")
	assert.Contains(t, out, "secret 99 unreadable")
}

// --- AccessReviewCmd "not connected" ---

func TestAccessReview_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 1

	err := AccessReviewCmd.RunE(AccessReviewCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// --- AccessReviewCmd server error ---

func TestAccessReview_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 1

	err := AccessReviewCmd.RunE(AccessReviewCmd, nil)
	require.Error(t, err)
}

// --- campaignOpenCmd "not connected" ---

func TestCampaignOpenCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject, origName := cProject, cName
	defer func() { cProject = origProject; cName = origName }()
	cProject = 1
	cName = "test"

	err := campaignOpenCmd.RunE(campaignOpenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// --- campaignOpenCmd server error ---

func TestCampaignOpenCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origName := cProject, cName
	defer func() { cProject = origProject; cName = origName }()
	cProject = 1
	cName = "err campaign"

	err := campaignOpenCmd.RunE(campaignOpenCmd, nil)
	require.Error(t, err)
}

// --- campaignOpenCmd degraded response ---

func TestCampaignOpenCmd_DegradedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":2,"project_id":7,"name":"Degraded","state":"open","degraded":true,"degraded_reasons":["secret 5 unreadable"]},"progress":{"total":1,"pending":1,"attested":0,"revoked":0}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origName := cProject, cName
	defer func() { cProject = origProject; cName = origName }()
	cProject = 7
	cName = "Degraded"

	out := captureOutput(func() {
		require.NoError(t, campaignOpenCmd.RunE(campaignOpenCmd, nil))
	})
	assert.Contains(t, out, "DEGRADED SNAPSHOT")
	assert.Contains(t, out, "secret 5 unreadable")
}

// --- campaignListCmd "not connected" ---

func TestCampaignListCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 1

	err := campaignListCmd.RunE(campaignListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// --- campaignListCmd server error ---

func TestCampaignListCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject := cProject
	defer func() { cProject = origProject }()
	cProject = 1

	err := campaignListCmd.RunE(campaignListCmd, nil)
	require.Error(t, err)
}

// --- campaignShowCmd "not connected" ---

func TestCampaignShowCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 1
	cCampaign = 1

	err := campaignShowCmd.RunE(campaignShowCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// --- campaignShowCmd server error ---

func TestCampaignShowCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 1
	cCampaign = 1

	err := campaignShowCmd.RunE(campaignShowCmd, nil)
	require.Error(t, err)
}

// --- campaignShowCmd empty items ---

func TestCampaignShowCmd_EmptyItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":3,"project_id":5,"name":"Empty","state":"open"},"items":[],"progress":{"total":0,"pending":0,"attested":0,"revoked":0}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 5
	cCampaign = 3

	out := captureOutput(func() {
		require.NoError(t, campaignShowCmd.RunE(campaignShowCmd, nil))
	})
	assert.Contains(t, out, "No items.")
}

// --- campaignShowCmd degraded campaign ---

func TestCampaignShowCmd_DegradedCampaign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":4,"project_id":5,"name":"Deg","state":"open","degraded":true,"degraded_reasons":["secret 77 unreadable"]},"items":[],"progress":{"total":0,"pending":0,"attested":0,"revoked":0}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 5
	cCampaign = 4

	out := captureOutput(func() {
		require.NoError(t, campaignShowCmd.RunE(campaignShowCmd, nil))
	})
	assert.Contains(t, out, "DEGRADED SNAPSHOT")
	assert.Contains(t, out, "secret 77 unreadable")
}

// --- campaignShowCmd items with email and secret source ---

func TestCampaignShowCmd_ItemsWithEmailAndSecretSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":5,"project_id":6,"name":"C","state":"open"},"items":[
			{"id":1,"principal_type":"user","principal_name":"bob","email":"bob@x.io","source":"direct_share","access_level":"read","secret_name":"db-pass","decision":"pending"},
			{"id":2,"principal_type":"group","principal_name":"devs","source":"group_share","access_level":"write","secret_name":"api-key","decision":"pending"}
		],"progress":{"total":2,"pending":2,"attested":0,"revoked":0}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 6
	cCampaign = 5

	out := captureOutput(func() {
		require.NoError(t, campaignShowCmd.RunE(campaignShowCmd, nil))
	})
	assert.Contains(t, out, "bob")
	assert.Contains(t, out, "db-pass")
}

// --- campaignDecideCmd "not connected" ---

func TestCampaignDecideCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject, origCampaign, origItem, origAction :=
		cProject, cCampaign, cItem, cAction
	defer func() {
		cProject = origProject
		cCampaign = origCampaign
		cItem = origItem
		cAction = origAction
	}()
	cProject = 1
	cCampaign = 1
	cItem = 1
	cAction = "attest"

	err := campaignDecideCmd.RunE(campaignDecideCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// --- campaignDecideCmd server error ---

func TestCampaignDecideCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign, origItem, origAction :=
		cProject, cCampaign, cItem, cAction
	defer func() {
		cProject = origProject
		cCampaign = origCampaign
		cItem = origItem
		cAction = origAction
	}()
	cProject = 1
	cCampaign = 1
	cItem = 1
	cAction = "revoke"

	err := campaignDecideCmd.RunE(campaignDecideCmd, nil)
	require.Error(t, err)
}

// --- campaignDecideCmd missing campaign-id only ---

func TestCampaignDecideCmd_MissingCampaignID(t *testing.T) {
	origProject, origCampaign, origItem, origAction :=
		cProject, cCampaign, cItem, cAction
	defer func() {
		cProject = origProject
		cCampaign = origCampaign
		cItem = origItem
		cAction = origAction
	}()
	cProject = 5
	cCampaign = 0
	cItem = 1
	cAction = "attest"

	err := campaignDecideCmd.RunE(campaignDecideCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id, --campaign-id and --item-id are required")
}

// --- campaignDecideCmd missing item-id only ---

func TestCampaignDecideCmd_MissingItemID(t *testing.T) {
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
	cItem = 0
	cAction = "attest"

	err := campaignDecideCmd.RunE(campaignDecideCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id, --campaign-id and --item-id are required")
}

// --- campaignCloseCmd "not connected" ---

func TestCampaignCloseCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origProject, origCampaign := cProject, cCampaign
	defer func() { cProject = origProject; cCampaign = origCampaign }()
	cProject = 1
	cCampaign = 1

	err := campaignCloseCmd.RunE(campaignCloseCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// --- campaignCloseCmd server error ---

func TestCampaignCloseCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign, origForce := cProject, cCampaign, cForce
	defer func() { cProject = origProject; cCampaign = origCampaign; cForce = origForce }()
	cProject = 1
	cCampaign = 1
	cForce = false

	err := campaignCloseCmd.RunE(campaignCloseCmd, nil)
	require.Error(t, err)
}

// --- campaignCloseCmd degraded response ---

func TestCampaignCloseCmd_DegradedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"campaign":{"id":3,"project_id":5,"name":"Q1","state":"closed","degraded":true,"degraded_reasons":["secret 10 unreadable"]},"progress":{"total":3,"pending":0,"attested":2,"revoked":1}}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origCampaign, origForce := cProject, cCampaign, cForce
	defer func() { cProject = origProject; cCampaign = origCampaign; cForce = origForce }()
	cProject = 5
	cCampaign = 3
	cForce = true

	out := captureOutput(func() {
		require.NoError(t, campaignCloseCmd.RunE(campaignCloseCmd, nil))
	})
	assert.Contains(t, out, "DEGRADED SNAPSHOT")
	assert.Contains(t, out, "secret 10 unreadable")
}

// --- campaignBase helper ---

func TestCampaignBase(t *testing.T) {
	assert.Equal(t, "/api/v1/projects/42/access-review/campaigns", campaignBase(42))
}
