package accessreview

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessReview_Wiring(t *testing.T) {
	assert.Equal(t, "access-review", AccessReviewCmd.Name())
	assert.Contains(t, AccessReviewCmd.Aliases, "recert")
	assert.NotNil(t, AccessReviewCmd.Flags().Lookup("project-id"))
}

func TestAccessReview_RequiresProject(t *testing.T) {
	flagProject = 0
	err := AccessReviewCmd.RunE(AccessReviewCmd, nil)
	require.ErrorContains(t, err, "--project-id is required")
}

func TestAccessReview_GetsProjectReview(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"entries":[{"principal_type":"user","principal_name":"alice","email":"a@x.io","role_name":"editor","access_level":"write","environment_id":0},{"principal_type":"group","principal_name":"devs","role_name":"viewer","access_level":"read","environment_id":0}],"count":2}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	flagProject = 7
	require.NoError(t, AccessReviewCmd.RunE(AccessReviewCmd, nil))
	assert.Equal(t, "/api/v1/projects/7/access-review", gotPath)
}
