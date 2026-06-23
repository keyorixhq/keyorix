package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunGetRemote_ByRef(t *testing.T) {
	var gotPath, gotRef string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotRef = r.URL.Path, r.URL.Query().Get("ref")
		if gotPath == "/api/v1/secrets/value" {
			_, _ = w.Write([]byte(`{"data":{"secret":{},"value":"p4ss"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	getID, getName, getRef, getShowValue = 0, "", "app/production/db", true
	defer func() { getID, getName, getRef, getShowValue = 0, "", "", false }()

	require.NoError(t, runGetRemote(context.Background(), rc))
	assert.Equal(t, "/api/v1/secrets/value", gotPath, "--ref uses the by-reference value endpoint (ADR-059)")
	assert.Equal(t, "app/production/db", gotRef, "the full project/environment/name ref is passed")
}

func TestRunGet_SelectorValidation(t *testing.T) {
	reset := func() { getID, getName, getRef, getShowValue = 0, "", "", false }
	defer reset()

	reset()
	require.ErrorContains(t, runGet(nil, nil), "one of --id, --name, or --ref")

	reset()
	getID, getRef = 1, "app/prod/db"
	require.ErrorContains(t, runGet(nil, nil), "mutually exclusive")
}
