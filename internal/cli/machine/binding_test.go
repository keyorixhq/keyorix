package machine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBindingCmd_Registration(t *testing.T) {
	binding, _, err := MachineCmd.Find([]string{"binding"})
	require.NoError(t, err)
	require.Equal(t, "binding", binding.Name())

	subs := map[string]*struct{ args, project bool }{}
	for _, name := range []string{"add", "list", "rm"} {
		subs[name] = &struct{ args, project bool }{}
	}
	for _, c := range binding.Commands() {
		if s, ok := subs[c.Name()]; ok {
			s.project = c.Flags().Lookup("project") != nil
		}
	}
	for _, name := range []string{"add", "list", "rm"} {
		require.Contains(t, subs, name)
		assert.True(t, subs[name].project, "binding %s should have --project", name)
	}

	add, _, _ := binding.Find([]string{"add"})
	assert.NotNil(t, add.Flags().Lookup("issuer"), "add should have --issuer")
	assert.NotNil(t, add.Flags().Lookup("subject"), "add should have --subject")

	// Arg arity: add/list take one ref, rm takes <machine> <binding-id>.
	assert.Error(t, add.Args(add, []string{}))
	assert.NoError(t, add.Args(add, []string{"ci"}))
	rm, _, _ := binding.Find([]string{"rm"})
	assert.Error(t, rm.Args(rm, []string{"ci"}))
	assert.NoError(t, rm.Args(rm, []string{"ci", "4"}))
}

func TestFetchBindingsRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/3/machine-identities/5/oidc-bindings" {
			_, _ = w.Write([]byte(`{"data":{"bindings":[` +
				`{"id":1,"issuer":"https://kubernetes.default.svc","subject":"system:serviceaccount:prod:ci","created_at":"2026-06-20T10:00:00Z"},` +
				`{"id":2,"issuer":"https://accounts.google.com","subject":"123","created_at":"2026-06-21T10:00:00Z"}` +
				`]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	rows, err := fetchBindingsRemote(context.Background(), rc, 3, 5)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, uint(1), rows[0].ID)
	assert.Equal(t, "https://kubernetes.default.svc", rows[0].Issuer)
	assert.Equal(t, "system:serviceaccount:prod:ci", rows[0].Subject)
	assert.False(t, rows[0].CreatedAt.IsZero(), "created_at should parse")
	assert.Equal(t, uint(2), rows[1].ID)
}
