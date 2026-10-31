// audit_search_actor_kinds_3736_test.go — #3736 over the real router: GET
// /api/v1/audit/search?actor= (what `keyorix audit search --actor` sends) finds the
// actor by the name the ACTOR column shows, for a user AND a machine identity. The
// storage filter is pinned by internal/storage/store/audit_actor_machine_search_test.go;
// this pins that the transport maps `actor` onto it and that the rows it returns show
// that actor, both reached by real requests (a machine-token read, a session read).
// gRPC GetAuditLogs has no actor-name filter (user_id and actor_type only), so there is
// no gRPC mapping to pin.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditSearch_ActorFindsUserAndMachineIdentity(t *testing.T) {
	w := newRRWorld(t, "sqlite", false)
	s := w.newSecret(t)
	// A value read (by reference) is audited as secret.read for either actor kind.
	path := fmt.Sprintf("/api/v1/secrets/value?ref=%s/%s/%s", w.projectName, w.envAName, s.Name)

	code, raw := doMachineRequest(t, w.a.srv, w.machineToken, http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, code, raw)
	code, raw = doMachineRequest(t, w.a.srv, w.tokens["dev"], http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, code, raw)

	sess, _, err := w.a.c.Login(context.Background(), &core.LoginRequest{Username: "rradmin", Password: rrPassword})
	require.NoError(t, err)

	search := func(actor string) []map[string]any {
		t.Helper()
		code, raw := doMachineRequest(t, w.a.srv, sess.SessionToken, http.MethodGet,
			fmt.Sprintf("/api/v1/audit/search?actor=%s&resource_id=%d&limit=100", actor, s.ID), nil)
		require.Equal(t, http.StatusOK, code, raw)
		var out struct {
			Data struct {
				Events []map[string]any `json:"events"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
		return out.Data.Events
	}

	for _, tc := range []struct{ term, actor, kind string }{
		{"rr-runner", "rr-runner", "machine_identity"}, // the machine's full name
		{"RUNNER", "rr-runner", "machine_identity"},    // partial, case-insensitive
		{"dev", "dev", "user"},
	} {
		got := search(tc.term)
		require.NotEmpty(t, got, "actor=%s finds nothing; the %s read is audited on secret %d", tc.term, tc.kind, s.ID)
		for _, e := range got {
			assert.Equal(t, tc.actor, e["actor"], "actor=%s returned another actor's row: %v", tc.term, e)
			assert.Equal(t, tc.kind, e["actor_type"], "actor=%s: %v", tc.term, e)
		}
	}
	assert.Empty(t, search("nobody-by-this-name"))
}
