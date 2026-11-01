// scope_resolver_ref_read_fault_test.go — ERR-FOLD-HANDLERS-1 item 1.
//
// RequireScopedSecretRefPermission resolves ?ref=project/environment/name through
// core.ResolveSecretRef. That used to fold a ListProjects / ListEnvironmentsByProject /
// GetSecretByName fault into errTargetNotFound (404 for a global holder), so a database
// outage looked like "no such secret". A fault now takes the errTargetReadFault branch
// of the by-ID resolvers: 503 for a global holder, the absent-target 403 for anyone else.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

func srfServeRef(t *testing.T, w *srfWorld, user uint, ref string) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	rec := httptest.NewRecorder()
	req := makeRequest(t, http.MethodGet, "/x", nil, &UserContext{UserID: user, ActorType: core.ActorTypeUser}, w.cs)
	req.URL.RawQuery = "ref=" + ref
	RequireScopedSecretRefPermission("secrets.read")(okNext(&called)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		assert.False(t, called, "the handler behind the gate ran on a %d", rec.Code)
	}
	return rec
}

func TestScopeResolverRefReadFault(t *testing.T) {
	const ref = "proj/dev/s"
	for _, method := range []string{"ListProjects", "ListEnvironmentsByProject", "GetSecretByName"} {
		t.Run(method, func(t *testing.T) {
			w := newSRFWorld(t)
			w.armOnce(t, method, errScanFault)
			holder := srfServeRef(t, w, a503UserAdmin, ref)
			w.disarm(t)
			assert.Equal(t, http.StatusServiceUnavailable, holder.Code, "a read fault is not \"not found\": %s", holder.Body.String())
			assert.NotEmpty(t, holder.Header().Get("Retry-After"))
			assert.Contains(t, holder.Body.String(), `"storage_unavailable"`)
			assert.NotContains(t, holder.Body.String(), "project_id", "the driver cause must not reach the client")

			// A caller without global standing keeps the exact answer an absent ref gets.
			w.armOnce(t, method, errScanFault)
			fault := srfServeRef(t, w, a503UserNobody, ref)
			w.disarm(t)
			absent := srfServeRef(t, w, a503UserNobody, "proj/dev/absent")
			assert.Equal(t, http.StatusForbidden, absent.Code, absent.Body.String())
			assert.Equal(t, absent.Code, fault.Code)
			assert.Equal(t, absent.Body.String(), fault.Body.String())
			assert.Empty(t, fault.Header().Get("Retry-After"))

			// Nothing cached: the request is served once the fault clears.
			assert.Equal(t, http.StatusOK, srfServeRef(t, w, a503UserAdmin, ref).Code)
		})
	}

	t.Run("true not-found unchanged", func(t *testing.T) {
		w := newSRFWorld(t)
		holder := srfServeRef(t, w, a503UserAdmin, "proj/dev/absent")
		assert.Equal(t, http.StatusNotFound, holder.Code, holder.Body.String())
		assert.Empty(t, holder.Header().Get("Retry-After"))
	})
}
