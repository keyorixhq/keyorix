package k8ssync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSink points a RESTSink at an httptest server (same package, so we set fields
// directly rather than going through the in-cluster constructor).
func testSink(srv *httptest.Server) *RESTSink {
	return &RESTSink{host: srv.URL, token: "tok", fieldManager: "keyorix-sync", hc: srv.Client()}
}

func TestRESTSink_GetAbsentReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	data, err := testSink(srv).Get(context.Background(), "app", "creds")
	require.NoError(t, err)
	assert.Nil(t, data, "an absent Secret returns (nil, nil) so the engine treats it as create")
}

func TestRESTSink_GetDecodesData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/namespaces/app/secrets/creds", r.URL.Path)
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{"DB":"` + base64.StdEncoding.EncodeToString([]byte("p4ss")) + `"}}`))
	}))
	defer srv.Close()

	data, err := testSink(srv).Get(context.Background(), "app", "creds")
	require.NoError(t, err)
	assert.Equal(t, []byte("p4ss"), data["DB"])
}

// TestRESTSink_ApplyCreatesNewSecretViaPOST verifies that when no Secret exists yet
// at the target name, Apply issues a plain POST create rather than a Server-Side
// Apply PATCH (#Bug4): Kubernetes create is atomic against the object's existence, so
// a name collision that raced into existence between the ownership read and this
// write fails the POST outright (see TestRESTSink_ApplyCreateRace_Bug4) instead of
// silently claiming/overwriting whatever is there.
func TestRESTSink_ApplyCreatesNewSecretViaPOST(t *testing.T) {
	var gotMethod, gotPath, gotCT string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// The pre-write ownership check (#139): no pre-existing Secret at this
			// name, so Apply proceeds as a fresh create.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"DB": []byte("p4ss")})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, gotMethod, "a fresh create must be an atomic POST, not an unconditional force=true PATCH")
	assert.Equal(t, "/api/v1/namespaces/app/secrets", gotPath, "POST targets the namespace's collection endpoint, not a specific object path")
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, "Secret", gotBody["kind"])
	// Value is base64-encoded in the Secret's data map.
	data := gotBody["data"].(map[string]interface{})
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("p4ss")), data["DB"])
	// The Secret is stamped with the managed-by label so cleanup can find it.
	meta := gotBody["metadata"].(map[string]interface{})
	labels := meta["labels"].(map[string]interface{})
	assert.Equal(t, "keyorix-sync", labels["app.kubernetes.io/managed-by"])
	// A fresh create must never carry a resourceVersion precondition — there is
	// nothing to pin yet.
	_, hasRV := meta["resourceVersion"]
	assert.False(t, hasRV, "a create must not set resourceVersion")
}

// TestRESTSink_ApplyCreateRace_Bug4 proves the fix for Bug4: a namespace-scoped
// attacker races a Secret into existence at the exact target name between Apply's
// ownership read (GET, 404 — nothing there yet) and its write. The create POST must
// fail (simulating the K8s API server's atomic 409 AlreadyExists) rather than the old
// behavior of an unconditional force=true PATCH silently claiming and overwriting the
// attacker's pre-created object with the real secret value.
func TestRESTSink_ApplyCreateRace_Bug4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Ownership check observes nothing at this name yet.
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost:
			// The attacker's Secret raced into existence in between — the API server's
			// atomic create check rejects it.
			w.WriteHeader(http.StatusConflict)
		}
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"DB": []byte("real-secret")})
	require.Error(t, err, "a create-time race must surface as an error, never a silent overwrite")
	assert.Contains(t, err.Error(), "HTTP 409")
}

func TestRESTSink_ListOwnedScopesByLabel(t *testing.T) {
	var gotSelector string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/namespaces/app/secrets", r.URL.Path)
		gotSelector = r.URL.Query().Get("labelSelector")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"creds"}},{"metadata":{"name":"stale"}}]}`))
	}))
	defer srv.Close()

	names, err := testSink(srv).List(context.Background(), "app")
	require.NoError(t, err)
	assert.Equal(t, "app.kubernetes.io/managed-by=keyorix-sync", gotSelector,
		"List must scope to owned Secrets so foreign Secrets are never seen")
	assert.ElementsMatch(t, []string{"creds", "stale"}, names)
}

func TestRESTSink_DeleteOwnerConditional(t *testing.T) {
	var methods []string
	var deleteBody, deletePath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		switch r.Method {
		case http.MethodGet:
			// An owned Secret with a known uid/resourceVersion.
			_, _ = w.Write([]byte(`{"metadata":{"uid":"u-1","resourceVersion":"rv-9","labels":{"app.kubernetes.io/managed-by":"keyorix-sync"}}}`))
		case http.MethodDelete:
			b, _ := io.ReadAll(r.Body)
			deleteBody, deletePath = string(b), r.URL.Path
			_, _ = w.Write([]byte(`{"kind":"Status"}`))
		}
	}))
	defer srv.Close()

	err := testSink(srv).Delete(context.Background(), "app", "stale")
	require.NoError(t, err)
	assert.Equal(t, []string{http.MethodGet, http.MethodDelete}, methods, "the owner re-check (GET) must precede the DELETE")
	assert.Equal(t, "/api/v1/namespaces/app/secrets/stale", deletePath)
	// The delete is pinned to the exact object we verified (closes the TOCTOU).
	assert.Contains(t, deleteBody, `"uid":"u-1"`)
	assert.Contains(t, deleteBody, `"resourceVersion":"rv-9"`)
}

func TestRESTSink_DeleteSkipsUnownedSecret(t *testing.T) {
	var sawDelete bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			sawDelete = true
		}
		// The Secret no longer carries our managed-by label (e.g. label stripped and the
		// name reused by an unrelated object between listing and delete).
		_, _ = w.Write([]byte(`{"metadata":{"uid":"u-2","resourceVersion":"rv-1","labels":{"app":"other"}}}`))
	}))
	defer srv.Close()

	err := testSink(srv).Delete(context.Background(), "app", "not-ours")
	require.NoError(t, err)
	assert.False(t, sawDelete, "a Secret without our managed-by label must never be deleted")
}

func TestRESTSink_DeleteAbsentIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := testSink(srv).Delete(context.Background(), "app", "gone")
	require.NoError(t, err, "deleting an already-absent Secret meets the goal state")
}

// TestRESTSink_ApplyRefusesUnownedPreExistingSecret pins #139: Apply used
// force=true Server-Side Apply unconditionally, with no check for a pre-existing
// Secret at the target name — silently overwriting (and, by always stamping the
// managed-by label, "branding" as agent-owned) a Secret an operator or a
// different tool created. The next orphan-cleanup pass would then DELETE that
// foreign Secret outright. Apply must refuse to write when a pre-existing
// Secret lacks the managed-by label, and must never even attempt the PATCH.
func TestRESTSink_ApplyRefusesUnownedPreExistingSecret(t *testing.T) {
	var sawPatch bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sawPatch = true
			_, _ = w.Write([]byte(`{"kind":"Secret"}`))
			return
		}
		// A pre-existing Secret this agent did not create (an operator's own
		// database credential, unrelated to Keyorix).
		_, _ = w.Write([]byte(`{"metadata":{"uid":"u-1","resourceVersion":"rv-1","labels":{"app.kubernetes.io/managed-by":"some-operator"}}}`))
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "db-credentials", map[string][]byte{"password": []byte("new")})
	require.Error(t, err)
	assert.True(t, ErrNotManaged(err), "the error must be identifiable as the not-managed refusal")
	assert.False(t, sawPatch, "an unowned pre-existing Secret must never be written to, not even attempted")
}

// A Secret this agent already owns (from a prior apply) can still be updated. #Bug4:
// the PATCH must carry the exact resourceVersion just observed as an
// optimistic-concurrency precondition, so a change to the object between the
// ownership read and this write (e.g. deleted and recreated by an attacker under the
// same name) is rejected by the API server rather than silently overwritten.
func TestRESTSink_ApplyUpdatesAlreadyOwnedSecret(t *testing.T) {
	var sawPatch bool
	var gotCT, gotFM, gotForce string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			sawPatch = true
			gotCT = r.Header.Get("Content-Type")
			gotFM = r.URL.Query().Get("fieldManager")
			gotForce = r.URL.Query().Get("force")
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotBody)
			_, _ = w.Write([]byte(`{"kind":"Secret"}`))
			return
		}
		_, _ = w.Write([]byte(`{"metadata":{"uid":"u-1","resourceVersion":"rv-1","labels":{"app.kubernetes.io/managed-by":"keyorix-sync"}}}`))
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"DB": []byte("v2")})
	require.NoError(t, err)
	assert.True(t, sawPatch, "an already-owned Secret must still be updatable")
	assert.Equal(t, "application/apply-patch+yaml", gotCT)
	assert.Equal(t, "keyorix-sync", gotFM)
	assert.Equal(t, "true", gotForce)
	meta := gotBody["metadata"].(map[string]interface{})
	assert.Equal(t, "rv-1", meta["resourceVersion"], "the PATCH must pin the exact resourceVersion observed by the ownership check")
}

// TestRESTSink_ApplyPatchRejectsResourceVersionConflict_Bug4 proves the precondition
// is load-bearing, not decorative: when the server reports the resourceVersion no
// longer matches (a 409, simulating the object having changed between the ownership
// read and this PATCH), Apply must surface that as an error rather than treating the
// write as having succeeded.
func TestRESTSink_ApplyPatchRejectsResourceVersionConflict_Bug4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusConflict)
			return
		}
		_, _ = w.Write([]byte(`{"metadata":{"uid":"u-1","resourceVersion":"rv-1","labels":{"app.kubernetes.io/managed-by":"keyorix-sync"}}}`))
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"DB": []byte("v2")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 409")
}

// failOnMethodTransport is an http.RoundTripper that simulates a network failure
// for one specific HTTP method (letting every other method through to base), so a
// test can force applyOwnedSecret's/createSecret's hc.Do error branch on exactly the
// request it targets without disturbing the preceding ownership-check GET.
type failOnMethodTransport struct {
	base       http.RoundTripper
	failMethod string
}

func (t *failOnMethodTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == t.failMethod {
		return nil, fmt.Errorf("simulated network failure")
	}
	return t.base.RoundTrip(req)
}

// TestRESTSink_ApplyPatchNetworkError exercises applyOwnedSecret's hc.Do error
// branch: the ownership-check GET succeeds (the Secret is owned, so Apply proceeds
// to the Server-Side-Apply PATCH), but the PATCH itself fails at the transport level
// (e.g. a connection drop) rather than getting an HTTP response at all.
func TestRESTSink_ApplyPatchNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the ownership-check GET should ever reach the server; the PATCH is
		// intercepted by the failing transport before it leaves the client.
		require.Equal(t, http.MethodGet, r.Method)
		_, _ = w.Write([]byte(`{"metadata":{"uid":"u-1","resourceVersion":"rv-1","labels":{"app.kubernetes.io/managed-by":"keyorix-sync"}}}`))
	}))
	defer srv.Close()

	sink := testSink(srv)
	sink.hc = &http.Client{Transport: &failOnMethodTransport{base: http.DefaultTransport, failMethod: http.MethodPatch}}

	err := sink.Apply(context.Background(), "app", "creds", map[string][]byte{"DB": []byte("v2")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestRESTSink_ApplyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := testSink(srv).Apply(context.Background(), "app", "creds", map[string][]byte{"K": []byte("v")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403")
}

// End-to-end through the engine: the REST sink plays the K8s side while a fake
// fetcher plays Keyorix, proving the seams compose.
func TestRESTSink_WithEngine(t *testing.T) {
	applied := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound) // nothing exists yet → create
			return
		}
		applied[r.URL.Path] = true
		_, _ = w.Write([]byte(`{"kind":"Secret"}`))
	}))
	defer srv.Close()

	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	res, err := NewEngine(f, testSink(srv)).Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created)
	// Nothing existed yet, so Apply creates via POST to the namespace collection
	// endpoint (#Bug4), not a PATCH to the specific object path.
	assert.True(t, applied["/api/v1/namespaces/app/secrets"])
}
