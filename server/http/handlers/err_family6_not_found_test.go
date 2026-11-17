package handlers

// err_family6_not_found_test.go — CORE-ERR-FAMILY-6 item 1 (REST).
//
// Five handlers answered 404 by looking for "not found" in the error text, so a storage
// read FAULT whose driver message contains those words read as a missing target (and a
// plain fault was a 500). Core now types the not-found, the handler reads it with
// errors.Is, and a fault is 503 storage_unavailable + Retry-After. A true not-found
// stays 404.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// errFaultNotFoundText is a driver-style fault whose text contains the words the old handlers matched.
var errFaultNotFoundText = errors.New("driver: relation lookup failed: not found in pool")

func armFamily6(fw *foldWorld, method string) {
	fw.faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: errFaultNotFoundText})
}

func TestErrFamily6_Item1_PostReadNotFoundIsTypedAndFaultIs503(t *testing.T) {
	fw := newFoldWorld(t)

	cat := NewCatalogHandler(fw.cs)
	groups, err := NewGroupHandler(fw.cs)
	require.NoError(t, err)
	tmpls := NewSecretTemplateHandler(fw.cs)
	shares, err := NewShareHandler(fw.cs)
	require.NoError(t, err)

	proj, secret := fw.secret(t, "fam6")
	group := &models.Group{Name: "fam6-group", NameFolded: "fam6-group"}
	require.NoError(t, fw.db.Create(group).Error)
	tmpl := &models.SecretTemplate{Name: "fam6-tmpl", Description: "d"}
	require.NoError(t, fw.db.Create(tmpl).Error)

	cases := []struct {
		name   string
		method string // storage method the fault is armed on
		call   func(id string) *httptest.ResponseRecorder
		okID   uint
	}{
		{"GetProject", "GetProject", func(id string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.GetProject(w, suReq(http.MethodGet, "", map[string]string{"id": id}))
			return w
		}, proj.ID},
		{"GetGroup", "GetGroup", func(id string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			groups.GetGroup(w, suReq(http.MethodGet, "", map[string]string{"id": id}))
			return w
		}, group.ID},
		{"SecretTemplate.Get", "GetSecretTemplate", func(id string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			tmpls.Get(w, suReq(http.MethodGet, "", map[string]string{"id": id}))
			return w
		}, tmpl.ID},
		{"GetSharingStatusWithIndicators", "GetSecret", func(id string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			shares.GetSharingStatusWithIndicators(w, suReq(http.MethodGet, "", map[string]string{"id": id}))
			return w
		}, secret.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			armFamily6(fw, tc.method)
			w := tc.call(suID(tc.okID))
			require.True(t, fw.faulty.Fired(), "the read fault must be reached")
			requireFold503(t, w, tc.name+" read fault whose text says not found")
			fw.faulty.Arm(nil)

			w = tc.call("9999999")
			assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404: %s", w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"))
		})
	}

	t.Run("sharing status: a later read fault is 503, a stranger is 403", func(t *testing.T) {
		for _, method := range []string{"ListSharesBySecret"} {
			armFamily6(fw, method)
			w := httptest.NewRecorder()
			shares.GetSharingStatusWithIndicators(w, suReq(http.MethodGet, "", map[string]string{"id": suID(secret.ID)}))
			require.True(t, fw.faulty.Fired(), method)
			requireFold503(t, w, method+" fault")
			fw.faulty.Arm(nil)
		}
		w := httptest.NewRecorder()
		shares.GetSharingStatusWithIndicators(w, suReq(http.MethodGet, "", map[string]string{"id": suID(secret.ID)}))
		assert.Equal(t, http.StatusForbidden, w.Code, "user 1 neither owns nor holds a share: %s", w.Body.String())
	})
}
