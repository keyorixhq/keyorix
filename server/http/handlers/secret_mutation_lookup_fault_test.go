package handlers

// secret_mutation_lookup_fault_test.go — FIX-ERRMAP-STRUCT-1 item 3 (#3873): the REST
// secret mutations that authorize INSIDE core (UpdateSecret, DeleteSecret, SetTags,
// DescribeSecret, MoveSecret) answer a storage outage of that permission lookup 503 +
// Retry-After with the gates' fixed text, not 403 "access denied" (the gRPC twins did
// so already through core.WithAuthorizeFaultRecorder / mapSecretMutationError). A real
// denial keeps its 403, and nothing is cached: the retry succeeds once the fault clears
// for a caller who is allowed.
//
// The fault is injected on the permission lookup itself (ResolveUserPermissionAt) for a
// caller who is neither owner nor sharee, so core's RBAC fallback is the read that fails.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type mutationLookupSite struct {
	name string
	call func(h *SecretHandler, id string, actor uint) *httptest.ResponseRecorder
}

func mutationLookupSites() []mutationLookupSite {
	return []mutationLookupSite{
		{"UpdateSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.UpdateSecret, http.MethodPut, `{"value":"v2"}`, id, a)
		}},
		{"DeleteSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.DeleteSecret, http.MethodDelete, "", id, a)
		}},
		{"SetTags", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.SetTags, http.MethodPut, `{"tags":["a"]}`, id, a)
		}},
		{"DescribeSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.DescribeSecret, http.MethodPatch, `{"description":"d"}`, id, a)
		}},
		{"MoveSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.MoveSecret, http.MethodPost, `{"parent_id":0}`, id, a)
		}},
	}
}

func TestSecretMutation_PermissionLookupOutageIs503(t *testing.T) {
	for _, site := range mutationLookupSites() {
		t.Run(site.name, func(t *testing.T) {
			_, db := freshCoreS12WithAdmin(t)
			fx := seedSecretsFixture(t, db)
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError,
				Err: fmt.Errorf("injected: dial tcp: %w", syscall.ECONNREFUSED),
			})
			h, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)

			w := site.call(h, fx.id(), secretsPlainID)
			require.True(t, faulty.Fired(), "%s must reach the permission lookup", site.name)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, authorizeLookupUnavailableRetryAfter, w.Header().Get("Retry-After"))
			assert.Contains(t, w.Body.String(), authorizeLookupUnavailableMessage)
			assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			assert.NotContains(t, w.Body.String(), "Forbidden")
			assert.NotContains(t, strings.ToLower(w.Body.String()), "denied")
		})
	}
}

func TestSecretMutation_PermissionDenialStays403(t *testing.T) {
	for _, site := range mutationLookupSites() {
		t.Run(site.name, func(t *testing.T) {
			cs, db := freshCoreS12WithAdmin(t)
			fx := seedSecretsFixture(t, db)
			h, err := NewSecretHandler(cs)
			require.NoError(t, err)
			w := site.call(h, fx.id(), secretsPlainID)
			assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"))
		})
	}
}
