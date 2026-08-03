package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Machine identities ---

func TestRemoteStorage_CreateMachineIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 1, "project_id": 2, "name": "ci-runner",
			"identity_type": "ci", "state": "pending", "description": "CI runner",
			"created_by": 5, "created_at": time.Now(), "updated_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	mi, err := rs.CreateMachineIdentity(context.Background(), &models.MachineIdentity{
		Name: "ci-runner", ProjectID: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(1), mi.ID)
	assert.Equal(t, "ci-runner", mi.Name)
	assert.Equal(t, uint(2), mi.ProjectID)
}

func TestRemoteStorage_GetMachineIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/7", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 7, "name": "svc-account", "state": "active",
			"created_at": time.Now(), "updated_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	mi, err := rs.GetMachineIdentity(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, uint(7), mi.ID)
	assert.Equal(t, "svc-account", mi.Name)
	assert.Equal(t, "active", mi.State)
}

func TestRemoteStorage_LockMachineIdentityForUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 3, "name": "k8s-sa", "state": "active",
			"created_at": time.Now(), "updated_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	mi, err := rs.LockMachineIdentityForUpdate(context.Background(), 3)
	require.NoError(t, err)
	assert.Equal(t, uint(3), mi.ID)
	assert.Equal(t, "k8s-sa", mi.Name)
}

func TestRemoteStorage_UpdateMachineIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/9", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateMachineIdentity(context.Background(), &models.MachineIdentity{
		ID: 9, Name: "updated-runner", State: "active",
	})
	require.NoError(t, err)
}

func TestRemoteStorage_TransitionMachineIdentityState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/4/transition", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	matched, err := rs.TransitionMachineIdentityState(context.Background(),
		&models.MachineIdentity{ID: 4, State: "active"}, "pending")
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestRemoteStorage_TransitionMachineIdentityState_NotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	matched, err := rs.TransitionMachineIdentityState(context.Background(),
		&models.MachineIdentity{ID: 4, State: "revoked"}, "active")
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestRemoteStorage_ListMachineIdentities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"machine_identities": []map[string]interface{}{
				{
					"id": 1, "project_id": 10, "name": "runner",
					"state": "active", "created_at": time.Now(), "updated_at": time.Now(),
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListMachineIdentities(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(1), list[0].ID)
	assert.Equal(t, "runner", list[0].Name)
}

func TestRemoteStorage_ListAllMachineIdentities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/all", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"machine_identities": []map[string]interface{}{
				{
					"id": 2, "name": "global-runner",
					"state": "active", "created_at": time.Now(), "updated_at": time.Now(),
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListAllMachineIdentities(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(2), list[0].ID)
}

func TestRemoteStorage_CountMachineIdentitiesByClassification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/classification-counts", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"counts": map[string]int{"confidential": 3, "public": 7},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	counts, err := rs.CountMachineIdentitiesByClassification(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, counts["confidential"])
	assert.Equal(t, 7, counts["public"])
}

func TestRemoteStorage_CountStaleMachineIdentitiesByProject_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:9"))
	require.NoError(t, err)

	_, err = rs.CountStaleMachineIdentitiesByProject(context.Background(), []uint{1}, time.Now())
	assert.Error(t, err)
}

// --- Machine-token credentials ---

func TestRemoteStorage_CreateMachineIdentityCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 11, "machine_identity_id": 4, "name": "prod-token",
			"token_hash": "abc123", "token_prefix": "kx_machine_ab",
			"created_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	cred, err := rs.CreateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{
		MachineIdentityID: 4, Name: "prod-token", TokenHash: "abc123",
	})
	require.NoError(t, err)
	assert.Equal(t, uint(11), cred.ID)
	assert.Equal(t, "prod-token", cred.Name)
	assert.Equal(t, "abc123", cred.TokenHash)
}

func TestRemoteStorage_GetMachineIdentityCredentialByHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/by-hash/deadbeef", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 5, "machine_identity_id": 2, "name": "ci-token",
			"token_hash": "deadbeef", "token_prefix": "kx_machine_de",
			"created_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	cred, err := rs.GetMachineIdentityCredentialByHash(context.Background(), "deadbeef")
	require.NoError(t, err)
	assert.Equal(t, uint(5), cred.ID)
	assert.Equal(t, "deadbeef", cred.TokenHash)
}

func TestRemoteStorage_GetMachineIdentityCredentialByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/8", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 8, "machine_identity_id": 3, "name": "svc-token",
			"token_hash": "cafebabe", "token_prefix": "kx_machine_ca",
			"created_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	cred, err := rs.GetMachineIdentityCredentialByID(context.Background(), 8)
	require.NoError(t, err)
	assert.Equal(t, uint(8), cred.ID)
	assert.Equal(t, "svc-token", cred.Name)
}

func TestRemoteStorage_ListMachineIdentityCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/6/credentials", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"credentials": []map[string]interface{}{
				{
					"id": 20, "machine_identity_id": 6, "name": "tok-a",
					"token_hash": "hash1", "token_prefix": "kx_machine_ha",
					"created_at": time.Now(),
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListMachineIdentityCredentials(context.Background(), 6)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(20), list[0].ID)
	assert.Equal(t, "tok-a", list[0].Name)
}

func TestRemoteStorage_ListActiveMachineIdentityCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/active", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"credentials": []map[string]interface{}{
				{
					"id": 30, "machine_identity_id": 1, "name": "active-tok",
					"token_hash": "hash2", "token_prefix": "kx_machine_hb",
					"revoked": false, "created_at": time.Now(),
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListActiveMachineIdentityCredentials(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(30), list[0].ID)
	assert.False(t, list[0].Revoked)
}

func TestRemoteStorage_UpdateMachineIdentityCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/15", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{
		ID: 15, Name: "updated-tok", Classification: "internal",
	})
	require.NoError(t, err)
}

func TestRemoteStorage_CountMachineIdentityCredentialsByClassification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/classification-counts", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"counts": map[string]int{"restricted": 2, "internal": 5},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	counts, err := rs.CountMachineIdentityCredentialsByClassification(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, counts["restricted"])
	assert.Equal(t, 5, counts["internal"])
}

func TestRemoteStorage_RevokeMachineIdentityCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/12/revoke", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RevokeMachineIdentityCredential(context.Background(), 12)
	require.NoError(t, err)
}

func TestRemoteStorage_TouchMachineIdentityCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/machine-credentials/18/touch", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.TouchMachineIdentityCredential(context.Background(), 18, now, 30*time.Second)
	require.NoError(t, err)
}

// --- Machine role grants ---

func TestRemoteStorage_AssignMachineRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/5/roles/3", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		assert.Equal(t, "20", r.URL.Query().Get("environment_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignMachineRole(context.Background(), 5, 3, corestorage.Scope{ProjectID: 10, EnvironmentID: 20})
	require.NoError(t, err)
}

func TestRemoteStorage_RemoveMachineRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/5/roles/3", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveMachineRole(context.Background(), 5, 3, corestorage.Scope{ProjectID: 10, EnvironmentID: 0})
	require.NoError(t, err)
}

func TestRemoteStorage_GetMachineRoleIDsAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/7/roles/ids", r.URL.Path)
		assert.Equal(t, "2", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"role_ids": []uint{1, 4, 9},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	ids, err := rs.GetMachineRoleIDsAt(context.Background(), 7, corestorage.Scope{ProjectID: 2, EnvironmentID: 0})
	require.NoError(t, err)
	assert.Equal(t, []uint{1, 4, 9}, ids)
}

func TestRemoteStorage_GetMachineRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/7/roles", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"roles": []map[string]interface{}{
				{"id": 1, "name": "viewer", "description": "Read-only"},
				{"id": 2, "name": "editor", "description": "Read-write"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	roles, err := rs.GetMachineRoles(context.Background(), 7)
	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.Equal(t, uint(1), roles[0].ID)
	assert.Equal(t, "viewer", roles[0].Name)
	assert.Equal(t, "editor", roles[1].Name)
}

// --- OIDC bindings ---

func TestRemoteStorage_CreateOIDCBinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/machine-oidc-bindings", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 1, "machine_identity_id": 5,
			"issuer":     "https://token.actions.githubusercontent.com",
			"subject":    "repo:org/repo:ref:refs/heads/main",
			"created_by": 1, "created_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	b, err := rs.CreateOIDCBinding(context.Background(), &models.MachineIdentityOIDCBinding{
		MachineIdentityID: 5,
		Issuer:            "https://token.actions.githubusercontent.com",
		Subject:           "repo:org/repo:ref:refs/heads/main",
		CreatedBy:         1,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(1), b.ID)
	assert.Equal(t, "https://token.actions.githubusercontent.com", b.Issuer)
}

func TestRemoteStorage_GetMachineByOIDCSubject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-oidc-bindings/by-subject", r.URL.Path)
		assert.Equal(t, "https://example.com", r.URL.Query().Get("issuer"))
		assert.Equal(t, "system:serviceaccount:default:ci", r.URL.Query().Get("subject"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 3, "name": "k8s-sa", "state": "active",
			"created_at": time.Now(), "updated_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	mi, err := rs.GetMachineByOIDCSubject(context.Background(),
		"https://example.com", "system:serviceaccount:default:ci")
	require.NoError(t, err)
	assert.Equal(t, uint(3), mi.ID)
	assert.Equal(t, "k8s-sa", mi.Name)
}

func TestRemoteStorage_ListOIDCBindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-identities/5/oidc-bindings", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"bindings": []map[string]interface{}{
				{
					"id": 10, "machine_identity_id": 5,
					"issuer": "https://issuer.example.com", "subject": "sa:default:ci",
					"created_by": 1, "created_at": time.Now(),
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListOIDCBindings(context.Background(), 5)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(10), list[0].ID)
	assert.Equal(t, "https://issuer.example.com", list[0].Issuer)
}

func TestRemoteStorage_GetOIDCBindingByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/machine-oidc-bindings/42", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 42, "machine_identity_id": 5,
			"issuer": "https://issuer.example.com", "subject": "sa:ns:name",
			"created_by": 1, "created_at": time.Now(),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	b, err := rs.GetOIDCBindingByID(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, uint(42), b.ID)
	assert.Equal(t, "sa:ns:name", b.Subject)
}

func TestRemoteStorage_DeleteOIDCBinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/system/machine-oidc-bindings/99", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteOIDCBinding(context.Background(), 99)
	require.NoError(t, err)
}
