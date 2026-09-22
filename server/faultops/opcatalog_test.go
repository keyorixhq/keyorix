// opcatalog_test.go is FuzzStorageFaultOperations' operation catalog: real
// dispatch functions driving the actual REST/system/gRPC transports (never
// calling a core.* or storage.* method directly), so a fault only visible to a
// caller that goes through the real handler — F3's replaceRolePermissions, the
// /system proxy Storage()-bypass class — is actually exercised.
//
// Every operation is split into Setup (runs on an UNFAULTED world) and Execute
// (runs on the SAME world after the harness Arms the fault) — the prefix/op
// split STEP 0 called for. Splitting matters for two reasons, both found by
// this harness's own seed corpus before this split existed: (1) NthCall must
// count only Execute's own calls, or a fault meant for the operation under test
// fires during unrelated setup instead; (2) the "error implies unchanged state"
// oracle is only valid relative to POST-setup state — comparing against the
// pristine pre-setup world flags every setup write as a false "state changed"
// violation regardless of whether Execute's own fault handling is correct.
//
// Every key here must exactly match a key in inventory_registry_generated_test.go
// (enforced by TestOperationCatalogKeysAreRegistered below) so StatusFuzzed in
// inventory_overrides_test.go can never silently drift from what the harness
// actually drives.
package faultops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// opResult is transport-agnostic: Success is the ONLY thing oracle (a)/(b) care
// about (2xx / codes.OK vs everything else), Detail is kept for readable tracing.
type opResult struct {
	Success bool
	Detail  string // "HTTP 200: ..." / "codes.OK" / "HTTP 500: <body>" etc.
}

type operation struct {
	// Key must match a "REST <METHOD> <path>" or "GRPC <service>.<method>" key
	// in inventory_registry_generated_test.go.
	Key string
	// Setup runs BEFORE the harness arms any fault — real calls (through the
	// real transport, same as Execute) that put the world in the state Execute
	// needs (e.g. a role to update, a secret to delete). Its return value is
	// passed to Execute untouched. nil Setup means "nothing to do."
	Setup func(ctx context.Context, w *faultWorld) (any, error)
	// Execute performs the ONE call under test, run AFTER the harness arms the
	// fault — this is the only phase whose storage calls count toward NthCall.
	Execute func(ctx context.Context, w *faultWorld, state any) (opResult, error)
}

func httpJSON(ctx context.Context, w *faultWorld, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.httpServer.URL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.adminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

func httpResult(st int, body []byte) opResult {
	return opResult{Success: st/100 == 2, Detail: fmt.Sprintf("HTTP %d: %s", st, body)}
}

// createRoleForFuzz sets up a role with exactly one permission the bootstrapped
// admin holds, returning its ID — setup for the UpdateRole/F3 and gRPC
// AssignRole operations.
func createRoleForFuzz(ctx context.Context, w *faultWorld) (uint, error) {
	status, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
		"name": "fuzz-role", "description": "fuzz role", "permissions": []string{"secrets.read"},
	})
	if err != nil {
		return 0, err
	}
	if status/100 != 2 {
		return 0, fmt.Errorf("setup CreateRole: HTTP %d: %s", status, body)
	}
	var decoded struct {
		Data struct {
			Role struct {
				ID uint `json:"id"`
			} `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return 0, fmt.Errorf("decoding CreateRole response: %w (body=%s)", err, body)
	}
	if decoded.Data.Role.ID == 0 {
		return 0, fmt.Errorf("CreateRole response carried no role id (body=%s)", body)
	}
	return decoded.Data.Role.ID, nil
}

// createMachineIdentityForFuzz creates a project + machine identity, returning
// (projectID, machineIdentityID).
func createMachineIdentityForFuzz(ctx context.Context, w *faultWorld) (uint, uint, error) {
	pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-mi-project"})
	if err != nil {
		return 0, 0, err
	}
	if pStatus/100 != 2 {
		return 0, 0, fmt.Errorf("setup CreateProject: HTTP %d: %s", pStatus, pBody)
	}
	// models.Project carries no json tags, so its fields serialize with Go's
	// default (capitalized) names — confirmed against a live response body
	// during opcatalog_smoke_test.go's TestOpCatalog_SucceedsWithNoFaultArmed,
	// not guessed.
	var proj struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(pBody, &proj); err != nil || proj.Data.ID == 0 {
		return 0, 0, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, pBody)
	}

	mStatus, mBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"project_id": proj.Data.ID, "name": "fuzz-machine", "created_by": 1,
	})
	if err != nil {
		return 0, 0, err
	}
	if mStatus/100 != 2 {
		return 0, 0, fmt.Errorf("setup CreateMachineIdentityProxy: HTTP %d: %s", mStatus, mBody)
	}
	var mi struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(mBody, &mi); err != nil || mi.Data.ID == 0 {
		return 0, 0, fmt.Errorf("decoding CreateMachineIdentityProxy response: %w (body=%s)", err, mBody)
	}
	return proj.Data.ID, mi.Data.ID, nil
}

// createSecretForFuzz creates a secret and returns its ID — setup for the
// UpdateSecret/DeleteSecret operations. Same "no json tags, Go default
// capitalized names" shape as Project (models.SecretNode).
func createSecretForFuzz(ctx context.Context, w *faultWorld) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
		"name": "fuzz-secret-setup", "value": "fuzz-value", "project_id": 1, "environment_id": 1, "type": "generic",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateSecret: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateSecret response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// createGroupForFuzz creates a group via the ordinary (non-/system) REST
// endpoint and returns its ID — setup for group-member operations.
func createGroupForFuzz(ctx context.Context, w *faultWorld, name string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/groups/", map[string]any{
		"name": name, "description": "fuzz group",
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateGroup: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateGroup response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// createUserForFuzz creates a user via the ordinary REST endpoint and returns
// its ID — setup for membership/role-assignment operations.
func createUserForFuzz(ctx context.Context, w *faultWorld, username string) (uint, error) {
	st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/users/", map[string]any{
		"username": username, "email": username + "@example.com",
		"password": "Xk7#Qm2$Lp9@Vn4!", "display_name": "Fuzz User " + username,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup CreateUser: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding CreateUser response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}

// machineIdentityWireForFuzz mirrors server/http/handlers/machine_identities_proxy.go's
// unexported machineIdentityProxyWire (fields it round-trips over the wire) —
// duplicated here rather than exported from the production handler package,
// consistent with this repo's fuzzworld_test.go convention of a harness owning
// its own fixture shapes instead of the production package growing a
// test-only export.
type machineIdentityWireForFuzz struct {
	ID             uint   `json:"id"`
	ProjectID      uint   `json:"project_id"`
	Name           string `json:"name"`
	IdentityType   string `json:"identity_type"`
	State          string `json:"state"`
	Description    string `json:"description"`
	CreatedBy      uint   `json:"created_by"`
	Classification string `json:"classification"`
}

// opCatalog is the closed set of operations FuzzStorageFaultOperations can pick
// from — see the STEP 0 report for the running Fuzzed/Pending/Excluded count
// across the full 309-operation inventory; this is intentionally a starting
// slice covering all three known bug classes plus ordinary CRUD across
// REST/system/gRPC, not the full surface (see TestReportOperationTableCoverage).
var opCatalog = []operation{
	{
		// F3: replaceRolePermissions (server/http/handlers/rbac.go) drops
		// GetRolePermissions/RemovePermissionFromRole errors and always replies
		// 200 — confirmed live on main, see the STEP 0 report.
		Key: "REST PUT /api/v1/roles/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			roleID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", roleID), map[string]any{
				"permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// /system proxy bypass class: TransitionMachineIdentityStateProxy calls
		// coreService.Storage() directly, never core.* — same bypass shape as F3.
		Key: "REST PUT /api/v1/system/machine-identities/{id}/transition",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			_, miID, err := createMachineIdentityForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			// The wire protocol expects the FULL row with State already mutated
			// client-side plus the FromState it was read at
			// (transitionMachineIdentityStateBody). CreateMachineIdentity leaves
			// a fresh row in MachineActive ("active"); MachineActive ->
			// MachineSuspended ("suspended") is the one legal non-terminal
			// transition (machineTransitions, internal/core/machine_identities.go).
			getStatus, getBody, err := httpJSON(ctx, w, http.MethodGet,
				fmt.Sprintf("/api/v1/system/machine-identities/%d", miID), nil)
			if err != nil {
				return nil, err
			}
			if getStatus/100 != 2 {
				return nil, fmt.Errorf("setup GetMachineIdentityProxy: HTTP %d: %s", getStatus, getBody)
			}
			var got struct {
				Data machineIdentityWireForFuzz `json:"data"`
			}
			if err := json.Unmarshal(getBody, &got); err != nil {
				return nil, fmt.Errorf("decoding GetMachineIdentityProxy response: %w (body=%s)", err, getBody)
			}
			fromState := got.Data.State
			got.Data.State = "suspended"
			return map[string]any{"miID": miID, "machine_identity": got.Data, "from_state": fromState}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]any)
			st, body, err := httpJSON(ctx, w, http.MethodPut,
				fmt.Sprintf("/api/v1/system/machine-identities/%d/transition", s["miID"]),
				map[string]any{"machine_identity": s["machine_identity"], "from_state": s["from_state"]})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/secrets/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
				"name": "fuzz-secret", "value": "fuzz-value", "project_id": 1, "environment_id": 1, "type": "generic",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST PUT /api/v1/secrets/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), map[string]any{
				"value": "fuzz-value-updated",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/secrets/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/projects",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-project"})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/users/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/users/", map[string]any{
				"username": "fuzz-user", "email": "fuzz-user@example.com",
				"password": "Xk7#Qm2$Lp9@Vn4!", "display_name": "Fuzz User",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Representative gRPC mutating call, over the REAL grpc.Server (bufconn)
		// including RecoveryInterceptor/AuthInterceptor — proves the harness
		// generalizes across transports, not just REST.
		Key: "GRPC keyorix.v1.RoleService.AssignRole",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			roleID := state.(uint)
			_, err := pb.NewRoleServiceClient(w.grpcConn).AssignRole(w.grpcCtx, &pb.AssignRoleRequest{
				UserId: 1, RoleId: uint32(roleID),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// /system proxy bypass class (batch 1): CreateMachineIdentityProxy
		// calls coreService.CreateMachineIdentity directly, never through a
		// REST-facing handler layer of its own.
		Key: "REST POST /api/v1/system/machine-identities",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-mi-batch1-project"})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", st, body)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, body)
			}
			return proj.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			projectID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
				"project_id": projectID, "name": "fuzz-mi-batch1", "created_by": 1,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// /system proxy bypass class (batch 1): CreateGroupProxy.
		Key: "REST POST /api/v1/system/groups",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/system/groups", map[string]any{
				"name": "fuzz-group-batch1", "description": "fuzz group",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// /system proxy bypass class (batch 1): DeleteGroupProxy.
		Key: "REST DELETE /api/v1/system/groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/system/groups", map[string]any{
				"name": "fuzz-group-batch1-setup", "description": "fuzz group",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateGroupProxy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateGroupProxy response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/system/groups/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// /system proxy bypass class (batch 1): DeleteProjectProxy.
		Key: "REST DELETE /api/v1/system/projects/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-project-delete-batch1"})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", st, body)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, body)
			}
			return proj.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/system/projects/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 2: ordinary (non-/system) REST CRUD, one per
		// major resource type not yet covered.
		Key: "REST POST /api/v1/groups/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/groups/", map[string]any{
				"name": "fuzz-group-batch2", "description": "fuzz group",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/groups/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/groups/", map[string]any{
				"name": "fuzz-group-batch2-setup", "description": "fuzz group",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateGroup: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateGroup response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST POST /api/v1/roles/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
				"name": "fuzz-role-batch2", "description": "fuzz role", "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/roles/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 3: gRPC group/role CRUD, over the real grpc.Server
		// (bufconn) with the production interceptor chain.
		Key: "GRPC keyorix.v1.GroupService.CreateGroup",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			_, err := pb.NewGroupServiceClient(w.grpcConn).CreateGroup(w.grpcCtx, &pb.CreateGroupRequest{
				Name: "fuzz-group-grpc-batch3", Description: "fuzz group",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		Key: "GRPC keyorix.v1.RoleService.DeleteRole",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createRoleForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			roleID := state.(uint)
			_, err := pb.NewRoleServiceClient(w.grpcConn).DeleteRole(w.grpcCtx, &pb.DeleteRoleRequest{
				Id: uint32(roleID),
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 4: group membership.
		Key: "REST POST /api/v1/groups/{id}/members",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-group-batch4")
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-user-batch4")
			if err != nil {
				return nil, err
			}
			return map[string]uint{"groupID": groupID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", s["groupID"]), map[string]any{
				"user_id": s["userID"],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/groups/{id}/members/{userId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			groupID, err := createGroupForFuzz(ctx, w, "fuzz-group-batch4b")
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-user-batch4b")
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", groupID), map[string]any{
				"user_id": userID,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup AddGroupMember: HTTP %d: %s", st, body)
			}
			return map[string]uint{"groupID": groupID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete,
				fmt.Sprintf("/api/v1/groups/%d/members/%d", s["groupID"], s["userID"]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 5: rotation policies.
		Key: "REST POST /api/v1/rotation-policies/",
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rotation-policies/", map[string]any{
				"name": "fuzz-rotation-policy-batch5", "scope": "project", "project_id": 1, "interval_days": 30,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		Key: "REST DELETE /api/v1/rotation-policies/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/rotation-policies/", map[string]any{
				"name": "fuzz-rotation-policy-batch5-setup", "scope": "project", "project_id": 1, "interval_days": 30,
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup CreateRotationPolicy: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateRotationPolicy response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/rotation-policies/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 6: RevokeBreakGlassActivationProxy — a multi-step
		// /system proxy (state guard + role removal + conditional revoke +
		// audit, see break_glass_proxy.go's own doc for why it is NOT a thin
		// passthrough) with no transaction spanning its steps. No REST
		// creation route exists any more (CreateBreakGlassActivationProxy was
		// deleted, G80 liveness sweep), so Setup seeds the activation and its
		// role grant directly through the unfaulted storage wrapper — the
		// same primitives a real downstream server's core.ActivateBreakGlass
		// would call.
		Key: "REST POST /api/v1/system/break-glass/{id}/revoke",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-bg-project"})
			if err != nil {
				return nil, err
			}
			if pStatus/100 != 2 {
				return nil, fmt.Errorf("setup CreateProject: HTTP %d: %s", pStatus, pBody)
			}
			var proj struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			if err := json.Unmarshal(pBody, &proj); err != nil || proj.Data.ID == 0 {
				return nil, fmt.Errorf("decoding CreateProject response: %w (body=%s)", err, pBody)
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-bg-user")
			if err != nil {
				return nil, err
			}
			roleID, err := createRoleForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := w.faulty.AssignRole(ctx, userID, roleID, coreStorage.Scope{ProjectID: proj.Data.ID}); err != nil {
				return nil, fmt.Errorf("setup AssignRole: %w", err)
			}
			activation, err := w.faulty.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
				ProjectID:     proj.Data.ID,
				UserID:        userID,
				RoleID:        roleID,
				RoleName:      "fuzz-role",
				Justification: "fuzz break-glass",
				State:         core.BreakGlassActive,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateBreakGlassActivation: %w", err)
			}
			return activation.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/system/break-glass/%d/revoke", id), map[string]any{
				"revoked_by": 1, "revoked_at": time.Now(),
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 6: CreateSecretDependencyExclusiveProxy — the ONE
		// deliberately non-passthrough method in secret_dependencies_proxy.go
		// (evaluates the duplicate/cycle invariant itself, since no real
		// transaction spans the HTTP hop back to the calling server); routed
		// through core.LockedCreateSecretDependencyExclusive, which holds the
		// same lock core.AddSecretDependency does around the identical call.
		Key: "REST POST /api/v1/system/secret-dependencies/exclusive",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			createSecret := func(name string) (uint, error) {
				st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secrets/", map[string]any{
					"name": name, "value": "fuzz-value", "project_id": 1, "environment_id": 1, "type": "generic",
				})
				if err != nil {
					return 0, err
				}
				if st/100 != 2 {
					return 0, fmt.Errorf("setup CreateSecret(%s): HTTP %d: %s", name, st, body)
				}
				var decoded struct {
					Data struct {
						ID uint `json:"ID"`
					} `json:"data"`
				}
				if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
					return 0, fmt.Errorf("decoding CreateSecret(%s) response: %w (body=%s)", name, err, body)
				}
				return decoded.Data.ID, nil
			}
			dependent, err := createSecret("fuzz-sd-dependent")
			if err != nil {
				return nil, err
			}
			dependsOn, err := createSecret("fuzz-sd-dependson")
			if err != nil {
				return nil, err
			}
			return map[string]uint{"dependent": dependent, "dependsOn": dependsOn}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/system/secret-dependencies/exclusive", map[string]any{
				"project_id": 1, "dependent_secret_id": s["dependent"], "depends_on_secret_id": s["dependsOn"],
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
}

// runOp runs op.Setup (if any) then op.Execute against w, with no fault
// arming of its own — used by the fault-free smoke test, and as the shape the
// fuzz harness's own two-phase (Setup unfaulted / Execute faulted) run mirrors.
func runOp(ctx context.Context, w *faultWorld, op operation) (opResult, error) {
	var state any
	if op.Setup != nil {
		var err error
		state, err = op.Setup(ctx, w)
		if err != nil {
			return opResult{}, fmt.Errorf("setup: %w", err)
		}
	}
	return op.Execute(ctx, w, state)
}

// TestOperationCatalogKeysAreRegistered fails if opCatalog references a key the
// live route/method inventory no longer has — a rename or removal upstream
// would otherwise leave a Setup/Execute pair silently dispatching to a dead route.
func TestOperationCatalogKeysAreRegistered(t *testing.T) {
	inCatalog := make(map[string]bool, len(opCatalog))
	for _, op := range opCatalog {
		inCatalog[op.Key] = true
		if !knownOperations[op.Key] {
			t.Errorf("opCatalog references %q, which is not in the live operation inventory (rename/removal upstream?)", op.Key)
		}
		if statusOf(op.Key).Status != StatusFuzzed {
			t.Errorf("opCatalog references %q, but inventory_overrides_test.go does not mark it StatusFuzzed", op.Key)
		}
	}
	// The reverse direction: a key marked StatusFuzzed with no matching
	// opCatalog entry would claim coverage the harness doesn't actually drive.
	for key, e := range operationOverrides {
		if e.Status == StatusFuzzed && !inCatalog[key] {
			t.Errorf("inventory_overrides_test.go marks %q StatusFuzzed, but opCatalog has no entry for it", key)
		}
	}
}
