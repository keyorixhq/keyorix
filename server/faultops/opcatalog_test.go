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
	defer func() { _ = resp.Body.Close() }()
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

// addProjectMemberForFuzz adds userID to projectID as a "viewer" (seeded by
// every BootstrapSystem call, see defaultRoles in internal/core/auth_bootstrap.go)
// — setup for operations whose core function requires the target/recipient to
// be a live project member (secret ACL grant, secret share) before it will
// act, distinct from the admin-bypasses-everything path createSecretForFuzz's
// other callers rely on.
func addProjectMemberForFuzz(ctx context.Context, w *faultWorld, projectID, userID uint) error {
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/members", projectID), map[string]any{
		"user_id": userID, "role": "viewer",
	})
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("setup AddProjectMember: HTTP %d: %s", st, body)
	}
	return nil
}

// addAdminAsProjectMemberForFuzz adds the world's own bootstrap admin
// ("faultadmin") to projectID as a project member — setup for operations
// whose core function checks the ACTOR's own live project membership, not
// just an owner/permission flag (ShareSecret's requireLiveOwnerAuthority:
// the admin globally holds the admin role via a Scope{} grant, which is NOT
// the same thing as an explicit project_members row, and the owner-share
// gate requires the latter).
func addAdminAsProjectMemberForFuzz(ctx context.Context, w *faultWorld, projectID uint) error {
	admin, err := w.faulty.GetUserByUsername(ctx, "faultadmin")
	if err != nil {
		return fmt.Errorf("setup GetUserByUsername(faultadmin): %w", err)
	}
	return addProjectMemberForFuzz(ctx, w, projectID, admin.ID)
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
		// Coverage batch 7 (2026-09-24, fuzz/new-surfaces): RevokeBreakGlass —
		// the ORDINARY, roles.assign-gated self-service revoke path
		// (server/http/handlers/break_glass.go), sibling to
		// RevokeBreakGlassActivationProxy above but reached through
		// core.RevokeBreakGlass directly (no /system proxy hop, no
		// guard+role-removal+conditional-revoke sequence of its own — that
		// logic lives once, in core.RevokeBreakGlass/
		// RevokeBreakGlassActivationAtomic, shared by both callers). Exercises
		// PR #2018's break-glass revoke role-removal + state-update atomicity
		// fix from this OTHER caller path into the same core function. Setup
		// seeds the activation directly through the unfaulted storage wrapper
		// (same shortcut the /system entry above uses), since going through
		// the real self-service ActivateBreakGlass REST route would also
		// require configuring c.breakGlassPolicy's emergency role in this
		// world, which no other opCatalog entry needs.
		Key: "REST POST /api/v1/projects/{id}/break-glass/{activationId}/revoke",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			pStatus, pBody, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/projects", map[string]any{"name": "fuzz-bg2-project"})
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
			userID, err := createUserForFuzz(ctx, w, "fuzz-bg2-user")
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
				Justification: "fuzz break-glass ordinary path",
				State:         core.BreakGlassActive,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateBreakGlassActivation: %w", err)
			}
			return map[string]uint{"projectID": proj.Data.ID, "activationID": activation.ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost,
				fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/revoke", s["projectID"], s["activationID"]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 8 (2026-09-24, fuzz/new-surfaces): CreateSecretAccessRequest
		// — self-service creation of a secret-scoped access request
		// (internal/core/classification_gate.go's RequestSecretAccess, introduced
		// by #2032), previously entirely absent from this catalog.
		Key: "REST POST /api/v1/secret-access-requests",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			return secretID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			secretID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/secret-access-requests", map[string]any{
				"secret_id": secretID, "reason": "fuzz access request",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 8: WithdrawSecretAccessRequest — self-service withdraw of
		// the caller's own pending secret-scoped request (invitations.go's generic
		// WithdrawAccessRequest, unchanged for this SecretID-scoped shape). State
		// is seeded directly through the unfaulted storage wrapper (same shortcut
		// break-glass batch 7 uses) as the world's own bootstrap admin
		// ("faultadmin"), since Execute authenticates as that same admin token and
		// withdraw requires requester == caller.
		Key: "REST POST /api/v1/secret-access-requests/{requestId}/withdraw",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			admin, err := w.faulty.GetUserByUsername(ctx, "faultadmin")
			if err != nil {
				return nil, fmt.Errorf("setup GetUserByUsername(faultadmin): %w", err)
			}
			expires := time.Now().Add(24 * time.Hour)
			created, err := w.faulty.CreateAccessRequest(ctx, &models.AccessRequest{
				ProjectID: 1, UserID: admin.ID, SecretID: &secretID,
				State: core.AccessRequestPending, Reason: "fuzz withdraw setup", ExpiresAt: &expires,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateAccessRequest: %w", err)
			}
			return created.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			reqID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secret-access-requests/%d/withdraw", reqID), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 8: ResolveSecretAccessRequest (approve) — the
		// requester-cannot-approve-their-own, admin-authority-ceiling-gated state
		// transition (ApproveSecretAccessRequest), the most state-machine-shaped
		// operation in this family. Requester is a freshly created ordinary user
		// (never the world's own admin), so the real Execute call — as the
		// bootstrap admin, who never made the request — exercises the actual
		// authority/self-approval guards rather than short-circuiting them.
		Key: "REST PUT /api/v1/secret-access-requests/{requestId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			requesterID, err := createUserForFuzz(ctx, w, "fuzz-sar-requester")
			if err != nil {
				return nil, err
			}
			expires := time.Now().Add(24 * time.Hour)
			created, err := w.faulty.CreateAccessRequest(ctx, &models.AccessRequest{
				ProjectID: 1, UserID: requesterID, SecretID: &secretID,
				State: core.AccessRequestPending, Reason: "fuzz approve setup", ExpiresAt: &expires,
			})
			if err != nil {
				return nil, fmt.Errorf("setup CreateAccessRequest: %w", err)
			}
			return created.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			reqID := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/secret-access-requests/%d", reqID), map[string]any{
				"action": "approve",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9 (FAULTOPS-SPEED STEP 2, secret ACL/share/rotation
		// family — highest security value per the STEP 1 plan): secret ACL
		// grant (RBAC Phase 3, secrets.manage-gated).
		Key: "REST POST /api/v1/secrets/{id}/acl",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", s["secretID"]), map[string]any{
				"user_id": s["userID"], "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: secret ACL revoke. Setup grants the ACL first
		// (through the real POST), then reads it back via ListSecretACLs
		// (the grant response itself carries no ACL id — {"granted":true} —
		// so the id must come from a follow-up list call).
		Key: "REST DELETE /api/v1/secrets/{id}/acl/{aclId}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-revoke-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", secretID), map[string]any{
				"user_id": userID, "permissions": []string{"secrets.read"},
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup GrantSecretACL: HTTP %d: %s", st, body)
			}
			gst, gbody, err := httpJSON(ctx, w, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", secretID), nil)
			if err != nil {
				return nil, err
			}
			if gst/100 != 2 {
				return nil, fmt.Errorf("setup ListSecretACLs: HTTP %d: %s", gst, gbody)
			}
			var decoded struct {
				Data []struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(gbody, &decoded); err != nil || len(decoded.Data) == 0 {
				return nil, fmt.Errorf("decoding ListSecretACLs response: %w (body=%s)", err, gbody)
			}
			return map[string]uint{"secretID": secretID, "aclID": decoded.Data[0].ID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/%d", s["secretID"], s["aclID"]), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of secret ACL grant — proves the RBAC
		// Phase 3 ACL family generalizes across transports too.
		Key: "GRPC keyorix.v1.SecretService.GrantSecretACL",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-grpc-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewSecretServiceClient(w.grpcConn).GrantSecretACL(w.grpcCtx, &pb.GrantSecretACLRequest{
				SecretId: uint64(s["secretID"]), UserId: uint64(s["userID"]), Permissions: []string{"secrets.read"},
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of secret ACL revoke. Setup grants
		// via the gRPC path itself (GrantSecretACLRequest's response DOES
		// carry the new entry's id, unlike the REST grant response).
		Key: "GRPC keyorix.v1.SecretService.RevokeSecretACL",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-acl-grpc-revoke-user")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			entry, err := pb.NewSecretServiceClient(w.grpcConn).GrantSecretACL(w.grpcCtx, &pb.GrantSecretACLRequest{
				SecretId: uint64(secretID), UserId: uint64(userID), Permissions: []string{"secrets.read"},
			})
			if err != nil {
				return nil, fmt.Errorf("setup GrantSecretACL (grpc): %w", err)
			}
			return map[string]uint64{"secretID": uint64(secretID), "aclID": entry.GetId()}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint64)
			_, err := pb.NewSecretServiceClient(w.grpcConn).RevokeSecretACL(w.grpcCtx, &pb.RevokeSecretACLRequest{
				SecretId: s["secretID"], AclId: s["aclID"],
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: auto-rotate toggle — enables Keyorix-managed
		// rotation (backend="" = regenerate in Keyorix only, ADR-047), no
		// external rotation backend config needed.
		Key: "REST PATCH /api/v1/secrets/{id}/auto-rotate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/secrets/%d/auto-rotate", id), map[string]any{
				"enabled": true,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of auto-rotate toggle.
		Key: "GRPC keyorix.v1.SecretService.SetSecretAutoRotate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			_, err := pb.NewSecretServiceClient(w.grpcConn).SetSecretAutoRotate(w.grpcCtx, &pb.SetSecretAutoRotateRequest{
				Id: uint32(id), Enabled: true,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: secret rotate-on-demand — RotateSecretOnDemand
		// (#193), which also rotates any bound upstream credential.
		Key: "REST POST /api/v1/secrets/{id}/rotate",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return createSecretForFuzz(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), map[string]any{
				"new_value": "fuzz-rotated-value",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: secret rollback. Setup rotates once first (a
		// fresh secret's only version IS its current one — RollbackSecret
		// rejects "already the current version" — so a second version must
		// exist before Execute can roll back to version 1).
		Key: "REST POST /api/v1/secrets/{id}/rollback",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			id, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rotate", id), map[string]any{
				"new_value": "fuzz-rollback-setup-rotated",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup RotateSecret: HTTP %d: %s", st, body)
			}
			return id, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/rollback", id), map[string]any{
				"version": 1,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: share a secret with another project member. The
		// admin (bootstrap creator) is the secret's owner, so ShareSecret's
		// owner gate passes; the recipient must independently be a live
		// project member (a distinct check from the owner gate).
		Key: "REST POST /api/v1/secrets/{id}/share",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", s["secretID"]), map[string]any{
				"recipient_id": s["userID"], "permission": "read",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: update an existing share's permission/expiry.
		// Setup creates the share first through the real POST, then decodes
		// its id from the response (shareRecordWire.ID, "id").
		Key: "REST PUT /api/v1/shares/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-update-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID), map[string]any{
				"recipient_id": userID, "permission": "read",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup ShareSecret: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding ShareSecret response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/shares/%d", id), map[string]any{
				"permission": "write",
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: revoke a share. Same setup shape as the update
		// path above, distinct share so the two operations never race a
		// shared row within one iteration.
		Key: "REST DELETE /api/v1/shares/{id}",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-revoke-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID), map[string]any{
				"recipient_id": userID, "permission": "read",
			})
			if err != nil {
				return nil, err
			}
			if st/100 != 2 {
				return nil, fmt.Errorf("setup ShareSecret: HTTP %d: %s", st, body)
			}
			var decoded struct {
				Data struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
				return nil, fmt.Errorf("decoding ShareSecret response: %w (body=%s)", err, body)
			}
			return decoded.Data.ID, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			id := state.(uint)
			st, body, err := httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", id), nil)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of secret share. ShareSecretRequest's
		// response (ShareRecord) carries its own id directly, unlike the ACL
		// grant's REST response.
		Key: "GRPC keyorix.v1.ShareService.ShareSecret",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-grpc-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			return map[string]uint{"secretID": secretID, "userID": userID}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			s := state.(map[string]uint)
			_, err := pb.NewShareServiceClient(w.grpcConn).ShareSecret(w.grpcCtx, &pb.ShareSecretRequest{
				SecretId: uint32(s["secretID"]), RecipientId: uint32(s["userID"]), Permission: "read",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of share update. Setup shares via
		// the gRPC path itself so the returned ShareRecord.Id is used
		// directly (no REST decode needed).
		Key: "GRPC keyorix.v1.ShareService.UpdateSharePermission",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-grpc-update-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			rec, err := pb.NewShareServiceClient(w.grpcConn).ShareSecret(w.grpcCtx, &pb.ShareSecretRequest{
				SecretId: uint32(secretID), RecipientId: uint32(userID), Permission: "read",
			})
			if err != nil {
				return nil, fmt.Errorf("setup ShareSecret (grpc): %w", err)
			}
			return rec.GetId(), nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			shareID := state.(uint32)
			_, err := pb.NewShareServiceClient(w.grpcConn).UpdateSharePermission(w.grpcCtx, &pb.UpdateSharePermissionRequest{
				ShareId: shareID, Permission: "write",
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	},
	{
		// Coverage batch 9: gRPC sibling of share revoke.
		Key: "GRPC keyorix.v1.ShareService.RevokeShare",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			secretID, err := createSecretForFuzz(ctx, w)
			if err != nil {
				return nil, err
			}
			if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
				return nil, err
			}
			userID, err := createUserForFuzz(ctx, w, "fuzz-share-grpc-revoke-recipient")
			if err != nil {
				return nil, err
			}
			if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
				return nil, err
			}
			rec, err := pb.NewShareServiceClient(w.grpcConn).ShareSecret(w.grpcCtx, &pb.ShareSecretRequest{
				SecretId: uint32(secretID), RecipientId: uint32(userID), Permission: "read",
			})
			if err != nil {
				return nil, fmt.Errorf("setup ShareSecret (grpc): %w", err)
			}
			return rec.GetId(), nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			shareID := state.(uint32)
			_, err := pb.NewShareServiceClient(w.grpcConn).RevokeShare(w.grpcCtx, &pb.RevokeShareRequest{
				ShareId: shareID,
			})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
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
