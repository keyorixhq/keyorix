package faultops

import (
	"context"
	"fmt"
	"net/http"
)

// SCIM-TAILS-1 item 3: the SCIM Users ops and POST /scim/v2/Groups, the five SCIM write
// routes SESSION-AT AT5 left StatusPending (inventory_overrides_test.go). Appended in
// their own file, after zz_saml_acs_op_test.go: Go runs init()s in file-name order and
// fuzz seeds address ops by opCatalog INDEX, so appending keeps every committed seed on
// the op it was recorded against.
func init() {
	scimUserOp := func(key, setupName string, execute func(ctx context.Context, w *faultWorld, id uint) (int, []byte, error)) operation {
		return operation{
			Key: key,
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createSCIMUserForFuzz(ctx, w, setupName)
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				st, body, err := execute(ctx, w, state.(uint))
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		}
	}
	const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
	patchActive := func(active bool) map[string]any {
		return map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{
				{"op": "replace", "path": "active", "value": active},
			},
		}
	}
	opCatalog = append(opCatalog,
		operation{
			// scim.go's CreateUser -> core.ProvisionSCIMUser. Fixed names: oracle (a)
			// compares against an independently built reference world.
			Key: "REST POST /scim/v2/Users",
			Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
				st, body, err := scimJSON(ctx, w, http.MethodPost, "/scim/v2/Users", map[string]any{
					"schemas":    []string{userSchema},
					"userName":   "fuzz-scim-create-user@example.com",
					"externalId": "fuzz-scim-create-user",
				})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
		// PUT and PATCH deactivate: the revoking path (sessions, PATs), the one the
		// SCIM-NOTIFY-1 status tests (#3494) pin.
		scimUserOp("REST PUT /scim/v2/Users/{id}", "fuzz-scim-replace-user", func(ctx context.Context, w *faultWorld, id uint) (int, []byte, error) {
			return scimJSON(ctx, w, http.MethodPut, fmt.Sprintf("/scim/v2/Users/%d", id), map[string]any{
				"schemas":     []string{userSchema},
				"userName":    "fuzz-scim-replace-user@example.com",
				"displayName": "Fuzz SCIM Replaced",
				"active":      false,
			})
		}),
		scimUserOp("REST PATCH /scim/v2/Users/{id}", "fuzz-scim-patch-user", func(ctx context.Context, w *faultWorld, id uint) (int, []byte, error) {
			return scimJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/scim/v2/Users/%d", id), patchActive(false))
		}),
		scimUserOp("REST DELETE /scim/v2/Users/{id}", "fuzz-scim-delete-user", func(ctx context.Context, w *faultWorld, id uint) (int, []byte, error) {
			return scimJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/scim/v2/Users/%d", id), nil)
		}),
		operation{
			// scim_groups.go's CreateGroup -> core.ProvisionSCIMGroup with one member
			// (the member must be SCIM-managed, #167).
			Key: "REST POST /scim/v2/Groups",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createSCIMUserForFuzz(ctx, w, "fuzz-scim-create-group-member")
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				st, body, err := scimJSON(ctx, w, http.MethodPost, "/scim/v2/Groups", map[string]any{
					"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
					"displayName": "fuzz-scim-create-group",
					"members":     []map[string]any{{"value": fmt.Sprintf("%d", state.(uint))}},
				})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
	)
}
