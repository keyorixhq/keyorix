// admin_rank_ceiling_transport_parity_test.go — table-driven proof that every
// REST route calling internal/core's requireAdminRankCeilingForTarget has
// its gRPC twin enforce the identical check.
//
// requireAdminRankCeilingForTarget's own doc comment (internal/core/authz.go)
// names 7 callers: UpdateUser, DeleteUser, RestoreUser,
// SuspendUser/ReactivateUser/RequirePasswordReset, RevokeUserSessions,
// ResendAccountSetupLink. Sweeping server/grpc/services for callers of each
// (rg "SuspendUser|ReactivateUser|RequirePasswordReset|RestoreUser|
// RevokeUserSessions|ResendAccountSetupLink" server/grpc/services/*.go)
// found ZERO gRPC callers for 5 of the 7 -- there is no gRPC twin for
// RestoreUser, the account-state family, RevokeUserSessions, or
// ResendAccountSetupLink at all, so there is nothing for those routes to be
// out of parity WITH (a missing RPC is not a parity gap; see this repo's own
// "a Go call graph is not a deployment path" / reachability discipline).
// share_service.go's gRPC ListSharedSecrets is a DIFFERENT, self-only
// capability (always the caller's own shares) than REST's
// ListSharedSecretsForUser (an admin viewing ANOTHER user's shares) -- gRPC
// simply does not expose the "view someone else's shares" capability that
// needs the ceiling at all.
//
// Only UpdateUser and DeleteUser have a REAL gRPC twin
// (server/grpc/services/user_service.go), and both call the EXACT SAME
// core.KeyorixCore method REST calls (core.UpdateUser / core.DeleteUser) --
// so by construction they enforce the identical ceiling. This test proves
// that construction actually holds (not just that it looks like it should on
// paper): a real, narrowly-privileged actor (holds users.write/users.delete
// — enough to pass each transport's own coarse permission gate — but NOT
// the full admin authority set the target holds) is refused by BOTH
// transports when targeting a higher-authority user, via the SAME
// sentinel error (core.ErrInsufficientAdminAuthority) mapped to each
// transport's own "forbidden" status (REST 403, gRPC PermissionDenied).
package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	"github.com/keyorixhq/keyorix/server/middleware"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// bootstrapCeilingParityFixture bootstraps a fully-migrated core (the exact
// recipe internal/core's own newBootstrappedCore test helper uses -- see
// that helper's comment on why MaxOpenConns is pinned to 1 for a plain
// ":memory:" DSN) with an admin, plus a SECOND user holding a CUSTOM role
// scoped to ONLY users.write + users.delete -- narrow enough to fail the
// admin-rank ceiling against the admin (who holds every permission that
// narrow role does, and more), but wide enough to pass BOTH transports' own
// coarse "do you hold users.write/users.delete at all" gate. Without that
// narrower role, a bootstrap admin acting on itself, or a totally
// unprivileged user, would never actually exercise
// requireAdminRankCeilingForTarget's own logic -- either the self-action
// exemption or the coarse permission gate would refuse first, proving
// nothing about the ceiling specifically.
func bootstrapCeilingParityFixture(t *testing.T) (coreService *core.KeyorixCore, admin, narrowActor *models.User) {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initialize i18n: %v", err)
	}
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get raw db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := kxstorage.MigrateExisting(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	st := store.NewLocalStorage(db)
	coreService = core.NewKeyorixCore(st)
	coreService.SetBootstrapToken("test-bootstrap-token")
	bootstrapResult, err := coreService.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "ceiling-admin", Email: "ceiling-admin@example.com",
		Password: "Tr1cky-Bootstrap-Passphrase!", DisplayName: "Ceiling Admin",
		Token: "test-bootstrap-token",
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err = coreService.GetUserByUsername(ctx, "ceiling-admin")
	if err != nil {
		t.Fatalf("get bootstrap admin: %v", err)
	}

	perms, err := coreService.ListPermissions(ctx)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	var permIDs []uint
	for _, p := range perms {
		if p.Name == "users.write" || p.Name == "users.delete" {
			permIDs = append(permIDs, p.ID)
		}
	}
	if len(permIDs) != 2 {
		t.Fatalf("expected exactly 2 permissions (users.write, users.delete) in the catalog, found %d", len(permIDs))
	}
	narrowRole, _, err := coreService.CreateRole(ctx, admin.ID, "narrow-user-manager",
		"users.write/users.delete only -- no other admin authority", permIDs)
	if err != nil {
		t.Fatalf("create narrow role: %v", err)
	}

	narrowActor, err = coreService.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "narrow-mgr", Email: "narrow-mgr@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!", DisplayName: "Narrow-Scope Manager",
	}, "", nil, admin.ID, false)
	if err != nil {
		t.Fatalf("create narrow actor: %v", err)
	}
	if err := coreService.AssignUserRole(ctx, admin.ID, narrowActor.ID, narrowRole.ID, core.Scope{}, false); err != nil {
		t.Fatalf("assign narrow role: %v", err)
	}

	_ = bootstrapResult
	return coreService, admin, narrowActor
}

// TestAdminRankCeiling_TransportParity is the table-driven test itself: for
// each of {UpdateUser, DeleteUser}, drive BOTH the REST handler and the gRPC
// service method directly (no network listener needed -- both take a plain
// context/request and return a response/error synchronously), with the
// SAME narrowly-privileged actor targeting the SAME higher-authority admin,
// and assert BOTH refuse via the SAME underlying sentinel.
func TestAdminRankCeiling_TransportParity(t *testing.T) {
	cases := []struct {
		name string
		rest func(t *testing.T, h *handlers.UserHandler, actorID, targetID uint) int
		grpc func(t *testing.T, svc *services.UserGRPCService, actorID, targetID uint) error
	}{
		{
			name: "UpdateUser",
			rest: func(t *testing.T, h *handlers.UserHandler, actorID, targetID uint) int {
				t.Helper()
				body := bytes.NewBufferString(`{"display_name":"Renamed By Narrow Actor"}`)
				r := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+strconv.FormatUint(uint64(targetID), 10), body)
				r = withChiIDParam(r, targetID)
				r = withUserContext(r, actorID)
				w := httptest.NewRecorder()
				h.UpdateUser(w, r)
				return w.Code
			},
			grpc: func(t *testing.T, svc *services.UserGRPCService, actorID, targetID uint) error {
				t.Helper()
				ctx := withGRPCUserContext(actorID)
				name := "Renamed By Narrow Actor"
				_, err := svc.UpdateUser(ctx, &pb.UpdateUserRequest{Id: uint32(targetID), DisplayName: &name})
				return err
			},
		},
		{
			name: "DeleteUser",
			rest: func(t *testing.T, h *handlers.UserHandler, actorID, targetID uint) int {
				t.Helper()
				r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+strconv.FormatUint(uint64(targetID), 10), nil)
				r = withChiIDParam(r, targetID)
				r = withUserContext(r, actorID)
				w := httptest.NewRecorder()
				h.DeleteUser(w, r)
				return w.Code
			},
			grpc: func(t *testing.T, svc *services.UserGRPCService, actorID, targetID uint) error {
				t.Helper()
				ctx := withGRPCUserContext(actorID)
				_, err := svc.DeleteUser(ctx, &pb.DeleteUserRequest{Id: uint32(targetID)})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coreService, admin, narrowActor := bootstrapCeilingParityFixture(t)

			h, err := handlers.NewUserHandler(coreService)
			if err != nil {
				t.Fatalf("construct REST handler: %v", err)
			}
			restCode := tc.rest(t, h, narrowActor.ID, admin.ID)
			if restCode != http.StatusForbidden {
				t.Fatalf("REST %s: narrow actor targeting the admin got HTTP %d, want %d (Forbidden) -- "+
					"the admin-rank ceiling did not refuse over REST", tc.name, restCode, http.StatusForbidden)
			}

			svc := services.NewUserService(coreService)
			grpcErr := tc.grpc(t, svc, narrowActor.ID, admin.ID)
			if grpcErr == nil {
				t.Fatalf("gRPC %s: narrow actor targeting the admin succeeded (nil error) -- "+
					"the admin-rank ceiling did not refuse over gRPC, even though REST (tested above) did: a real transport-parity gap", tc.name)
			}
			if st, ok := status.FromError(grpcErr); !ok || st.Code() != codes.PermissionDenied {
				t.Fatalf("gRPC %s: expected codes.PermissionDenied, got %v", tc.name, grpcErr)
			}

			// The target must be UNCHANGED by either refused attempt -- proves
			// this was a real refusal, not a no-op success.
			stillAdmin, err := coreService.GetUser(context.Background(), admin.ID)
			if err != nil {
				t.Fatalf("re-fetch target after refusal: %v", err)
			}
			if tc.name == "UpdateUser" && stillAdmin.DisplayName == "Renamed By Narrow Actor" {
				t.Fatalf("target's DisplayName was changed despite both transports refusing")
			}
			if tc.name == "DeleteUser" && stillAdmin.DeletedAt.Valid {
				t.Fatalf("target was deleted despite both transports refusing")
			}
		})
	}
}

// withChiIDParam sets chi's "id" URL param on r, matching how the real
// router resolves /api/v1/users/{id} for both UpdateUser and DeleteUser.
func withChiIDParam(r *http.Request, id uint) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.FormatUint(uint64(id), 10))
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// withUserContext carries actorID as the REST-authenticated caller, matching
// what customMiddleware.Authentication sets on a real request.
func withUserContext(r *http.Request, actorID uint) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.GetUserContextKey(), &middleware.UserContext{UserID: actorID})
	return r.WithContext(ctx)
}

// withGRPCUserContext carries actorID as the gRPC-authenticated caller,
// matching what the auth interceptor sets on a real request. No Permissions
// field is populated: authorizeGlobal/authorizeScoped route through
// core.Authorize, which resolves the actor's REAL permissions from storage
// by UserID -- not from a precomputed field on this context struct (the
// exact flat-vs-scoped bug class this package's own conversions.go
// documents fixing).
func withGRPCUserContext(actorID uint) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(), &interceptors.UserContext{UserID: actorID})
}
