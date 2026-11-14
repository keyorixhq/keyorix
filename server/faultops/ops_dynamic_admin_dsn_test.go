package faultops

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// Replace a stored admin_dsn in place (DYNAMIC-ADMIN-DSN-1, #4193): REST PATCH
// .../configs/{id}/admin-dsn and its gRPC sibling UpdateConfigAdminDSN.
//
// The change and its audit row commit in one transaction, so a fault at any write
// must leave either both or neither: the old DSN and no audit row, or the new DSN
// and its row. Setup is a fresh config with no lease, so the live-lease host pin
// (a 409 when the new DSN names another host) is not in play here; it is driven by
// internal/core TestDynamicSecrets_UpdateAdminDSN_* and the handler tests
// (server/http/dynamic_secret_admin_dsn_test.go, services/dynamic_admin_dsn_test.go).
//
// The new DSN is as unreachable as the one in createDynamicSecretConfigForFuzz
// (dynamicSecretFuzzAdminDSN): the route checks the egress policy and the refused
// driver options and never dials, so no engine is involved.
//
// Both keys are classified in inventory_overrides_test.go (the legacy table already
// held them as StatusPending), not through registerOverrides, which never overwrites
// an existing key.
const dynamicSecretFuzzReplacementDSN = "postgres://fake:fake-replacement@localhost/fakedb2"

func init() {
	registerOps("dynamic_admin_dsn",
		operation{
			Key: "REST PATCH /api/v1/dynamic-secrets/configs/{id}/admin-dsn",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-admin-dsn")
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				cfgID := state.(uint)
				st, body, err := httpJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/admin-dsn", cfgID), map[string]any{
					"admin_dsn": dynamicSecretFuzzReplacementDSN,
				})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
		operation{
			Key: "GRPC keyorix.v1.DynamicSecretService.UpdateConfigAdminDSN",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createDynamicSecretConfigForFuzz(ctx, w, "fuzz-dynsec-admin-dsn-grpc")
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				cfgID := state.(uint)
				_, err := pb.NewDynamicSecretServiceClient(w.grpcConn).UpdateConfigAdminDSN(w.grpcCtx, &pb.UpdateDynamicConfigAdminDSNRequest{
					Id: uint32(cfgID), AdminDsn: dynamicSecretFuzzReplacementDSN,
				})
				if err != nil {
					return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
				}
				return opResult{Success: true, Detail: codes.OK.String()}, nil
			},
		},
	)
}
