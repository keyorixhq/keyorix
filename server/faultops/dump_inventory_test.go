// dump_inventory_test.go builds the LIVE set of every mutating REST route,
// /system proxy route, and gRPC method reachable in this server, by walking the
// actual constructed chi router and the actual generated gRPC ServiceDescs —
// never by hand-transcription — so the count can't silently drift from what the
// server actually serves. inventory_ratchet_test.go compares this live set
// against the checked-in registry (inventory_registry_generated_test.go).
package faultops

import (
	"net/http"
	"sort"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	httpserver "github.com/keyorixhq/keyorix/server/http"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// faultopsSCIMToken is a fixed, >=20-char (core/rules.MinSCIMTokenLength)
// bearer token enabling the /scim/v2 route group for BOTH liveOperationKeys
// below and newFaultWorld (world_test.go) -- the same constant in both places
// so a route liveOperationKeys discovers is the SAME route opCatalog's SCIM
// entries (opcatalog_test.go) can actually reach and authenticate against.
// Before this, cfg.SCIM.Enabled was never set anywhere in this package, so
// every /scim/v2 route -- read AND write -- was invisible to BOTH the
// generated registry and the fault-injection catalog, not because anyone
// excluded it, but because it was never mounted in the router these helpers
// construct. Not a secret -- this process never persists data beyond its own
// run and this token authenticates nothing but requests this same process
// sends to its own in-memory httptest.Server.
const faultopsSCIMToken = "faultops-scim-test-token-not-a-secret"

// allGRPCServiceDescs is the hand-maintained list of every generated gRPC
// ServiceDesc — gRPC has no runtime registry to walk without spinning up a real
// *grpc.Server, so the SERVICE list here is hand-maintained (13 as of writing,
// server/proto/pb/keyorix_grpc.pb.go), while the METHOD list within each is
// walked via reflection over .Methods/.Streams, so a new RPC added to an
// EXISTING service is caught automatically; only a whole new service needs a
// line added here (and would also break every *GRPCService constructor call
// site elsewhere, so it won't go unnoticed).
var allGRPCServiceDescs = []grpc.ServiceDesc{
	pb.SecretService_ServiceDesc,
	pb.ShareService_ServiceDesc,
	pb.UserService_ServiceDesc,
	pb.RoleService_ServiceDesc,
	pb.AuditService_ServiceDesc,
	pb.SystemService_ServiceDesc,
	pb.BreakGlassService_ServiceDesc,
	pb.GroupService_ServiceDesc,
	pb.ProjectService_ServiceDesc,
	pb.MachineIdentityService_ServiceDesc,
	pb.DynamicSecretService_ServiceDesc,
	pb.ComplianceService_ServiceDesc,
	pb.ConnectService_ServiceDesc,
}

// readShapedGRPCPrefixes are the method-name prefixes this API uses for
// non-mutating RPCs, derived by enumerating the full live 86-method set once
// (2026-09-21) and checking every single one against its internal/core
// implementation, not guessed: Get*/List*/Stream* cover the bulk of read
// methods. ReadSecret (ConnectService) and VerifyAuditChain (AuditService,
// confirmed by reading internal/core/audit_retention.go:
// KeyorixCore.VerifyAuditChain does a storage read and returns a verification
// result, no write) are the two exceptions caught this way — an earlier prefix
// list without VerifyAuditChain wrongly classified it as mutating, exactly the
// "enumeration only as complete as the idioms it knows about" failure mode
// (CLAUDE.md) this comment exists to prevent recurring. Every method NOT
// matching one of these is treated as mutating — see TestDumpAllGRPCMethods's
// captured output for the full classification this was checked against.
var readShapedGRPCPrefixes = []string{"Get", "List", "Stream", "HealthCheck"}
var readShapedGRPCExact = map[string]bool{"ReadSecret": true, "VerifyAuditChain": true}

func isMutatingGRPCMethod(name string) bool {
	if readShapedGRPCExact[name] {
		return false
	}
	for _, p := range readShapedGRPCPrefixes {
		if len(name) >= len(p) && name[:len(p)] == p {
			return false
		}
	}
	return true
}

var mutatingHTTPMethods = map[string]bool{
	http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// stateChangingGETRoutes are GET routes that change server state, named
// explicitly because mutatingHTTPMethods classifies by verb and so can never
// see them (#2910). Every one is a browser redirect hop in an SSO login flow,
// where the protocol fixes the verb as GET:
//   - /auth/sso/{provider}/login and /auth/saml/{provider}/login write an
//     SSOLoginState row (BeginSSO / BeginSAML);
//   - /auth/sso/{provider}/callback consumes that row, can JIT-provision an
//     account, reconciles group memberships and role grants, and mints a
//     session (CompleteSSO). It is the OIDC twin of the POST SAML ACS, which
//     was always in the inventory.
//
// HOW THIS LIST WAS ESTABLISHED, and what it does NOT cover: it comes from
// reading the unauthenticated auth block of server/http/router.go, the only
// place a protocol forces a state-changing GET. It is NOT a sweep of every GET
// handler in the router for writes. A GET that writes anywhere else stays
// invisible here until someone adds it, which is the "enumeration only as
// complete as the idioms it knows about" gap (CLAUDE.md), stated rather than
// hidden. GET /auth/setup/{token} was checked and is read-only (it inspects
// the token; POST /auth/setup/consume consumes it).
var stateChangingGETRoutes = map[string]bool{
	"/auth/sso/{provider}/login":    true,
	"/auth/sso/{provider}/callback": true,
	"/auth/saml/{provider}/login":   true,
}

// liveOperationKeys walks the real constructed router and the real gRPC service
// descriptors and returns every mutating operation's registry key, sorted. REST
// keys are "REST <METHOD> <path>"; gRPC keys are "GRPC <service>.<method>".
func liveOperationKeys(t *testing.T) []string {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}
	testCore := core.NewKeyorixCore(store.NewLocalStorage(db))
	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}},
		SCIM:   config.SCIMConfig{Enabled: true, Token: faultopsSCIMToken},
	}
	handler, err := httpserver.NewRouter(cfg, testCore)
	if err != nil {
		t.Fatal(err)
	}
	routes, ok := handler.(chi.Routes)
	if !ok {
		t.Fatal("router does not expose chi.Routes")
	}

	var keys []string
	err = chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if mutatingHTTPMethods[method] || (method == http.MethodGet && stateChangingGETRoutes[route]) {
			keys = append(keys, "REST "+method+" "+route)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, svc := range allGRPCServiceDescs {
		for _, m := range svc.Methods {
			if isMutatingGRPCMethod(m.MethodName) {
				keys = append(keys, "GRPC "+svc.ServiceName+"."+m.MethodName)
			}
		}
		for _, s := range svc.Streams {
			if isMutatingGRPCMethod(s.StreamName) {
				keys = append(keys, "GRPC "+svc.ServiceName+"."+s.StreamName+" [stream]")
			}
		}
	}

	sort.Strings(keys)
	return keys
}

// TestDumpAllGRPCMethods prints every gRPC method (mutating and read alike) —
// kept as a standing tool for re-deriving readShapedGRPCPrefixes/Exact by hand
// if the API's naming convention ever changes, not part of the ratchet itself.
func TestDumpAllGRPCMethods(t *testing.T) {
	var out []string
	for _, svc := range allGRPCServiceDescs {
		for _, m := range svc.Methods {
			mark := "read"
			if isMutatingGRPCMethod(m.MethodName) {
				mark = "MUTATING"
			}
			out = append(out, svc.ServiceName+"."+m.MethodName+" ["+mark+"]")
		}
	}
	sort.Strings(out)
	t.Logf("TOTAL_GRPC_METHODS=%d", len(out))
	for _, l := range out {
		t.Logf("GRPCMETHOD: %s", l)
	}
}
