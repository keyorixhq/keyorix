package http

// multitenant_isolation_grpc_fuzz_test.go — FuzzMultiTenantIsolationGRPC.
//
// Extends multitenant_isolation_fuzz_test.go's two-tenant isolation harness across
// BOTH transports keyorix serves: REST (server/http, NewRouter) and gRPC
// (server/grpc, NewServer). SAME generated world (buildAPIFuzzWorlds — same core,
// same alice/bob principals + FIXED grants, same two secrets sa/sb) driven through a
// SECOND, gRPC-specific in-process server wired onto the IDENTICAL *core.KeyorixCore
// the REST router already uses — not a separate world, not a parallel setup. A
// grant/revoke or secret mutation is visible to both surfaces instantly because they
// share one core.
//
// Oracle:
//   - (a) SAME AS REST (multitenant_isolation_fuzz_test.go): no cross-tenant read, no
//     cross-tenant item in a list, no cross-tenant write succeeding — reapplied here
//     against gRPC responses (GetSecretValue, GetSecret, ListSecrets).
//   - (b) NEW — REST-vs-gRPC PARITY: for the identical generated world + identical
//     logical operation (read a secret's VALUE, identified by the SAME underlying
//     secret, addressed the way each transport supports — REST by ref, gRPC by id),
//     the ALLOW/DENY decision REST returns must equal what gRPC returns for the SAME
//     actor + SAME target secret. A divergence means one transport is more permissive
//     than the other for the exact same tenant boundary — a transport-dependent
//     isolation bypass. When both allow, the returned plaintext must match too
//     (VALUE PARITY).
//
// Honest scope note — NOT every REST op here has a decision-parity gRPC twin:
//   - VALUE READ has full decision + value parity (case 0 below).
//   - BY-ID METADATA read (gRPC GetSecret) only has an (a)-oracle + its own
//     existence-oracle differential (ADR-096 403-for-both, gRPC's
//     authorizeScopedTarget) — REST's by-id metadata route is already covered by
//     multitenant_isolation_fuzz_test.go itself, so it is not repeated here.
//   - LIST is NOT decision-parity-checked: REST's scoped list (?project_id=) is
//     deny-by-empty-result (200, filtered rows) for an out-of-scope project, while
//     gRPC's ListSecrets authorizes the REQUESTED scope up front and returns
//     PermissionDenied for the identical input (secret_service.go ListSecrets calls
//     AuthorizePrincipal(listScope) before ListSecretsWithSharingInfo) — a real,
//     pre-existing status-code asymmetry between the two surfaces, not a
//     confidentiality gap (neither ever returns a cross-tenant row). LIST keeps its
//     own (a)-only oracle here: no cross-tenant secret name ever appears in a
//     same-tenant-scoped gRPC list.
//   - BY-NAME metadata lookup has no gRPC RPC at all (documented gap, not silently
//     dropped) — kept as a REST-only call so the byte-program's operation
//     distribution stays aligned with the REST harness's; it asserts nothing new.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// miGRPCWorldContext extends miWorldContext (multitenant_isolation_fuzz_test.go) with a
// gRPC client wired onto the SAME *core.KeyorixCore the REST router already uses.
type miGRPCWorldContext struct {
	miWorldContext
	grpc pb.SecretServiceClient
}

func FuzzMultiTenantIsolationGRPC(f *testing.F) {
	worlds := buildAPIFuzzWorlds(f, "isolationgrpcfuzz")
	f.Cleanup(i18n.ResetForTesting)
	ctx := f.Context()

	miWorlds := make([]miGRPCWorldContext, 0, len(worlds))
	for _, w := range worlds {
		alice, bob := w.principals[0], w.principals[1]
		if alice.token == "" || bob.token == "" {
			f.Fatalf("[%s] isolation-grpc harness needs two logged-in principals (alice=%q bob=%q)", w.backend, alice.token, bob.token)
		}
		// Fixed, single-project grants — alice->projA, bob->projB. Never cross-project.
		// Identical to multitenant_isolation_fuzz_test.go's own setup (same core, same roles).
		if err := w.c.AssignUserRole(ctx, 0, alice.id, w.readerRole, core.Scope{ProjectID: w.projAID}, false); err != nil {
			f.Fatalf("[%s] grant alice@projA: %v", w.backend, err)
		}
		if err := w.c.AssignUserRole(ctx, 0, bob.id, w.readerRole, core.Scope{ProjectID: w.projBID}, false); err != nil {
			f.Fatalf("[%s] grant bob@projB: %v", w.backend, err)
		}

		var na, nb models.SecretNode
		if e := w.db.Where("name = ? AND project_id = ?", "sa", w.projAID).First(&na).Error; e != nil {
			f.Fatalf("[%s] lookup sa id: %v", w.backend, e)
		}
		if e := w.db.Where("name = ? AND project_id = ?", "sb", w.projBID).First(&nb).Error; e != nil {
			f.Fatalf("[%s] lookup sb id: %v", w.backend, e)
		}
		idA, idB := na.ID, nb.ID
		fakeID := idA + idB + 4242424

		tA := miTenant{tok: alice.token, ref: w.refA, val: w.valA, proj: "proja", id: idA}
		tB := miTenant{tok: bob.token, ref: w.refB, val: w.valB, proj: "projb", id: idB}

		// gRPC server wired onto the SAME core `w.c` (not a fresh one) — grants and secrets
		// created above/by the REST world are immediately visible to it. This is the SAME
		// generated world, exercised through a second transport, not a parallel world.
		srv, err := keyorixgrpc.NewServer(&config.Config{}, w.c)
		if err != nil {
			f.Fatalf("[%s] grpc server: %v", w.backend, err)
		}
		lis := bufconn.Listen(1 << 20)
		go func() { _ = srv.Serve(lis) }()
		f.Cleanup(srv.Stop)
		conn, err := grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			f.Fatalf("[%s] grpc dial: %v", w.backend, err)
		}
		f.Cleanup(func() { _ = conn.Close() })

		miWorlds = append(miWorlds, miGRPCWorldContext{
			miWorldContext: miWorldContext{w: w, tA: tA, tB: tB, fakeID: fakeID},
			grpc:           pb.NewSecretServiceClient(conn),
		})
	}

	f.Add([]byte{0x00})             // alice read-value own
	f.Add([]byte{0x08})             // alice read-value other (cross-tenant, parity-checked)
	f.Add([]byte{0x0a})             // alice read-id-metadata other
	f.Add([]byte{0x04})             // alice list (own scope)
	f.Add([]byte{0x09, 0x0b, 0x0c}) // bob cross reads + list
	f.Add([]byte{0x06})             // alice by-name (REST-only op, no new gRPC assertion)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		if len(program) > 64 {
			program = program[:64]
		}
		for _, mw := range miWorlds {
			runMultiTenantIsolationGRPCIteration(t, mw, program)
		}
	})
}

func runMultiTenantIsolationGRPCIteration(t *testing.T, mw miGRPCWorldContext, program []byte) {
	t.Helper()
	w, tA, tB, fakeID := mw.w, mw.tA, mw.tB, mw.fakeID

	doREST := func(tok, method, target string) (int, string) {
		req := httptest.NewRequest(method, target, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	grpcCtx := func(tok string) context.Context {
		gctx := context.Background()
		if tok != "" {
			gctx = metadata.NewOutgoingContext(gctx, metadata.Pairs("authorization", "Bearer "+tok))
		}
		return gctx
	}

	// grpcReadValue returns (allowed, value). allowed == GetSecretValue succeeded.
	grpcReadValue := func(tok string, id uint) (bool, string) {
		resp, err := mw.grpc.GetSecretValue(grpcCtx(tok), &pb.GetSecretRequest{Id: uint32(id), IncludeValue: true})
		if err != nil {
			return false, ""
		}
		return true, resp.GetValue()
	}

	// grpcList returns the secret NAMEs visible to tok when the list is scoped to projID
	// (the actor's OWN project — see file header on why cross-project list isn't
	// decision-parity-checked). ok==false means the call was denied outright.
	grpcList := func(tok string, projID uint) (bool, []string) {
		pid := uint32(projID)
		resp, err := mw.grpc.ListSecrets(grpcCtx(tok), &pb.ListSecretsRequest{ProjectId: &pid})
		if err != nil {
			return false, nil
		}
		names := make([]string, 0, len(resp.GetSecrets()))
		for _, s := range resp.GetSecrets() {
			names = append(names, s.GetName())
		}
		return true, names
	}

	for _, b := range program {
		actor, other := tA, tB
		if b&1 == 1 {
			actor, other = tB, tA
		}
		targetOther := (b>>3)&1 == 1
		tgt := actor
		if targetOther {
			tgt = other
		}

		switch (b >> 1) & 3 {
		case 0: // read VALUE: (a) gRPC isolation oracle + (b) REST-vs-gRPC decision/value parity
			restCode, restBody := doREST(actor.tok, http.MethodGet, "/api/v1/secrets/value?ref="+tgt.ref)
			grpcOK, grpcVal := grpcReadValue(actor.tok, tgt.id)

			if targetOther {
				if grpcOK {
					t.Fatalf("[%s] ISOLATION(gRPC): cross-tenant GetSecretValue of id %d succeeded", w.backend, tgt.id)
				}
				if strings.Contains(grpcVal, tgt.val) {
					t.Fatalf("[%s] PLAINTEXT LEAK(gRPC): cross-tenant GetSecretValue of id %d returned the value", w.backend, tgt.id)
				}
			}

			restAllow := restCode == http.StatusOK
			if restAllow != grpcOK {
				t.Fatalf("[%s] REST/gRPC PARITY VIOLATION reading %q: REST allow=%v (code=%d), gRPC allow=%v — transport-dependent tenant-isolation decision",
					w.backend, tgt.ref, restAllow, restCode, grpcOK)
			}
			if restAllow && grpcOK {
				if !strings.Contains(restBody, tgt.val) {
					t.Fatalf("[%s] REST POSITIVE-CONTROL: allowed read of %q lacks the value in body", w.backend, tgt.ref)
				}
				if grpcVal != tgt.val {
					t.Fatalf("[%s] VALUE PARITY VIOLATION: gRPC GetSecretValue of id %d returned %q, REST body for %q carries %q", w.backend, tgt.id, grpcVal, tgt.ref, tgt.val)
				}
			}

		case 1: // read-by-id metadata (gRPC GetSecret) + existence-oracle differential, gRPC-side
			if targetOther {
				gctx := grpcCtx(actor.tok)
				realResp, realErr := mw.grpc.GetSecret(gctx, &pb.GetSecretRequest{Id: uint32(tgt.id)})
				_, fakeErr := mw.grpc.GetSecret(gctx, &pb.GetSecretRequest{Id: uint32(fakeID)})
				if realErr == nil {
					t.Fatalf("[%s] ISOLATION(gRPC): cross-tenant GetSecret of real id %d succeeded (name=%q)", w.backend, tgt.id, realResp.GetName())
				}
				realCode, fakeCode := status.Code(realErr), status.Code(fakeErr)
				// Existence oracle (ADR-096 403-for-both, gRPC's authorizeScopedTarget): only
				// meaningful when the real-id denial is one of the two codes that convention
				// governs. Any other code is a THIRD outcome we don't assert on.
				if realCode == codes.NotFound || realCode == codes.PermissionDenied {
					if realCode != fakeCode {
						t.Fatalf("[%s] EXISTENCE ORACLE(gRPC): cross-tenant GetSecret of a REAL other-tenant id (code=%s) differs from a never-existed id (code=%s) — leaks existence", w.backend, realCode, fakeCode)
					}
				}
			}

		case 2: // list — gRPC-side no-enumeration oracle (own-scope list only; see file header)
			ownProjID := w.projAID
			wantOtherName := "sb"
			if actor.proj == "projb" {
				ownProjID = w.projBID
				wantOtherName = "sa"
			}
			ok, names := grpcList(actor.tok, ownProjID)
			if ok {
				for _, n := range names {
					if n == wantOtherName {
						t.Fatalf("[%s] ENUMERATION(gRPC): %s's own-scope secret list contains the other tenant's secret %q", w.backend, actor.proj, n)
					}
				}
			}

		case 3: // by-name metadata: REST-only op (no gRPC RPC exists — documented gap, see file
			// header). Kept so the byte-program's operation distribution matches the REST
			// harness's own; asserts nothing new here.
			if targetOther {
				name := "sa"
				if tgt.proj == "projb" {
					name = "sb"
				}
				_, _ = doREST(actor.tok, http.MethodGet, "/api/v1/secrets/by-name?project_id="+projIDFor(w, tgt.proj)+"&name="+name)
			}
		}
	}

	// POSITIVE CONTROLS (non-vacuous), gRPC transport: each principal can read their own
	// secret's value via gRPC too — a harness that denied everything could not pass.
	for _, own := range []miTenant{tA, tB} {
		ok, val := grpcReadValue(own.tok, own.id)
		if !ok {
			t.Fatalf("[%s] POSITIVE-CONTROL(gRPC): own GetSecretValue of id %d denied — grant/setup regression makes the gRPC isolation oracles vacuous", w.backend, own.id)
		}
		if val != own.val {
			t.Fatalf("[%s] POSITIVE-CONTROL(gRPC): own GetSecretValue of id %d returned %q want %q", w.backend, own.id, val, own.val)
		}
	}
}

// projIDFor returns the string form of the project id backing tenant proj ("proja"/"projb").
// Small helper kept local to this file (case 3's REST-only by-name call is the only user).
func projIDFor(w *apiFuzzWorld, proj string) string {
	id := w.projAID
	if proj == "projb" {
		id = w.projBID
	}
	return strconv.FormatUint(uint64(id), 10)
}
