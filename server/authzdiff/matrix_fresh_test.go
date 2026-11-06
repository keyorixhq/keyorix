package authzdiff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
)

// TestMatrixKeysAreCurrent: matrix.json (devtools/authzmatrix output) feeds
// coreEnforced, the COVERAGE-ALL population and the route keys, so it must
// describe the current transports. Its REST ops must be exactly the rows of
// scripts/e2e/routes.json (same key, same gate flag and gate permissions;
// routes.json is kept current by TestRouteInventoryIsCurrent), and its gRPC
// ops exactly the methods the real gRPC server registers. A new route or RPC,
// a removed one or a changed REST gate fails here until the matrix is
// regenerated:
//
//	go run ./devtools/authzmatrix -md server/authzdiff/MATRIX.md -json server/authzdiff/matrix.json
//
// What it does NOT check: the derived columns (core entries, guard reach,
// core refusal class) of an unchanged key. Those change only when the code
// behind a route changes; regenerating on every such change is the
// generator's job, not this key-set check's.
func TestMatrixKeysAreCurrent(t *testing.T) {
	type gate struct {
		gated bool
		perms string
	}
	b, err := os.ReadFile("matrix.json")
	if err != nil {
		t.Fatalf("matrix.json: %v", err)
	}
	var m struct {
		Ops []struct {
			Key       string   `json:"key"`
			Layer     string   `json:"layer"`
			Gated     bool     `json:"gated"`
			GatePerms []string `json:"gate_perms"`
		} `json:"ops"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("matrix.json: %v", err)
	}
	matrixREST := map[string]gate{}
	matrixGRPC := map[string]bool{}
	for _, op := range m.Ops {
		switch op.Layer {
		case "rest":
			matrixREST[op.Key] = gate{op.Gated, strings.Join(slices.Sorted(slices.Values(op.GatePerms)), ",")}
		case "grpc":
			matrixGRPC[op.Key] = true
		}
	}

	rb, err := os.ReadFile(filepath.Join("..", "..", "scripts", "e2e", "routes.json"))
	if err != nil {
		t.Fatalf("routes.json: %v", err)
	}
	var routes []struct {
		Method    string   `json:"method"`
		Pattern   string   `json:"pattern"`
		Gated     bool     `json:"gated"`
		GatePerms []string `json:"gate_perms"`
	}
	if err := json.Unmarshal(rb, &routes); err != nil {
		t.Fatalf("routes.json: %v", err)
	}
	inventoryREST := map[string]gate{}
	for _, r := range routes {
		inventoryREST["REST "+r.Method+" "+r.Pattern] = gate{r.Gated, strings.Join(slices.Sorted(slices.Values(r.GatePerms)), ",")}
	}

	srv, err := keyorixgrpc.NewServer(&config.Config{}, nil)
	if err != nil {
		t.Fatalf("grpc server: %v", err)
	}
	defer srv.Stop()
	registered := map[string]bool{}
	for svc, info := range srv.GetServiceInfo() {
		if !strings.HasPrefix(svc, "keyorix.") {
			continue // grpc.health and similar infrastructure services
		}
		for _, md := range info.Methods {
			registered["GRPC "+svc+"."+md.Name] = true
		}
	}
	if len(inventoryREST) == 0 || len(registered) == 0 {
		t.Fatalf("empty population (routes=%d, rpcs=%d): the check is vacuous", len(inventoryREST), len(registered))
	}

	var stale []string
	for k, g := range inventoryREST {
		mg, ok := matrixREST[k]
		switch {
		case !ok:
			stale = append(stale, "missing from matrix: "+k)
		case mg != g:
			stale = append(stale, "gate changed: "+k)
		}
	}
	for k := range matrixREST {
		if _, ok := inventoryREST[k]; !ok {
			stale = append(stale, "no longer a route: "+k)
		}
	}
	for k := range registered {
		if !matrixGRPC[k] {
			stale = append(stale, "missing from matrix: "+k)
		}
	}
	for k := range matrixGRPC {
		if !registered[k] {
			stale = append(stale, "no longer registered: "+k)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		t.Errorf("matrix.json is stale (%d keys); regenerate it (see this test's doc):\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
}
