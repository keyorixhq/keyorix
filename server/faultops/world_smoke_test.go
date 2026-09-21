package faultops

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestNewFaultWorld_RESTAndGRPCBothReachable is the green control for world_test.go:
// both transports must be live and authenticated before the op catalog can rely
// on them.
func TestNewFaultWorld_RESTAndGRPCBothReachable(t *testing.T) {
	w := newFaultWorld(t, nil)

	body, err := json.Marshal(map[string]any{"name": "smoke-test-project"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, w.httpServer.URL+"/api/v1/projects", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+w.adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("REST CreateProject status = %d, want 2xx", resp.StatusCode)
	}

	sysResp, err := pb.NewSystemServiceClient(w.grpcConn).HealthCheck(w.grpcCtx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("gRPC HealthCheck: %v", err)
	}
	if sysResp.GetStatus() != "healthy" {
		t.Fatalf("gRPC HealthCheck status = %q, want healthy", sysResp.GetStatus())
	}
}
