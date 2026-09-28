package healthscan

import (
	"context"
	"strings"
	"testing"
)

func TestCheckHAStorage_HealthyRaftMultiNode(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"storage_type":"raft"}`,
		"/v1/sys/leader":      `{"ha_enabled":true,"is_self":true,"performance_standby":false}`,
		"/v1/sys/storage/raft/configuration": `{"data":{"config":{"servers":[
			{"node_id":"a","voter":true,"leader":true},
			{"node_id":"b","voter":true},
			{"node_id":"c","voter":true}
		]}}}`,
	})
	res := checkHAStorage(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info for a healthy 3-node raft cluster, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "peers=3") {
		t.Errorf("evidence = %q, want peer count 3", res.Finding.Evidence)
	}
}

func TestCheckHAStorage_SingleNodeRaftIsHigh(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"storage_type":"raft"}`,
		"/v1/sys/leader":      `{"ha_enabled":true,"is_self":true}`,
		"/v1/sys/storage/raft/configuration": `{"data":{"config":{"servers":[
			{"node_id":"a","voter":true,"leader":true}
		]}}}`,
	})
	res := checkHAStorage(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity for single-node raft, got %+v", res)
	}
}

func TestCheckHAStorage_NoHAIsHigh(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"storage_type":"file"}`,
		"/v1/sys/leader":      `{"ha_enabled":false,"is_self":true}`,
	})
	res := checkHAStorage(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity for ha_enabled=false, got %+v", res)
	}
}

func TestCheckRaftAutopilot_NotPresent(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/storage/raft/autopilot/state", 404, `{"errors":[]}`)
	res := checkRaftAutopilot(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected an info finding for a 404, got %+v", res)
	}
}

func TestCheckRaftAutopilot_Unhealthy(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/storage/raft/autopilot/state": `{"data":{"healthy":false,"failure_tolerance":0}}`,
	})
	res := checkRaftAutopilot(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity when unhealthy, got %+v", res)
	}
}
