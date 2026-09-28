package healthscan

import (
	"context"
	"strings"
	"testing"
)

func TestCheckRaftAutoSnapshot_NotVisibleIsUnknownAsk(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/storage/raft/snapshot-auto/config", 404, `{"errors":[]}`)
	res := checkRaftAutoSnapshot(context.Background(), c)
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(res.Finding.Evidence, "unknown, ask") {
		t.Errorf("evidence = %q, want the literal 'unknown, ask' wording", res.Finding.Evidence)
	}
	if res.Finding.Severity != SeverityInfo {
		t.Errorf("severity = %s, want info (this isn't evidence backups are missing)", res.Finding.Severity)
	}
}

func TestCheckRaftAutoSnapshot_NoneConfiguredIsHigh(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/storage/raft/snapshot-auto/config": `{"data":{"keys":[]}}`})
	res := checkRaftAutoSnapshot(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high when the API is visible but nothing is configured, got %+v", res)
	}
}

func TestCheckRaftAutoSnapshot_Configured(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/storage/raft/snapshot-auto/config": `{"data":{"keys":["daily"]}}`})
	res := checkRaftAutoSnapshot(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info when a snapshot config exists, got %+v", res)
	}
}
