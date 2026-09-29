package healthscan

import (
	"context"
	"testing"
)

func TestCheckAuditDevices_None(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/audit": `{"data":{}}`})
	res := checkAuditDevices(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityCritical {
		t.Fatalf("expected critical for zero audit devices, got %+v", res)
	}
}

func TestCheckAuditDevices_One(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/audit": `{"data":{"file/":{"type":"file"}}}`})
	res := checkAuditDevices(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityMedium {
		t.Fatalf("expected medium for one audit device, got %+v", res)
	}
}

func TestCheckAuditDevices_Two(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/audit": `{"data":{"file/":{"type":"file"},"syslog/":{"type":"syslog"}}}`})
	res := checkAuditDevices(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info for two audit devices, got %+v", res)
	}
}
