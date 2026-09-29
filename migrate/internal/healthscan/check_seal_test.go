package healthscan

import (
	"context"
	"net/http"
	"testing"
)

func TestCheckSeal_HealthyShamir(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"type":"shamir","sealed":false,"initialized":true,"t":3,"n":5,"recovery_seal":false}`,
	})
	res := checkSeal(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected an info finding, got %+v", res)
	}
}

func TestCheckSeal_SingleShareIsHigh(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"type":"shamir","sealed":false,"initialized":true,"t":1,"n":1,"recovery_seal":false}`,
	})
	res := checkSeal(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityHigh {
		t.Fatalf("expected high severity for a 1-of-1 threshold, got %+v", res)
	}
}

func TestCheckSeal_Sealed(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"type":"shamir","sealed":true,"initialized":true,"t":3,"n":5}`,
	})
	res := checkSeal(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityCritical {
		t.Fatalf("expected critical severity when sealed, got %+v", res)
	}
}

func TestCheckSeal_AutoUnsealRecoveryKeys(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/seal-status": `{"type":"awskms","sealed":false,"initialized":true,"t":3,"n":5,"recovery_seal":true}`,
	})
	res := checkSeal(context.Background(), c)
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
	if res.Finding.Severity != SeverityInfo {
		t.Errorf("auto-unseal with a 3-of-5 recovery threshold should not be flagged, got %s", res.Finding.Severity)
	}
}

func TestCheckSeal_Denied(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/seal-status", http.StatusForbidden, `{}`)
	res := checkSeal(context.Background(), c)
	if res.NotChecked == nil {
		t.Fatalf("expected NotChecked, got %+v", res)
	}
}
