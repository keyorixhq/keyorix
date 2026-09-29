package healthscan

import (
	"context"
	"testing"
)

func TestCheckNamespaces_NotSupported(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/namespaces", 404, `{"errors":[]}`)
	res := checkNamespaces(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info on 404, got %+v", res)
	}
}

func TestCheckNamespaces_Enterprise(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/namespaces": `{"data":{"keys":["team-a/","team-b/"]}}`})
	res := checkNamespaces(context.Background(), c)
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
}
