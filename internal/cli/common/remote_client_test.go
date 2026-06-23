package common

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRaw(t *testing.T) {
	const body = "name,project,type\napi-key,1,static\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer tok")
		}
		if r.URL.Path == "/ok" {
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := &RemoteClient{Endpoint: srv.URL, Token: "tok", hc: srv.Client()}

	t.Run("returns the raw body verbatim", func(t *testing.T) {
		got, err := c.GetRaw(context.Background(), "/ok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != body {
			t.Errorf("body = %q, want %q", got, body)
		}
	})

	t.Run("surfaces an HTTP error", func(t *testing.T) {
		if _, err := c.GetRaw(context.Background(), "/denied"); err == nil {
			t.Error("expected an error for a 403 response")
		}
	})
}
