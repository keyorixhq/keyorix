package reports

import (
	"context"
	"net/http"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// withUserCtx is the handlers package's test helper of the same name, copied
// here because a test helper cannot be shared across packages.
func withUserCtx(r *http.Request) *http.Request {
	userCtx := &middleware.UserContext{
		UserID:   1,
		Username: "testuser",
		Email:    "testuser@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), userCtx))
}
