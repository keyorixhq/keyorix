package httpx

// Error-message strings the shared helpers (and the handler subpackages) need.
// server/http/handlers/constants.go refers to these so each text has one source.
const (
	ErrInvalidEnvIDField     = "Invalid environment_id"
	ErrInvalidProjectID      = "Invalid project ID"
	ErrInvalidProjectIDField = "Invalid project_id"
	ErrInvalidRequestBody    = "Invalid request body"
	ErrUserContext           = "User context not found"
	ErrUserOnlyEndpoint      = "This endpoint is only available to user accounts"
)
