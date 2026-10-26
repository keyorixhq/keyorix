package httpx

// ErrorResponse is the standard error envelope returned on all 4xx/5xx responses.
//
// Success is always false here — the zero value already gives that for free,
// but it's written out explicitly for symmetry with SuccessResponse and so it
// doesn't rely on internal/storage/remote.HTTPClient's incidental
// parse-failure fallback (see helpers.go's sendError doc comment) to end up
// correct.
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Details any    `json:"details,omitempty"`
}

// SuccessResponse is the standard success envelope returned on 2xx responses.
//
// Success must always be true here: internal/storage/store/remote_*.go (the
// storage.type: remote backend) decodes this body into
// internal/storage/remote.APIResponse and branches on its Success field, not
// the HTTP status — omitting this field left it at Go's zero value (false)
// for every genuinely successful response, misreporting every proxied
// read/write as a failure.
type SuccessResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data"`
	Message string `json:"message,omitempty"`
}
