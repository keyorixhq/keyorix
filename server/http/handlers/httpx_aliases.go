package handlers

import "github.com/keyorixhq/keyorix/server/http/handlers/httpx"

// The shared response and request helpers live in server/http/handlers/httpx so
// handler subpackages (reports, ...) can use them. These aliases keep the old
// package-local names, so the ~150 handler files that call them do not change.
// New code outside this package calls httpx directly.

type (
	ErrorResponse   = httpx.ErrorResponse
	SuccessResponse = httpx.SuccessResponse
)

const (
	hdrContentType         = httpx.HdrContentType
	hdrXContentTypeOptions = httpx.HdrXContentTypeOptions
	mimeApplicationJSON    = httpx.MimeApplicationJSON
)

var (
	sendSuccess            = httpx.SendSuccess
	sendCreated            = httpx.SendCreated
	sendAccepted           = httpx.SendAccepted
	sendError              = httpx.SendError
	clientSafe             = httpx.ClientSafe
	errorMessageFor        = httpx.ErrorMessageFor
	goSafe                 = httpx.GoSafe
	mustParseUintParam     = httpx.MustParseUintParam
	mustParseProjectID     = httpx.MustParseProjectID
	mustGetUser            = httpx.MustGetUser
	mustGetHumanUser       = httpx.MustGetHumanUser
	mustDecodeBody         = httpx.MustDecodeBody
	encodeJSONResponse     = httpx.EncodeJSONResponse
	parseOptionalUintQuery = httpx.ParseOptionalUintQuery

	// DrainBackgroundGoroutines blocks until every goSafe goroutine dispatched so far
	// has returned (test-only observability hook; see httpx.DrainBackgroundGoroutines).
	DrainBackgroundGoroutines = httpx.DrainBackgroundGoroutines
)
