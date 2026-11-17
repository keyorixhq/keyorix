package handlers

// core_error_answer_test.go — the REST adapter of server/errclass renders every class
// of the shared table as errclass.HTTPStatus says (the gRPC adapter's test asserts the
// same rows against errclass.GRPCCode, so the two transports are checked against ONE
// table: a REST/gRPC parity check on the sentinel errors, FIX-ERRMAP-STRUCT-1 item 3),
// and the texts obey the raw-error rule.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/errclass"
)

func answerFor(t *testing.T, err error, a coreErrorAnswer) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	answerCoreError(w, r, err, a)
	return w
}

func TestAnswerCoreError_EverySentinelRendersItsClass(t *testing.T) {
	for _, s := range errclass.Sentinels() {
		t.Run(s.Name, func(t *testing.T) {
			var err error
			switch s.Err {
			case core.ErrStorageReadUnavailable:
				err = core.ReadFault(errors.New("pq: connection refused host=db-prod.internal"))
			default:
				err = fmt.Errorf("Speicherfehler: %w: pq: duplicate key value violates unique constraint \"idx\"", s.Err)
			}
			w := answerFor(t, err, coreErrorAnswer{op: "testing"})
			assert.Equal(t, errclass.HTTPStatus(s.Class), w.Code, w.Body.String())
			body := w.Body.String()
			if s.Class != errclass.InvalidInput {
				assert.NotContains(t, body, "pq:", "a wrapped driver message never reaches the client (class %s)", s.Class)
			}
			if w.Code == http.StatusServiceUnavailable {
				assert.NotEmpty(t, w.Header().Get("Retry-After"))
			}
			if code, ok := coreErrorCodes[s.Class]; ok {
				assert.Contains(t, body, `"error":"`+code+`"`)
			}
		})
	}
}

func TestAnswerCoreError_TextsAndCodes(t *testing.T) {
	// A site override keeps the route's wording; the default is fixed for every class
	// but InvalidInput, which shows core's own validation text.
	w := answerFor(t, fmt.Errorf("get: %w", storage.ErrSecretNotFound), coreErrorAnswer{texts: coreErrorTexts{errclass.NotFound: "Secret not found"}})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Secret not found"`)
	assert.Contains(t, w.Body.String(), `"error":"NotFound"`)

	w = answerFor(t, fmt.Errorf("get: %w", storage.ErrSecretNotFound), coreErrorAnswer{})
	assert.Contains(t, w.Body.String(), `"message":"Resource not found"`)

	w = answerFor(t, fmt.Errorf("%w: project name exceeds 200 characters", core.ErrValidation), coreErrorAnswer{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project name exceeds 200 characters")

	w = answerFor(t, fmt.Errorf("x: %w", core.ErrPermissionDenied), coreErrorAnswer{})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"Forbidden"`)

	w = answerFor(t, fmt.Errorf("x: %w", storage.ErrRoleAlreadyAssigned), coreErrorAnswer{})
	assert.Equal(t, http.StatusConflict, w.Code)
	w = answerFor(t, fmt.Errorf("x: %w", core.ErrSecretNotDeleted), coreErrorAnswer{})
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestAnswerCoreError_InternalIsClientSafe(t *testing.T) {
	raw := errors.New("pq: relation \"secrets\" does not exist on host db-prod.internal:5432")
	w := answerFor(t, raw, coreErrorAnswer{op: "listing"})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "pq:")
	assert.NotContains(t, w.Body.String(), "db-prod")
	assert.Equal(t, clientSafe(raw), errorMessageFor(http.StatusInternalServerError, raw))
	// Text that merely says "not found" / "permission denied" is a server fault, never a verdict.
	for _, txt := range []string{"record not found", "open /etc/x: permission denied", "already exists"} {
		w := answerFor(t, errors.New(txt), coreErrorAnswer{op: "testing"})
		assert.Equal(t, http.StatusInternalServerError, w.Code, txt)
	}
}

func TestAnswerCoreError_OutagesComeFirst(t *testing.T) {
	// A storage read fault wrapped in a "not found" text is 503 storage_unavailable.
	fault := fmt.Errorf("secret not found: %w", core.ReadFault(errors.New("driver: connection reset")))
	w := answerFor(t, fault, coreErrorAnswer{})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), storageUnavailableCode)
	assert.Equal(t, "5", w.Header().Get("Retry-After"))

	// An audit outage is 503 audit_unavailable.
	w = answerFor(t, fmt.Errorf("x: %w", core.ErrMutationAuditUnavailable), coreErrorAnswer{})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), auditUnavailableCode)

	// A partial mutation keeps its machine-readable body.
	partial := &core.PartialMutationError{Applied: "removal", NotApplied: "addition", Err: core.ErrMutationAuditUnavailable}
	w = answerFor(t, partial, coreErrorAnswer{})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), core.PartialMutationErrorType)
	assert.Contains(t, w.Body.String(), "retry_safe")

	// An authorize outage (the permission lookup's connection refused) is the gates'
	// 503, not a 500 and not a 403.
	outage := fmt.Errorf("resolve permission: dial tcp: %w", syscall.ECONNREFUSED)
	w = answerFor(t, outage, coreErrorAnswer{op: "testing"})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, authorizeLookupUnavailableRetryAfter, w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), authorizeLookupUnavailableMessage)
	assert.NotContains(t, w.Body.String(), "connection refused")

	// A canceled request is not a server fault either.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wc := httptest.NewRecorder()
	answerCoreError(wc, httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(ctx), errors.New("boom"), coreErrorAnswer{op: "testing"})
	assert.Equal(t, http.StatusServiceUnavailable, wc.Code)
}

// The permission-lookup-fault path through a recorder is driven end to end by the
// handler tests (secret_mutation_lookup_fault_test.go, faultstorage on
// ResolveUserPermissionAt); here only the shape of the empty recorder is checked.
func TestAnswerCoreError_EmptyRecorderKeepsTheRefusal(t *testing.T) {
	_, rec := core.WithAuthorizeFaultRecorder(context.Background())
	require.Nil(t, rec.Err())
	w := answerFor(t, fmt.Errorf("x: %w", core.ErrPermissionDenied), coreErrorAnswer{faults: rec})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), "Insufficient permissions"))
}
