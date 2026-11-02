package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
)

// storageUnavailableCode is the stable machine-readable error code (the envelope's
// "error" field) of an operation refused because a storage READ it depends on
// failed (core.ErrStorageReadUnavailable). Clients branch on it, never on the
// message. Same envelope as audit_unavailable (STORAGE-ERR-CLASS-1: no new shape).
const storageUnavailableCode = "storage_unavailable"

// storageUnavailableRetryAfterSeconds is the Retry-After a client is given: the
// outage is the store's, not the request's, and the operation was not applied.
const storageUnavailableRetryAfterSeconds = 5

// sendStorageUnavailable answers a core.ErrStorageReadUnavailable (a revoke, suspend,
// unbind, attest, ... whose storage read failed, so nothing was applied) with 503, a
// Retry-After header and the stable code storage_unavailable, and reports whether it
// did. The message is the sentinel's fixed text, never err.Error(): the wrapped
// cause names the driver failure. Check it in an error branch before any message-text
// mapping, which would otherwise answer a fault as 404 or 500.
func sendStorageUnavailable(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, core.ErrStorageReadUnavailable) {
		return false
	}
	log.Printf("operation refused, storage read failed (HTTP 503): %s", core.StorageReadFaultDetail(err))
	w.Header().Set("Retry-After", strconv.Itoa(storageUnavailableRetryAfterSeconds))
	sendError(w, storageUnavailableCode, core.StorageReadUnavailableMessage, http.StatusServiceUnavailable, nil)
	return true
}
