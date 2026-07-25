// secret_access_log_export_handler.go — GET /api/v1/secrets/{id}/access-log/export
//
// Returns the secret's access history (secret.read audit events) as a
// downloadable file in the requested format (csv or json, default json).
package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)


// ExportAccessLog handles GET /api/v1/secrets/{id}/access-log/export
func (h *SecretHandler) ExportAccessLog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, contentType, err := h.coreService.ExportSecretAccessLog(r.Context(), id, format)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			h.sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
		case strings.Contains(msg, "unsupported export format"):
			h.sendError(w, "InvalidParameter", msg, http.StatusBadRequest, nil)
		default:
			log.Printf("Error exporting access log for secret %d: %v", id, err)
			h.sendError(w, "InternalError", "Failed to export access log", http.StatusInternalServerError, nil)
		}
		return
	}

	filename := fmt.Sprintf("secret-%d-access-log.%s", id, format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data) // #nosec G705 -- Content-Type explicitly set (csv/json); X-Content-Type-Options: nosniff prevents sniffing // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
}
