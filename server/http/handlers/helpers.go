package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

// sendSuccess sends a successful JSON response
func sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	response := map[string]interface{}{
		"data": data,
	}
	if message != "" {
		response["message"] = message
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// clientSafe returns a generic, client-safe message in place of err's raw
// Error() text. Use it at the fallback/default branch of an error path once
// the caller has already carved out the small set of deliberately-crafted,
// known-safe outcomes (validation messages, "not found", "already exists",
// etc.) — everything left over is assumed to originate from a lower layer
// (database/ORM/driver, an upstream secret-store connector, a parser) whose
// raw text can leak schema, driver, or hostname details that help an
// attacker fingerprint the backend (backlog #116). The caller MUST still log
// the original err server-side (e.g. via log.Printf) before calling this —
// clientSafe only sanitizes the copy that reaches the client.
func clientSafe(err error) string {
	if err == nil {
		return ""
	}
	return "an internal error occurred; please try again or contact support if the problem persists"
}

// sendError sends an error JSON response
func sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":   errorType,
		"message": message,
		"code":    statusCode,
	}
	if details != nil {
		response["details"] = details
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}
