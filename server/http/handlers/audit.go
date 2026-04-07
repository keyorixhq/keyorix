package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         uint      `json:"id"`
	UserID     uint      `json:"user_id"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID *uint     `json:"resource_id,omitempty"`
	Details    string    `json:"details"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	Success    bool      `json:"success"`
	ErrorMsg   *string   `json:"error_message,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// RBACAuditLog represents an RBAC-specific audit log entry
type RBACAuditLog struct {
	ID         uint      `json:"id"`
	UserID     uint      `json:"user_id"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   uint      `json:"target_id"`
	TargetName string    `json:"target_name"`
	Details    string    `json:"details"`
	IPAddress  string    `json:"ip_address"`
	Success    bool      `json:"success"`
	ErrorMsg   *string   `json:"error_message,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// GetAuditLogs handles GET /api/v1/audit/logs
func GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse query parameters
	page := 1
	pageSize := 50
	action := r.URL.Query().Get("action")
	resource := r.URL.Query().Get("resource")
	userIDStr := r.URL.Query().Get("user_id")
	startTimeStr := r.URL.Query().Get("start_time")
	endTimeStr := r.URL.Query().Get("end_time")

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	var userID *uint
	if userIDStr != "" {
		if uid, err := strconv.ParseUint(userIDStr, 10, 32); err == nil {
			u := uint(uid)
			userID = &u
		}
	}

	var startTime, endTime *time.Time
	if startTimeStr != "" {
		if st, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			startTime = &st
		}
	}
	if endTimeStr != "" {
		if et, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			endTime = &et
		}
	}

	// Mock audit logs data
	now := time.Now()
	auditLogs := []AuditLog{
		{
			ID:         1,
			UserID:     1,
			Username:   "admin",
			Action:     "CREATE_SECRET",
			Resource:   "secret",
			ResourceID: uintPtr(1),
			Details:    "Created secret 'database-password' in production environment",
			IPAddress:  "192.168.1.100",
			UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			Success:    true,
			Timestamp:  now.Add(-2 * time.Hour),
		},
		{
			ID:         2,
			UserID:     2,
			Username:   "user1",
			Action:     "READ_SECRET",
			Resource:   "secret",
			ResourceID: uintPtr(1),
			Details:    "Accessed secret 'database-password'",
			IPAddress:  "192.168.1.101",
			UserAgent:  "curl/7.68.0",
			Success:    true,
			Timestamp:  now.Add(-1 * time.Hour),
		},
		{
			ID:        3,
			UserID:    3,
			Username:  "user2",
			Action:    "DELETE_SECRET",
			Resource:  "secret",
			Details:   "Attempted to delete secret 'api-key' without permission",
			IPAddress: "192.168.1.102",
			UserAgent: "PostmanRuntime/7.29.0",
			Success:   false,
			ErrorMsg:  stringPtr("Permission denied: insufficient privileges"),
			Timestamp: now.Add(-30 * time.Minute),
		},
		{
			ID:         4,
			UserID:     1,
			Username:   "admin",
			Action:     "UPDATE_USER",
			Resource:   "user",
			ResourceID: uintPtr(2),
			Details:    "Updated user profile for user1",
			IPAddress:  "192.168.1.100",
			UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			Success:    true,
			Timestamp:  now.Add(-15 * time.Minute),
		},
		{
			ID:         5,
			UserID:     1,
			Username:   "admin",
			Action:     "ASSIGN_ROLE",
			Resource:   "role",
			ResourceID: uintPtr(2),
			Details:    "Assigned role 'user' to user 'user1'",
			IPAddress:  "192.168.1.100",
			UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			Success:    true,
			Timestamp:  now.Add(-5 * time.Minute),
		},
	}

	// Apply filters (simplified for demo)
	filteredLogs := []AuditLog{}
	for _, log := range auditLogs {
		if action != "" && log.Action != action {
			continue
		}
		if resource != "" && log.Resource != resource {
			continue
		}
		if userID != nil && log.UserID != *userID {
			continue
		}
		if startTime != nil && log.Timestamp.Before(*startTime) {
			continue
		}
		if endTime != nil && log.Timestamp.After(*endTime) {
			continue
		}
		filteredLogs = append(filteredLogs, log)
	}

	// Apply pagination (simplified)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= len(filteredLogs) {
		filteredLogs = []AuditLog{}
	} else if end > len(filteredLogs) {
		filteredLogs = filteredLogs[start:]
	} else {
		filteredLogs = filteredLogs[start:end]
	}

	totalPages := (len(auditLogs) + pageSize - 1) / pageSize

	response := map[string]interface{}{
		"logs":        filteredLogs,
		"page":        page,
		"page_size":   pageSize,
		"total":       len(auditLogs),
		"total_pages": totalPages,
		"filters": map[string]interface{}{
			"action":     action,
			"resource":   resource,
			"user_id":    userID,
			"start_time": startTime,
			"end_time":   endTime,
		},
	}

	sendSuccess(w, response, "")
}

// GetRBACAuditLogs handles GET /api/v1/audit/rbac-logs
func GetRBACAuditLogs(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse query parameters
	page := 1
	pageSize := 50
	action := r.URL.Query().Get("action")
	targetType := r.URL.Query().Get("target_type")
	userIDStr := r.URL.Query().Get("user_id")

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	var userID *uint
	if userIDStr != "" {
		if uid, err := strconv.ParseUint(userIDStr, 10, 32); err == nil {
			u := uint(uid)
			userID = &u
		}
	}

	// Mock RBAC audit logs data
	now := time.Now()
	rbacLogs := []RBACAuditLog{
		{
			ID:         1,
			UserID:     1,
			Username:   "admin",
			Action:     "CREATE_USER",
			TargetType: "user",
			TargetID:   3,
			TargetName: "user2",
			Details:    "Created new user account",
			IPAddress:  "192.168.1.100",
			Success:    true,
			Timestamp:  now.Add(-3 * time.Hour),
		},
		{
			ID:         2,
			UserID:     1,
			Username:   "admin",
			Action:     "CREATE_ROLE",
			TargetType: "role",
			TargetID:   3,
			TargetName: "viewer",
			Details:    "Created new role with read-only permissions",
			IPAddress:  "192.168.1.100",
			Success:    true,
			Timestamp:  now.Add(-2 * time.Hour),
		},
		{
			ID:         3,
			UserID:     1,
			Username:   "admin",
			Action:     "ASSIGN_ROLE",
			TargetType: "user_role",
			TargetID:   2,
			TargetName: "user1 -> user",
			Details:    "Assigned role 'user' to user 'user1'",
			IPAddress:  "192.168.1.100",
			Success:    true,
			Timestamp:  now.Add(-1 * time.Hour),
		},
		{
			ID:         4,
			UserID:     2,
			Username:   "user1",
			Action:     "UPDATE_ROLE",
			TargetType: "role",
			TargetID:   2,
			TargetName: "user",
			Details:    "Attempted to modify role permissions",
			IPAddress:  "192.168.1.101",
			Success:    false,
			ErrorMsg:   stringPtr("Permission denied: insufficient privileges"),
			Timestamp:  now.Add(-30 * time.Minute),
		},
		{
			ID:         5,
			UserID:     1,
			Username:   "admin",
			Action:     "REMOVE_ROLE",
			TargetType: "user_role",
			TargetID:   3,
			TargetName: "user2 -> viewer",
			Details:    "Removed role 'viewer' from user 'user2'",
			IPAddress:  "192.168.1.100",
			Success:    true,
			Timestamp:  now.Add(-10 * time.Minute),
		},
	}

	// Apply filters (simplified for demo)
	filteredLogs := []RBACAuditLog{}
	for _, log := range rbacLogs {
		if action != "" && log.Action != action {
			continue
		}
		if targetType != "" && log.TargetType != targetType {
			continue
		}
		if userID != nil && log.UserID != *userID {
			continue
		}
		filteredLogs = append(filteredLogs, log)
	}

	// Apply pagination (simplified)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= len(filteredLogs) {
		filteredLogs = []RBACAuditLog{}
	} else if end > len(filteredLogs) {
		filteredLogs = filteredLogs[start:]
	} else {
		filteredLogs = filteredLogs[start:end]
	}

	totalPages := (len(rbacLogs) + pageSize - 1) / pageSize

	response := map[string]interface{}{
		"logs":        filteredLogs,
		"page":        page,
		"page_size":   pageSize,
		"total":       len(rbacLogs),
		"total_pages": totalPages,
		"filters": map[string]interface{}{
			"action":      action,
			"target_type": targetType,
			"user_id":     userID,
		},
	}

	sendSuccess(w, response, "")
}

// Helper functions
func uintPtr(u uint) *uint {
	return &u
}

func stringPtr(s string) *string {
	return &s
}

// Helper functions are now in helpers.go
