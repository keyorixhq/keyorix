// users_crud.go — CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser handlers.
//
// Handles core user lifecycle operations.
// For list/search see users_list.go.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// CreateUser handles POST /api/v1/users
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var body struct {
		Username    string `json:"username" validate:"required,min=3,max=50"`
		Email       string `json:"email" validate:"required,email"`
		DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
		// Password is optional when DeliverSetupLink is set — the user sets their own
		// password via the setup link (ADR-028) instead of the admin choosing one.
		Password string `json:"password" validate:"omitempty,min=8"`
		IsActive *bool  `json:"is_active,omitempty"`
		// DeliverSetupLink provisions an account_setup link instead of an admin-set
		// password: the account is created in pending_first_login state and a setup
		// link is delivered (or returned for out-of-band relay).
		DeliverSetupLink bool `json:"deliver_setup_link,omitempty"`
		// GenerateOneTimePassword provisions a server-generated initial password instead
		// of an admin-set one or a setup link: the account is created in
		// password_reset_required state and the password is returned once for the admin
		// to relay out-of-band (ADR-028 Part E). The user must change it on first login.
		GenerateOneTimePassword bool `json:"generate_one_time_password,omitempty"`
		// Atomic provisioning (ADR-028): an optional system role override and a set
		// of project-scoped role assignments, applied with the create in one
		// transaction. Supported on the admin-set-password path only.
		Role               string `json:"role,omitempty"`
		ProjectAssignments []struct {
			ProjectID uint   `json:"project_id"`
			Role      string `json:"role"`
		} `json:"project_assignments,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.CreateUserRequest{
		Username:    body.Username,
		Email:       body.Email,
		DisplayName: body.DisplayName,
		Password:    body.Password,
		IsActive:    body.IsActive,
	}

	// The three credential modes are mutually exclusive: admin-set password, setup
	// link, or generated one-time password.
	if body.DeliverSetupLink && body.GenerateOneTimePassword {
		sendError(w, "ValidationError", "Choose either deliver_setup_link or generate_one_time_password, not both", http.StatusBadRequest, nil)
		return
	}

	// Atomic role/project assignments are supported only on the admin-set-password
	// path for now (the setup-link / one-time-password paths create the account in
	// a restricted state before the user finishes setup).
	hasAssignments := body.Role != "" || len(body.ProjectAssignments) > 0
	if hasAssignments && (body.DeliverSetupLink || body.GenerateOneTimePassword) {
		sendError(w, "ValidationError", "role/project_assignments are only supported with an admin-set password", http.StatusBadRequest, nil)
		return
	}

	// One-time-password path (ADR-028 Part E): server generates the initial password,
	// returns it once for out-of-band relay, and forces a change on first login.
	if body.GenerateOneTimePassword {
		created, otp, err := h.coreService.CreateUserWithOneTimePassword(r.Context(), req, userCtx.UserID)
		if err != nil {
			log.Printf("Error creating user with one-time password: %v", err)
			if strings.Contains(err.Error(), "already exists") {
				sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
				return
			}
			if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
				sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
				return
			}
			sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
			return
		}
		w.WriteHeader(http.StatusCreated)
		sendSuccess(w, map[string]interface{}{
			"user":              userToAPIResponse(created),
			"one_time_password": otp,
		}, i18n.T("SuccessUserCreated", nil))
		return
	}

	// Setup-link provisioning path (ADR-028): no admin password; deliver a link.
	if body.DeliverSetupLink {
		created, prov, err := h.coreService.CreateUserWithSetupLink(r.Context(), req, userCtx.UserID)
		if err != nil {
			log.Printf("Error creating user with setup link: %v", err)
			if strings.Contains(err.Error(), "already exists") {
				sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
				return
			}
			if errors.Is(err, core.ErrSetupBaseURLRequired) {
				sendError(w, "ConfigError", err.Error(), http.StatusBadRequest, nil)
				return
			}
			if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
				sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
				return
			}
			sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
			return
		}
		w.WriteHeader(http.StatusCreated)
		sendSuccess(w, map[string]interface{}{
			"user":       userToAPIResponse(created),
			"setup_link": prov,
		}, i18n.T("SuccessUserCreated", nil))
		return
	}

	// Classic path: the admin supplies the initial password.
	if body.Password == "" {
		sendError(w, "ValidationError", "Password is required unless deliver_setup_link or generate_one_time_password is set", http.StatusBadRequest, nil)
		return
	}

	// Atomic provisioning must not let the caller hand out access they could not
	// assign directly (defense-in-depth beyond the users.write route gate, and the
	// principled fix for the cross-project privesc class): a system-role override
	// requires roles.assign at global scope; each project assignment requires
	// roles.assign at that project. A global admin passes both via admin-bypass.
	if hasAssignments {
		if body.Role != "" {
			if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "roles.assign", core.Scope{}); aerr != nil || !ok {
				sendError(w, "Forbidden", "You may not assign a system role", http.StatusForbidden, nil)
				return
			}
		}
		for _, a := range body.ProjectAssignments {
			if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "roles.assign", core.Scope{ProjectID: a.ProjectID}); aerr != nil || !ok {
				sendError(w, "Forbidden", "You may not assign roles in the target project", http.StatusForbidden, nil)
				return
			}
		}
	}

	var created *models.User
	var err error
	if hasAssignments {
		assignments := make([]core.ProjectAssignment, 0, len(body.ProjectAssignments))
		for _, a := range body.ProjectAssignments {
			assignments = append(assignments, core.ProjectAssignment{ProjectID: a.ProjectID, Role: a.Role})
		}
		created, err = h.coreService.CreateUserWithAssignments(r.Context(), req, body.Role, assignments, userCtx.UserID)
	} else {
		created, err = h.coreService.CreateUser(r.Context(), req)
	}
	if err != nil {
		log.Printf("Error creating user: %v", err)
		switch {
		case strings.Contains(err.Error(), "already exists"):
			sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
		case strings.Contains(err.Error(), "only an administrator can grant"):
			sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
		case strings.Contains(err.Error(), "unknown role"), strings.Contains(err.Error(), "unknown project"),
			strings.Contains(err.Error(), "each project assignment"),
			strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)):
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, userToAPIResponse(created), i18n.T("SuccessUserCreated", nil))
}

// GetUser handles GET /api/v1/users/{id}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUser(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error getting user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to get user", http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]interface{}{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// GetUserByEmail handles GET /api/v1/users/by-email?email=X — looks up a user by
// email address for callers (e.g. RemoteStorage, #503) that only have the email
// rather than the numeric ID. The route's permission gate (users.read, inherited
// from the /users group — the same gate GetUser-by-id uses) is the sole authz
// check, matching GetUser's model exactly; there is no additional per-record
// check to bypass. Deliberately mirrors GetUser's generic NotFound response
// (same status code, same static message) rather than a distinct shape, so a
// caller cannot use response differences to enumerate valid email addresses —
// a caller without users.read never reaches this handler at all (401/403 from
// the route middleware, identical for every email), and a caller WITH users.read
// can already enumerate every user (including email) via GET /users, so this
// route grants no new capability at that permission level.
func (h *UserHandler) GetUserByEmail(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		sendError(w, "InvalidParameter", "email is required", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUserByEmail(r.Context(), email)
	if err != nil {
		log.Printf("Error getting user by email: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to get user", http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]interface{}{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// GetUserByUsername handles GET /api/v1/users/by-username?username=X (#505) —
// the server-side counterpart RemoteStorage.GetUserByUsername needs. Same gate
// and NotFound shape as GetUserByEmail: users.read (the group-wide gate above),
// generic NotFound on a miss so the route adds no username-enumeration surface
// beyond what GET /users already exposes to a users.read caller.
func (h *UserHandler) GetUserByUsername(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		sendError(w, "InvalidParameter", "username is required", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUserByUsername(r.Context(), username)
	if err != nil {
		log.Printf("Error getting user by username: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to get user", http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]interface{}{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// GetUserByExternalID handles GET /api/v1/users/by-external-id?external_id=X
// (#505) — the server-side counterpart RemoteStorage.GetUserByExternalID needs
// for SSO/SCIM identity resolution. Same gate and NotFound shape as
// GetUserByEmail/GetUserByUsername: users.read, generic NotFound on a miss.
func (h *UserHandler) GetUserByExternalID(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	externalID := strings.TrimSpace(r.URL.Query().Get("external_id"))
	if externalID == "" {
		sendError(w, "InvalidParameter", "external_id is required", http.StatusBadRequest, nil)
		return
	}
	u, err := h.coreService.GetUserByExternalID(r.Context(), externalID)
	if err != nil {
		log.Printf("Error getting user by external id: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to get user", http.StatusInternalServerError, nil)
		return
	}
	resp := userToAPIResponse(u)
	h.attachProjectCounts(r.Context(), []map[string]interface{}{resp}, []uint{u.ID})
	sendSuccess(w, resp, "")
}

// VerifyCredentials handles POST /api/v1/users/verify-credentials (#506/#508)
// — the upstream half of the RemoteLoginVerifier proxy-login mechanism
// (internal/core/auth.go). It exists SOLELY so a storage.type: remote
// deployment's own core.Login can authenticate a password at all:
// models.User.PasswordHash never crosses the wire, so a "spoke" server backed
// by RemoteStorage has no real hash to bcrypt-compare against locally — this
// endpoint runs the ENTIRE login on the "hub" server that actually has it, by
// calling the hub's own core.Login (not a parallel reimplementation of either
// the bcrypt compare or of session minting), so the per-account lockout
// gate/accounting, account-active/account-state checks, and — #508 — session
// issuance all apply IDENTICALLY regardless of which path reached them.
//
// #508: this is the atomic verify-AND-mint step. A successful, non-MFA-gated
// call mints a REAL session on the hub (via core.Login, the exact same
// function the hub's own direct /auth/login handler calls) and returns its
// token in this SAME response — never via a second, separately callable
// "create a session for this user_id" endpoint. That second-call shape is
// exactly the confused-deputy risk this design avoids: splitting verification
// from issuance would let anyone holding the RemoteStorage service credential
// mint a session for an arbitrary user without ever proving that user's real
// credentials. See internal/storage/store/remote_login_verify.go's package
// doc for the full rationale.
//
// Gated by users.write — the SAME permission CreateUser/UnlockUser already
// require of the RemoteStorage service credential (server/http/router.go) —
// deliberately not a new, separately-provisioned permission: a credential
// trusted enough to create/unlock/suspend arbitrary accounts is already
// trusted enough to check whether a password matches one, and requiring a
// fresh grant here would silently strand every existing storage.type: remote
// deployment's login until an operator noticed and granted it.
//
// The response never distinguishes WHY a check failed — wrong password, an
// active lockout, or a suspended/inactive account all produce the SAME
// generic 401 here, mirroring how /auth/login itself already collapses every
// non-MFA-required Login error to one generic message for the actual end
// user (server/http/handlers/auth.go). A compromised RemoteStorage credential
// must not be able to use this endpoint to enumerate accounts or their
// lockout state beyond "that attempt failed" — nor is any of this logged with
// per-reason detail, for the same reason. ErrMFARequired is the one
// distinguished outcome: it is still a SUCCESSFUL verification (the password
// was correct), just one core.Login itself declines to mint a session for —
// the response reports mfa_enabled/webauthn_enabled with no session, so the
// spoke's own Login can apply the identical MFA gate it always has.
func (h *UserHandler) VerifyCredentials(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		UserAgent string `json:"user_agent"`
		IPAddress string `json:"ip_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if body.Username == "" || body.Password == "" {
		sendError(w, "ValidationError", "username and password are required", http.StatusBadRequest, nil)
		return
	}
	session, u, err := h.coreService.Login(r.Context(), &core.LoginRequest{
		Username:  body.Username,
		Password:  body.Password,
		UserAgent: body.UserAgent,
		IPAddress: body.IPAddress,
	})
	if err != nil && !errors.Is(err, core.ErrMFARequired) {
		// Deliberately no log.Printf here (unlike every other handler in this
		// file): logging the real error would record which of "no such user" /
		// "wrong password" / "locked" / "not active" / "suspended" applied,
		// re-opening exactly the oracle the generic response below exists to
		// close. The audit event mirrors the real /auth/login handler's
		// LogAuthFailure exactly — username + IP, no per-reason detail — so the
		// hub's own audit trail still sees brute-force attempts proxied through
		// a spoke, without widening the oracle.
		goSafe(func() { h.coreService.LogAuthFailure(context.Background(), body.Username, body.IPAddress) })
		sendError(w, "Unauthorized", "Invalid credentials", http.StatusUnauthorized, nil)
		return
	}
	resp := map[string]interface{}{
		"id":               u.ID,
		"username":         u.Username,
		"email":            u.Email,
		"display_name":     u.DisplayName,
		"account_state":    core.NormalizeAccountState(u.AccountState),
		"mfa_enabled":      u.MFAEnabled,
		"webauthn_enabled": u.WebAuthnEnabled,
	}
	// session is nil exactly when err is ErrMFARequired (core.Login's contract) —
	// no session to report in that case; the spoke applies its own MFA gate from
	// mfa_enabled/webauthn_enabled above.
	if session != nil {
		resp["session"] = map[string]interface{}{
			"id":                  session.ID,
			"token":               session.SessionToken,
			"family_id":           session.FamilyID,
			"created_at":          session.CreatedAt,
			"expires_at":          session.ExpiresAt,
			"absolute_expires_at": session.AbsoluteExpiresAt,
		}
		// The hub's own audit trail should reflect this login exactly like a
		// direct one — best-effort, non-blocking, mirroring the real /auth/login
		// handler (server/http/handlers/auth.go).
		goSafe(func() {
			h.coreService.LogAuthLogin(context.Background(), u.ID, u.Username, body.IPAddress, body.UserAgent)
		})
	}
	sendSuccess(w, resp, "")
}

// IssueMFAChallenge handles POST /api/v1/users/{id}/mfa-challenge (#509) — the
// upstream half of the core.RemoteMFAVerifier proxy-login mechanism
// (internal/core/mfa.go), mirroring VerifyCredentials above: it exists SOLELY
// so a storage.type: remote deployment's own core.CreateMFAChallenge (called
// right after VerifyCredentials/VerifyPasswordCredentials reports MFA is
// required) can mint a challenge at all — RemoteStorage has nowhere of its own
// to persist one. It mints and persists the SAME MFAChallenge row
// core.CreateMFAChallenge always has, just on this (the hub's) LocalStorage,
// and returns only the opaque token, never any storage internals.
//
// Gated by users.write, the SAME permission verify-credentials already
// requires — see its doc above and the RemoteMFAVerifier doc for why a
// challenge alone (with no valid TOTP/recovery code to redeem it) grants
// nothing and so is not a new, weaker trust boundary.
func (h *UserHandler) IssueMFAChallenge(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	challenge, err := h.coreService.CreateMFAChallenge(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Internal", "failed to start MFA challenge", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"challenge": challenge}, "")
}

// VerifyMFACredentials handles POST /api/v1/users/verify-mfa (#509) — the
// upstream half of the core.RemoteMFAVerifier proxy-login mechanism
// (internal/core/mfa.go): checks a plaintext TOTP or recovery code against the
// real, decrypted TOTP secret this server holds and returns only a verdict,
// never the secret, so a RemoteStorage-backed "spoke" deployment (which never
// receives the secret at all) can complete a second-factor login by proxying
// the ENTIRE check here rather than reimplementing it. Calls
// core.VerifyMFACredentials directly — the SAME function the hub's own direct
// second-factor login uses — so the per-account lockout gate/accounting,
// anti-replay (MarkTOTPStepUsed), and account-active/account-state checks
// apply identically regardless of which path reached them.
//
// Gated by users.write, the SAME permission verify-credentials already
// requires. Like VerifyCredentials, the response never distinguishes WHY a
// check failed — an expired challenge, a wrong code, a tripped lockout, or a
// suspended/inactive account all produce the SAME generic 401 here, mirroring
// how /auth/mfa/verify itself already collapses every failure reason to one
// generic message for the actual end user (server/http/handlers/mfa.go). A
// compromised RemoteStorage credential must not be able to use this endpoint
// to enumerate accounts or lockout state beyond "that attempt failed" — nor is
// any of this logged with per-reason detail, for the same reason.
func (h *UserHandler) VerifyMFACredentials(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if body.Challenge == "" || body.Code == "" {
		sendError(w, "ValidationError", "challenge and code are required", http.StatusBadRequest, nil)
		return
	}
	u, usedRecovery, err := h.coreService.VerifyMFACredentials(r.Context(), body.Challenge, body.Code)
	if err != nil {
		// Deliberately no log.Printf here (see VerifyCredentials above): logging
		// the real error would re-open exactly the oracle the generic response
		// below exists to close.
		sendError(w, "Unauthorized", "Invalid code", http.StatusUnauthorized, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"id":            u.ID,
		"username":      u.Username,
		"used_recovery": usedRecovery,
	}, "")
}

// UpdateUser handles PUT /api/v1/users/{id}
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	var body struct {
		Username    *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
		Email       *string `json:"email,omitempty" validate:"omitempty,email"`
		DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
		Active      *bool   `json:"active,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.UpdateUserRequest{ID: uint(id)}
	if body.Username != nil {
		req.Username = *body.Username
	}
	if body.Email != nil {
		req.Email = *body.Email
	}
	if body.DisplayName != nil {
		req.DisplayName = *body.DisplayName
	}
	if body.Active != nil {
		req.IsActive = body.Active
	}

	updated, err := h.coreService.UpdateUser(r.Context(), req)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
			return
		}
		sendError(w, "InternalError", "Failed to update user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, userToAPIResponse(updated), i18n.T("SuccessUserUpdated", nil))
}

// DeleteUser handles DELETE /api/v1/users/{id}
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteUser(r.Context(), userCtx.UserID, uint(id)); err != nil {
		log.Printf("Error deleting user: %v", err)
		switch {
		case strings.Contains(err.Error(), "not found"):
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "last install administrator"):
			sendError(w, "Conflict", err.Error(), http.StatusConflict, nil)
		default:
			sendError(w, "InternalError", "Failed to delete user", http.StatusInternalServerError, nil)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RestoreUser handles POST /api/v1/users/{id}/restore
func (h *UserHandler) RestoreUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreUser(r.Context(), userCtx.UserID, uint(id)); err != nil {
		log.Printf("Error restoring user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found or not soft-deleted", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to restore user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, nil, "User restored successfully")
}

// UnlockUser handles POST /api/v1/users/{id}/unlock — clears a user's login-lockout
// state (failed-attempt counter + active lock) after repeated failed logins.
func (h *UserHandler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.UnlockUser(r.Context(), userCtx.UserID, uint(id)); err != nil {
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to unlock user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, nil, "User login lockout cleared")
}

// accountStateAction is the shared handler body for the admin account-state
// transitions (ADR-025). transition performs the state change.
func (h *UserHandler) accountStateAction(w http.ResponseWriter, r *http.Request, okMessage string, transition func(ctx context.Context, adminID, userID uint) error) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	// A global admin must not suspend / lock themselves out of admin access.
	if uint(id) == admin.UserID {
		sendError(w, "BadRequest", "Cannot change your own account state", http.StatusBadRequest, nil)
		return
	}
	if err := transition(r.Context(), admin.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, okMessage)
}

// SuspendUser handles POST /api/v1/users/{id}/suspend.
func (h *UserHandler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "User suspended", h.coreService.SuspendUser)
}

// ReactivateUser handles POST /api/v1/users/{id}/reactivate.
func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "User reactivated", h.coreService.ReactivateUser)
}

// RequirePasswordReset handles POST /api/v1/users/{id}/require-password-reset.
func (h *UserHandler) RequirePasswordReset(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "Password reset required", h.coreService.RequirePasswordReset)
}

// RevokeSessions handles POST /api/v1/users/{id}/revoke-sessions — admin force-logout:
// terminate all of the user's active sessions without changing their account state
// (e.g. suspected token/session theft). Scoped users.write is enforced by the router.
func (h *UserHandler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	// Mirrors accountStateAction's self-action guard (line 367): an admin must not be
	// able to revoke their own active sessions out from under themselves mid-request.
	if uint(id) == admin.UserID {
		sendError(w, "BadRequest", "Cannot revoke your own sessions", http.StatusBadRequest, nil)
		return
	}
	n, err := h.coreService.RevokeUserSessions(r.Context(), admin.UserID, uint(id))
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"revoked": n}, "Sessions revoked")
}

// ResendSetupLink handles POST /api/v1/users/{id}/resend-setup-link (ADR-028). It
// reissues the user's account_setup link (superseding any prior one) and re-delivers
// it, returning the delivery outcome — including the link itself in out-of-band mode.
func (h *UserHandler) ResendSetupLink(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	res, err := h.coreService.ResendAccountSetupLink(r.Context(), uint(id), admin.UserID)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "limit") || strings.Contains(msg, "wait"):
			status = http.StatusTooManyRequests
		case strings.Contains(msg, "base_url") || strings.Contains(msg, "suspended"):
			status = http.StatusBadRequest
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, res, "Setup link resent")
}
