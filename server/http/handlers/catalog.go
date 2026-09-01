package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// actorID returns the acting user's ID from the request context (0 when absent).
//
// actorID(r)==0 is ambiguous by construction: it means EITHER no request
// context at all (a true local/embedded call — see isMachineActor's doc
// comment) OR a machine-authenticated request (a machine identity has no
// UserID). A caller whose ceiling check treats actorID==0 as "trusted, skip
// the check" — rather than letting it flow through and fail closed like an
// ordinary unauthorized actor would — is silently trusting every machine
// credential too. Check isMachineActor(r) explicitly wherever that
// distinction matters (see #1524).
func actorID(r *http.Request) uint {
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		return u.UserID
	}
	return 0
}

// isMachineActor reports whether the request's authenticated principal is a
// machine identity (any type, including a node credential) rather than a
// user or a true unauthenticated/embedded call. Unlike actorID(r), this
// distinguishes "no context at all" (nil UserContext — an in-process/local
// caller, e.g. the CLI's embedded LocalStorage path) from "authenticated as
// a machine" (non-nil UserContext with ActorType machine_identity,
// UserID==0) — the two cases actorID(r) alone cannot tell apart. #1524: a
// per-actor ceiling check that only tests `actorID != 0` treats both the
// same, silently trusting a machine credential the way it was only ever
// meant to trust a genuinely-local call.
func isMachineActor(r *http.Request) bool {
	u := middleware.GetUserFromContext(r.Context())
	return u != nil && u.ActorKind() == core.ActorTypeMachine
}

// machineID returns the acting machine identity's ID (0 for a human actor or
// no request context), for threading into a *MachineIdentityID attribution
// companion parameter (#1573) alongside actorID(r). Unlike actorID(r), which
// is always 0 for a machine caller (ADR-030, no UserID), this carries WHICH
// machine, so a model's actor-attribution field is not left unattributed.
func machineID(r *http.Request) uint {
	u := middleware.GetUserFromContext(r.Context())
	if u != nil && u.MachineIdentityID != nil {
		return *u.MachineIdentityID
	}
	return 0
}

// isNodeCredentialRequest is REMOVED (ADR-085, Accepted, 2026-08-25). It used
// to report whether a request authenticated with a genuine MachineTypeNode
// credential, so a handful of /system handlers could trust that call
// unconditionally on the theory that a node relays an already-authorized
// downstream decision. ADR-085 found that "downstream node relay" topology
// cannot exist in this codebase (ADR-083's validateRemoteStorageNotServer
// rejects storage.type: remote for any server process) and a liveness sweep
// found no live caller for the exemption at all — every former call site
// (AssignRoleWithExpiryProxy, RemoveGlobalAdminRoleGuardedProxy,
// CreateMachineIdentityCredentialProxy, CreateOIDCBindingProxy,
// DeleteOIDCBindingProxy, CreateSetupTokenProxy,
// RevokeAllPersonalAccessTokensForUserProxy, DeleteSessionsForUserExceptProxy)
// now runs its real ceiling check unconditionally, for every caller. The
// MachineTypeNode identity type itself is RETAINED (a node credential simply
// carries no more authority than any other machine identity now).

// CatalogHandler handles project and environment endpoints.
type CatalogHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewCatalogHandler creates a new CatalogHandler.
func NewCatalogHandler(svc *core.KeyorixCore) *CatalogHandler {
	return &CatalogHandler{coreService: svc, validator: validation.NewValidator()}
}

// ListProjects handles GET /api/v1/projects — returns projects with secret and
// environment counts. Pass ?include_deleted=true to also return soft-deleted
// projects (flagged via the deleted/deleted_at fields) for the restore UI.
func (h *CatalogHandler) ListProjects(w http.ResponseWriter, r *http.Request) {
	includeDeleted := r.URL.Query().Get("include_deleted") == "true"
	projects, err := h.coreService.ListProjectsWithCounts(r.Context(), includeDeleted)
	if err != nil {
		log.Printf("Error listing projects: %v", err)
		sendError(w, "Failed to list projects", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"projects": projects}, "")
}

// RestoreProject handles POST /api/v1/projects/{id}/restore
func (h *CatalogHandler) RestoreProject(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	if err := h.coreService.RestoreProject(r.Context(), actorID(r), id); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error restoring project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Project restored")
}

// GetProject handles GET /api/v1/projects/:id
func (h *CatalogHandler) GetProject(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	project, err := h.coreService.GetProject(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", "Project not found", http.StatusNotFound, nil)
			return
		}
		log.Printf("Error getting project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, project, "")
}

// GetProjectDrift handles GET /api/v1/projects/{id}/drift — the
// cross-environment drift report for the project (keys missing in some
// environments, or present everywhere with diverging settings).
func (h *CatalogHandler) GetProjectDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	report, err := h.coreService.DetectProjectDrift(r.Context(), id)
	if err != nil {
		sendError(w, "InternalError", "Failed to compute drift", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, report, "")
}

// CreateProject handles POST /api/v1/projects
func (h *CatalogHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		// #189: a Project name is a plain human-readable identifier (no existing
		// naming-policy mechanism, unlike SecretNode.Name's dedicated conformance
		// check), and it's routinely shown to higher-trust approvers in access-review
		// UIs, audit logs, and CLI confirmation prompts — so it's restricted to the
		// `identifier` charset (letters/digits/space/`-`/`_`) to block zero-width,
		// RTL-override, and homograph-lookalike characters that could otherwise make
		// a malicious project visually indistinguishable from a legitimate one.
		Name        string `json:"name" validate:"required,max=200,identifier"`
		Description string `json:"description"`
		// Environments, when non-empty, seeds the project with exactly these
		// environments instead of the default development/staging/production set —
		// one call for infrastructure-as-code provisioning. Blank entries are dropped.
		Environments []string `json:"environments"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	envs := make([]string, 0, len(body.Environments))
	for _, e := range body.Environments {
		if e = strings.TrimSpace(e); e != "" {
			envs = append(envs, e)
		}
	}

	var project *models.Project
	var err error
	if len(envs) > 0 {
		project, err = h.coreService.CreateProjectWithEnvs(r.Context(), body.Name, body.Description, envs)
	} else {
		project, err = h.coreService.CreateProject(r.Context(), body.Name, body.Description)
	}
	if err != nil {
		log.Printf("Error creating project: %v", err)
		switch {
		case strings.Contains(err.Error(), "already exists"):
			sendError(w, "ConflictError", "A project with that name already exists", http.StatusConflict, nil)
		case strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)):
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, project, "Project created")
}

// ListEnvironments handles GET /api/v1/environments (global, for backward compat)
func (h *CatalogHandler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	environments, err := h.coreService.ListEnvironments(r.Context())
	if err != nil {
		log.Printf("Error listing environments: %v", err)
		sendError(w, "Failed to list environments", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"environments": environments}, "")
}

// UpdateProject handles PUT /api/v1/projects/:id
func (h *CatalogHandler) UpdateProject(w http.ResponseWriter, r *http.Request) {
	id, ok := mustParseProjectID(w, r)
	if !ok {
		return
	}
	var body struct {
		// See CreateProject's Name field comment for why `identifier` is applied here.
		Name        string `json:"name" validate:"required,max=200,identifier"`
		Description string `json:"description"`
		RequireMFA  *bool  `json:"require_mfa"`
	}
	if !mustDecodeBody(w, r, &body) {
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	// require_mfa is a per-project SECURITY-POLICY control (ADR-037), not ordinary content.
	// The route gate only proves secrets.write — held by the non-admin editor persona — so
	// changing it must additionally require roles.assign at the project (the admin/membership
	// tier), otherwise a developer could silently disable the project's MFA enforcement.
	// name/description stay on the secrets.write gate.
	if body.RequireMFA != nil {
		actor, ok := mustGetUser(w, r)
		if !ok {
			return
		}
		if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), actor.ActorKind(), actor.PrincipalID(), "roles.assign", core.Scope{ProjectID: id}); aerr != nil || !ok {
			sendError(w, "Forbidden", "changing a project's MFA requirement requires the roles.assign permission", http.StatusForbidden, nil)
			return
		}
	}
	project, err := h.coreService.UpdateProject(r.Context(), id, body.Name, body.Description, body.RequireMFA)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "name is required"), strings.Contains(msg, "exceeds"):
			status = http.StatusBadRequest
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		default:
			log.Printf("Error updating project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, project, "Project updated")
}

// DeleteProject handles DELETE /api/v1/projects/:id
// Accepts ?force=true to cascade-delete even when the project contains secrets.
func (h *CatalogHandler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	force := r.URL.Query().Get("force") == "true"
	if err := h.coreService.DeleteProject(r.Context(), uint(id), force); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, "secret(s)") {
			status = http.StatusConflict
		} else {
			log.Printf("Error deleting project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Project deleted")
}

// CreateProjectEnvironment handles POST /api/v1/projects/:id/environments
func (h *CatalogHandler) CreateProjectEnvironment(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	if body.Name == "" {
		sendError(w, "ValidationError", "Environment name is required", http.StatusBadRequest, nil)
		return
	}
	// The scope check resolves the project id from the URL without verifying it exists,
	// so confirm the parent project is live before creating an environment under it —
	// otherwise a caller who held write on a since-deleted project could re-establish a
	// usable scope under it (GetProject excludes soft-deleted projects).
	if _, perr := h.coreService.Storage().GetProject(r.Context(), uint(id)); perr != nil {
		sendError(w, "NotFound", "Project not found", http.StatusNotFound, nil)
		return
	}
	env, err := h.coreService.CreateEnvironment(r.Context(), uint(id), body.Name)
	if err != nil {
		log.Printf("Error creating environment for project %d: %v", id, err)
		if strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
			sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
			return
		}
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, env, "Environment created")
}

// DeleteEnvironment handles DELETE /api/v1/environments/:id
func (h *CatalogHandler) DeleteEnvironment(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid environment ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteEnvironment(r.Context(), uint(id)); err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "active secret"):
			status = http.StatusConflict
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		default:
			log.Printf("Error deleting environment %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Environment deleted")
}

// ListProjectEnvironments handles GET /api/v1/projects/:id/environments.
// Pass ?include_deleted=true to also return soft-deleted environments.
func (h *CatalogHandler) ListProjectEnvironments(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	var environments []*models.Environment
	if r.URL.Query().Get("include_deleted") == "true" {
		environments, err = h.coreService.ListEnvironmentsByProjectIncludingDeleted(r.Context(), uint(id))
	} else {
		environments, err = h.coreService.ListEnvironmentsByProject(r.Context(), uint(id))
	}
	if err != nil {
		log.Printf("Error listing environments for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"environments": environments}, "")
}

// CloneEnvironment handles POST /api/v1/projects/{id}/environments/{envId}/clone
// Body: {"destination_environment_id": N}
// Copies all active secrets from {envId} into the destination environment (same project).
// Secrets already present by name in the destination are skipped.
func (h *CatalogHandler) CloneEnvironment(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "BadRequest", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	srcEnvID, err := strconv.ParseUint(chi.URLParam(r, "envId"), 10, 32)
	if err != nil {
		sendError(w, "BadRequest", errInvalidEnvironmentID, http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		DestinationEnvironmentID uint `json:"destination_environment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.DestinationEnvironmentID == 0 {
		sendError(w, "BadRequest", "destination_environment_id is required", http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.CloneEnvironment(r.Context(), uint(projectID), uint(srcEnvID), reqBody.DestinationEnvironmentID, userCtx.Username, userCtx.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, "must ") || strings.Contains(msg, "required") ||
			strings.Contains(msg, "belong") || strings.Contains(msg, "validation") {
			status = http.StatusBadRequest
		} else if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error cloning environment in project %d: %v", projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, result, "")
}

// RestoreEnvironment handles POST /api/v1/projects/{projectId}/environments/{id}/restore.
// Nested under the project so the permission scope resolves from the project ID
// (the environment row itself is soft-deleted and not loadable by the scope check).
func (h *CatalogHandler) RestoreEnvironment(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "projectId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid environment ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreEnvironment(r.Context(), actorID(r), uint(projectID), uint(id)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errNotFound) {
			status = http.StatusNotFound
		} else {
			log.Printf("Error restoring environment %d in project %d: %v", id, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Environment restored")
}
