package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// sendRoleScopeError answers a core role-scope refusal (core.ErrRoleScopeInvalid,
// #3546: e.g. a project-tier role granted with no project_id) with 400 and the
// refusal's client-safe message, and reports whether it did. Every grant handler
// checks it before its own error mapping, which would otherwise fall through to
// 500 for an error the caller can fix.
func sendRoleScopeError(w http.ResponseWriter, err error) bool {
	msg, ok := core.RoleScopeClientMessage(err)
	if !ok {
		return false
	}
	sendError(w, "ValidationError", msg, http.StatusBadRequest, nil)
	return true
}

// ssoRoleScopeRefusalMessage is the SSO/SAML login answer (a redirect, not a
// status) for a role-scope refusal: JIT provisioning or a group mapping named a
// role the global scope does not allow (#3546). The user cannot fix it; the
// message says who can. The config detail is in the server log and the
// startup notice, never in the redirect.
const ssoRoleScopeRefusalMessage = "Sign-in refused: this identity provider is configured to grant a role " +
	"that cannot apply install-wide. Ask your administrator to fix the provider's default_role."

// ssoRoleScopeErrorMessage reports whether err is a role-scope refusal and,
// if so, the fixed message the SSO callbacks redirect with.
func ssoRoleScopeErrorMessage(err error) (string, bool) {
	if _, ok := core.RoleScopeClientMessage(err); !ok {
		return "", false
	}
	return ssoRoleScopeRefusalMessage, true
}
