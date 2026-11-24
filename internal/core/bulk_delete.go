// bulk_delete.go — bulk deletion of secrets in a single call. Each deletion
// calls the same logic as single-secret delete (audit log, dependency events,
// ACL cleanup, etc.) rather than bypassing with a raw DB delete. Partial
// success is allowed — individual failures are collected in Failed.
// Project-scoped (route-gated secrets.delete). Parallels bulk-rename / extend-expiring.
package core

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// BulkDeleteRequest carries the set of secret node IDs to delete.
type BulkDeleteRequest struct {
	SecretIDs []uint `json:"secret_ids"`
}

// maxBulkDeleteBatchSize bounds how many secret IDs a single bulk-delete call
// accepts — each ID does a per-item storage round trip (GetSecret + DeleteSecret),
// so an unbounded list is a per-request resource-exhaustion vector (#G44), the
// same class of bug as maxBulkAccessRequestBatchSize (bulk_access_requests.go).
const maxBulkDeleteBatchSize = 500

// Stable machine-readable codes of a retryable bulk item, the same words the single
// delete answers with (the envelope "error" of its 503). Clients branch on the code,
// never on the message.
const (
	BulkErrCodeAuditUnavailable   = "audit_unavailable"
	BulkErrCodeStorageUnavailable = "storage_unavailable"
)

// BulkOpError captures why a single secret in a bulk operation could not be processed.
// Code and Retryable are set only for an outage (audit log or storage): nothing was
// changed for that item and the same call can be repeated. A real refusal or a missing
// secret carries neither.
type BulkOpError struct {
	SecretID  uint   `json:"secret_id"`
	Name      string `json:"name,omitempty"`
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
}

// BulkDeleteResult reports outcome counts and per-secret failures. Retryable is how
// many of Failed are retryable outages, so a caller can tell "retry these" from "these
// will never succeed" without walking the list.
type BulkDeleteResult struct {
	Deleted   []uint        `json:"deleted"`
	Failed    []BulkOpError `json:"failed"`
	Total     int           `json:"total"`
	Retryable int           `json:"retryable"`
}

// addFailure records a failed item and counts it when it is a retryable outage.
func (r *BulkDeleteResult) addFailure(e BulkOpError) {
	if e.Retryable {
		r.Retryable++
	}
	r.Failed = append(r.Failed, e)
}

// BulkDeleteSecrets deletes multiple secrets by ID within a project.
// Partial success is allowed — individual failures are collected in Failed.
// Each secret is fetched and deleted via the SAME authorization-checked path the
// singular delete endpoint uses (GetSecretWithPermissionCheck /
// DeleteSecretWithPermissionCheck) — not a raw, unauthorized GetSecret/DeleteSecret
// loop over caller-supplied IDs — so audit logging, dependency-invalidation events,
// and per-secret authorization (ACL/ownership, not just the coarse project check
// below) are all applied consistently with the single-secret path (#G31). Before
// any item, core decides the route gate itself: secrets.delete at projectID
// (requireScopedGate, #4666); the per-item checks run on top of it.
//
// projectID gates a mandatory cross-project guard: a secret belonging to a
// different project is rejected even if the caller holds a token with broad
// permissions. Unlike the prior version, projectID == 0 is refused outright rather
// than silently disabling the guard — a bulk delete must always be scoped to a
// real project. A secret outside the caller's project or authorization is reported
// identically to a nonexistent one ("secret not found"), never disclosing its name —
// the caller has no right to learn that ANOTHER tenant's secret exists at all.
// deletedBy is the authenticated username used in the audit trail.
func (c *KeyorixCore) BulkDeleteSecrets(ctx context.Context, req BulkDeleteRequest, projectID uint, deletedBy string, actorID uint, ip, ua string) (*BulkDeleteResult, error) {
	if len(req.SecretIDs) == 0 {
		return nil, fmt.Errorf("at least one secret ID is required")
	}
	if len(req.SecretIDs) > maxBulkDeleteBatchSize {
		return nil, fmt.Errorf("secret_ids exceeds the maximum batch size of %d", maxBulkDeleteBatchSize)
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}
	// The route gate, decided in core (#4666, as the other project-wide bulk ops):
	// secrets.delete at the project, before any secret is read. The per-item checks
	// below decide at each secret's own scope, so a role held only in one
	// environment passed them while the route gate refused it. A machine is decided
	// on its machine roles; actorID 0 with no machine tag stays exempt (gateActor).
	// A refusal deletes nothing.
	if err := c.requireScopedGate(ctx, actorID, permSecretsDelete, Scope{ProjectID: projectID}); err != nil {
		return nil, err
	}

	result := &BulkDeleteResult{
		Deleted: make([]uint, 0, len(req.SecretIDs)),
		Failed:  make([]BulkOpError, 0),
		Total:   len(req.SecretIDs),
	}

	for _, id := range req.SecretIDs {
		if id == 0 {
			result.Failed = append(result.Failed, BulkOpError{
				SecretID: 0,
				Error:    "secret ID must be non-zero",
			})
			continue
		}
		c.bulkDeleteOneSecret(ctx, id, projectID, deletedBy, actorID, ip, ua, result)
	}

	return result, nil
}

// bulkDeleteOneSecret processes a single secret within BulkDeleteSecrets'
// loop, appending its outcome to result. Wrapped in its own recover: without
// it, a panic anywhere in this item's authorization/delete chain — including
// the per-secret authz check itself (#G31) — unwinds past BulkDeleteSecrets
// entirely, reaching only the transport layer's Recovery middleware, which
// reports the WHOLE request as failed even though EARLIER loop iterations'
// deletes already committed — directly contradicting this file's own
// documented "Partial success is allowed" design. Same "best-effort helper,
// primary operation already succeeded" shape as evictUserSessionCache
// (account.go), scoped here to "the operation already succeeded for earlier
// items in this batch."
func (c *KeyorixCore) bulkDeleteOneSecret(ctx context.Context, id, projectID uint, deletedBy string, actorID uint, ip, ua string, result *BulkDeleteResult) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: BulkDeleteSecrets panicked processing secret %d (earlier items in this batch, if any, already committed): %v", id, r)
			result.Failed = append(result.Failed, BulkOpError{SecretID: id, Error: "internal error"})
		}
	}()

	// Per-secret authorization + fetch — the same check the singular delete
	// endpoint runs (secrets_crud.go's DeleteSecret handler). A secret the
	// caller cannot read (wrong project, no ACL/ownership grant, or genuinely
	// absent) is reported identically as "secret not found": its name must
	// never leak to a caller who was never authorized to see it.
	//
	// Three callers, told apart by actorID and the actor type on ctx:
	//   - an authenticated user (actorID != 0, secrets_bulk_delete.go's handler
	//     passes userCtx.UserID): the per-user owner/share/role check of the
	//     singular delete (GetSecretWithPermissionCheck /
	//     DeleteSecretWithPermissionCheck);
	//   - a machine token (actorID 0, ctx tagged ActorTypeMachine by the auth
	//     middleware, its UserID is always 0): the rule the singular DELETE route
	//     applies to a machine, secrets.delete at the secret's own scope
	//     (RequireScopedSecretPermission, AuthorizeSecretPrincipalForSecret), so a
	//     machine deletes in bulk only what it may delete one by one (#4546). A
	//     machine tag without a machine ID is refused (fail closed);
	//   - actorID 0 with no machine tag: an in-process caller with no
	//     authenticated principal (embedded/local mode, which has no RBAC concept
	//     at all; physical access to the local DB file is the boundary there),
	//     using the bare GetSecret/DeleteSecret as the singular local delete does.
	//
	// A storage FAULT is not a "not found": the item is reported as "storage
	// temporarily unavailable, please retry" (distinct text), because the
	// operator would otherwise read a transient outage as "already gone" and not
	// retry. Probed on the plain read first since the authorization-checked
	// fetches below fold every failure into the uniform denial.
	if ferr := c.secretReadFault(ctx, id); ferr != nil {
		log.Printf("bulk delete: secret %d not processed, storage read failed: %s", id, StorageReadFaultDetail(ferr))
		result.addFailure(BulkOpError{SecretID: id, Error: StorageReadUnavailableMessage, Code: BulkErrCodeStorageUnavailable, Retryable: true})
		return
	}
	machine := actorID == 0 && actorTypeFromContext(ctx) == ActorTypeMachine
	var secret *models.SecretNode
	var err error
	switch {
	case machine:
		secret, err = c.bulkDeleteMachineSecret(ctx, id)
	case actorID == 0:
		secret, err = c.GetSecret(ctx, id)
	default:
		secret, err = c.GetSecretWithPermissionCheck(ctx, id, actorID)
	}
	if IsStorageReadUnavailable(err) {
		// A storage fault on any lookup in the switch above (the machine's role read
		// in bulkDeleteMachineSecret, GetSecret, or the user's permission-checked
		// read) is the same "retry" answer as the secret-read fault above, not a
		// "not found".
		result.addFailure(BulkOpError{SecretID: id, Error: StorageReadUnavailableMessage, Code: BulkErrCodeStorageUnavailable, Retryable: true})
		return
	}
	if err != nil || secret == nil || secret.ProjectID != projectID {
		result.Failed = append(result.Failed, BulkOpError{
			SecretID: id,
			Error:    "secret not found",
		})
		return
	}

	secretName := secret.Name
	secretProjectID := secret.ProjectID

	if actorID == 0 { // a machine was authorized for this secret above
		err = c.DeleteSecret(ctx, id)
	} else {
		err = c.DeleteSecretWithPermissionCheck(ctx, id, actorID)
	}
	if err != nil {
		// The client gets one fixed class, never err.Error(): on a storage failure
		// that is driver text naming tables and columns (STORAGE-ERR-CLASS-3).
		log.Printf("bulk delete: secret %d not deleted: %s", id, StorageReadFaultDetail(err))
		msg, code := bulkDeleteFailure(ctx, err)
		result.addFailure(BulkOpError{
			SecretID:  id,
			Name:      secretName,
			Error:     msg,
			Code:      code,
			Retryable: code != "",
		})
		return
	}

	// Audit: same event shape as the single-delete handler's post-delete log.
	// #1600: this used to fire in a detached, un-awaited goroutine
	// (`go func(...) { ... }(...)`)  — safe in server/HTTP callers (a
	// long-lived process, so DetachedAuditContext's whole point — surviving
	// the REQUEST's context cancellation — still lets the goroutine finish
	// naturally) but not in the CLI's embedded-mode caller
	// (runBulkDeleteEmbedded, internal/cli/secret/bulk_delete.go): a CLI
	// invocation is a short-lived PROCESS, and Go does not wait for orphaned
	// goroutines when main() returns — BulkDeleteSecrets could return, the
	// command print its results, and the process exit before this goroutine
	// ever ran, silently dropping the secret_access_logs write (and,
	// separately, the loud "SECURITY: failed to persist secret access log"
	// line writeAccessLog emits on failure — see audit.go) with no trace at
	// all, under ANY storage backend, not just storage.type: remote. Calling
	// synchronously (still via DetachedAuditContext, so a caller-context
	// cancellation mid-batch can't truncate later items' audit writes)
	// guarantees the write is attempted, and any failure logged, before this
	// function can return.
	//
	// A context tagged with WithSecretMutationAudit (the HTTP handler's) already committed
	// the secret.deleted row and its access-log row inside the delete's transaction, so
	// the post-commit pair would be a second copy of the same event.
	if _, tagged := secretMutationAuditFromContext(ctx); !tagged {
		auditCtx := DetachedAuditContext(ctx)
		c.LogSecretDeletedWithProject(auditCtx, actorID, id, secretProjectID, deletedBy, secretName, ip, ua)
	}

	result.Deleted = append(result.Deleted, id)
}

// bulkDeleteFailureMessage classifies a failed per-item delete into the fixed text
// reported in BulkDeleteResult.Failed: a permission refusal, a positive not-found (the
// secret went away after it was read), an audit-log outage (retry), a storage outage
// (retry), or anything else.
func bulkDeleteFailureMessage(ctx context.Context, err error) string {
	msg, _ := bulkDeleteFailure(ctx, err)
	return msg
}

// bulkDeleteFailure is bulkDeleteFailureMessage plus the stable code of a retryable
// outage (BulkErrCodeAuditUnavailable / BulkErrCodeStorageUnavailable); the code is ""
// for every class that retrying cannot fix.
func bulkDeleteFailure(ctx context.Context, err error) (msg, code string) {
	switch {
	case errors.Is(err, ErrPermissionDenied):
		return "permission denied", ""
	case errors.Is(err, ErrSecretMutationAuditUnavailable), errors.Is(err, ErrMutationAuditUnavailable):
		// Same sentence REST and the other mutation endpoints send; the delete was rolled
		// back with its audit row, so the item can be retried.
		return MutationAuditUnavailableMessage, BulkErrCodeAuditUnavailable
	case isPositiveNotFound(err):
		return "secret not found", ""
	case IsStorageReadUnavailable(err) || IsAuthorizeTransient(ctx, err):
		return StorageReadUnavailableMessage, BulkErrCodeStorageUnavailable
	default:
		return "internal error", ""
	}
}

// bulkDeleteMachineSecret fetches secret id for a machine caller of BulkDeleteSecrets
// and authorizes it the way the singular DELETE route does: secrets.delete at the
// secret's own project and environment for the machine identity tagged on ctx
// (AuthorizeSecretPrincipalForSecret, the decision RequireScopedSecretPermission
// makes). Shares, ACLs and ownership are user-only and never apply to a machine.
// A missing machine ID, a refusal and a failed authorization lookup are all errors
// (fail closed). The caller reports a refusal as "secret not found", as it does a
// user's refusal, and a lookup fault (returned wrapped in ErrStorageReadUnavailable)
// as the retryable "storage temporarily unavailable".
func (c *KeyorixCore) bulkDeleteMachineSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	machineID, ok := machineActorFromContext(ctx)
	if !ok {
		return nil, permissionDeniedf("%s: machine caller without a machine identity", i18n.T("ErrorPermissionDenied", nil))
	}
	secret, err := c.GetSecret(ctx, id)
	if err != nil || secret == nil {
		return nil, cmp.Or(err, errSecretNotFoundText())
	}
	allowed, err := c.AuthorizeSecretPrincipalForSecret(ctx, ActorTypeMachine, machineID, secret, "secrets.delete")
	if err != nil {
		log.Printf("bulk delete: secret %d not processed, machine %d authorization lookup failed: %v", id, machineID, err)
		if errors.Is(err, errNoPrincipalPermission) {
			return nil, err // a storage contract violation, not an outage
		}
		return nil, cmp.Or(ReadFault(err), err)
	}
	if !allowed {
		return nil, permissionDeniedf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
	}
	return secret, nil
}
