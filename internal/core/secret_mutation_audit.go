// secret_mutation_audit.go — the audit row of a secret mutation commits in the
// mutation's own transaction (AUDIT-MUTATION-TX-1).
//
// Create, update (both HTTP paths), rotate, delete (secrets and folders) and
// version rollback used to commit first and write their audit row afterwards,
// as a separate append that could only be logged when it failed (#3276 made it
// synchronous, not atomic). A database that accepted the mutation and then
// refused the audit row left a change nobody can see in the audit log.
//
// Now the row is appended through the transaction-scoped storage handle as the
// LAST statement of the mutation's transaction (the same auditInto/auditForwardSink
// pattern SuspendSecret's clear-synced-copies path and DecideAccessReviewItem use,
// audit_target.go), and a failed append is returned, so the transaction rolls
// back: the mutation and its audit row commit together or not at all. Off-box
// side effects (SIEM forward, live-tail wake-up) run only after the commit.
//
// Last on purpose. On PostgreSQL the append takes the chain's transaction-scoped
// advisory lock (local_audit_chain.go), which is then held until this
// transaction commits — that is what makes chain order equal commit order for a
// row written inside a business transaction — so nothing may run between the
// append and the COMMIT. On SQLite every transaction is BEGIN IMMEDIATE, so the
// writer lock is held from the first statement and the chain head read inside
// the append is already the committed head.
//
// Durability: the transaction-scoped store never inherits auditSkipDurableSync
// (local_transaction.go), so audit_durability=standard never relaxes the commit
// of a transaction that carries a secret mutation (ADR-112 Amendment 3).
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretMutationAudit is the attribution a transport attaches to a request
// context (WithSecretMutationAudit) so the core mutation's in-transaction audit
// row names the caller, their IP and user agent. A mutation called without it
// still writes that row (AUDIT-FAILCLOSED-SECRETS-1, #4719): core derives it from
// the attribution the call itself carries (defaultSecretMutationAudit: the
// rotation's actor and rotatedBy label, a bulk operation's actor), or as
// "system" when there is none. No caller can commit a secret mutation without
// its row by forgetting the tag.
type SecretMutationAudit struct {
	UserID    uint
	Username  string
	IP        string
	UserAgent string
	// ClientOrigin is the raw ClientOriginHeader value, recorded as a labelled
	// client-asserted note on the mutation's own row only (#2545).
	ClientOrigin string
}

type secretMutationAuditKey struct{}

// WithSecretMutationAudit tags ctx so the secret mutation it is passed to
// writes its audit row in the same transaction as the change.
func WithSecretMutationAudit(ctx context.Context, a SecretMutationAudit) context.Context {
	return context.WithValue(ctx, secretMutationAuditKey{}, a)
}

func secretMutationAuditFromContext(ctx context.Context) (SecretMutationAudit, bool) {
	a, ok := ctx.Value(secretMutationAuditKey{}).(SecretMutationAudit)
	return a, ok
}

// untaggedSecretMutationActor is the username on the row of a mutation whose
// context carries no attribution at all.
const untaggedSecretMutationActor = "system"

// defaultSecretMutationAudit tags ctx with a unless it already carries a
// transport's attribution, which always wins (it has the request's IP and user
// agent). Internal callers that know their actor (bulk operations, copy, the
// rotation scheduler) use it so the row core writes names that actor.
func defaultSecretMutationAudit(ctx context.Context, a SecretMutationAudit) context.Context {
	if _, ok := secretMutationAuditFromContext(ctx); ok {
		return ctx
	}
	return WithSecretMutationAudit(ctx, a)
}

// ErrSecretMutationAuditUnavailable: the mutation's audit row could not be
// written, so the transaction rolled back and nothing was changed.
var ErrSecretMutationAuditUnavailable = errors.New("could not record the change in the audit log; nothing was changed, retry")

// mutationAuditRow is one secret mutation's audit row plus its
// secret_access_logs row.
type mutationAuditRow struct {
	eventType    string
	userID       *uint
	secretID     uint
	projectID    uint
	username     string
	ip           string
	userAgent    string
	clientOrigin string
	description  string
	diff         string
	// accessAction is the secret_access_logs action ("create", "update",
	// "rotate", "delete"); "" writes no access-log row.
	accessAction string
}

// mutationAuditRowFor builds the in-transaction row of a secret mutation. It is
// always built: an untagged ctx is attributed to "system" (see
// SecretMutationAudit). A zero UserID records no user id rather than user 0.
func mutationAuditRowFor(ctx context.Context, eventType, accessAction, verb string, secretID, projectID uint, secretName string) mutationAuditRow {
	a, ok := secretMutationAuditFromContext(ctx)
	if !ok {
		a = SecretMutationAudit{Username: untaggedSecretMutationActor}
	}
	var userID *uint
	if a.UserID != 0 {
		uid := a.UserID
		userID = &uid
	}
	return mutationAuditRow{
		eventType:    eventType,
		userID:       userID,
		secretID:     secretID,
		projectID:    projectID,
		username:     a.Username,
		ip:           a.IP,
		userAgent:    a.UserAgent,
		clientOrigin: a.ClientOrigin,
		description:  fmt.Sprintf("User %s %s secret %s", a.Username, verb, secretName),
		accessAction: accessAction,
	}
}

// writeSecretFieldsAudited writes fields onto secret id and row in ONE
// transaction, row last (writeMutationAuditTx), and runs the row's off-box side
// effects after the commit. matched is false (and nothing is written) when the
// secret is gone. For the single-column secret updates (classify, rename, extend,
// move) that used to commit first and audit afterwards (#4719).
func (c *KeyorixCore) writeSecretFieldsAudited(ctx context.Context, id uint, fields storage.SecretFieldUpdate, row mutationAuditRow) (matched bool, err error) {
	sink := &auditForwardSink{}
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		m, uerr := tx.UpdateSecretFields(ctx, id, fields)
		if uerr != nil || !m {
			return uerr
		}
		matched = true
		return c.writeMutationAuditTx(ctx, tx, sink, row)
	}); err != nil {
		return false, err
	}
	sink.Flush(c)
	return matched, nil
}

// writeMutationAuditTx appends row through tx (the mutation's transaction) and
// returns ErrSecretMutationAuditUnavailable when it cannot, so the caller's
// transaction rolls back. A panic is turned into the same error: the mutation
// has not committed yet, so failing closed loses nothing. The event is queued
// on sink for its off-box side effects; flush the sink only after the commit.
func (c *KeyorixCore) writeMutationAuditTx(ctx context.Context, tx storage.Storage, sink *auditForwardSink, row mutationAuditRow) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SECURITY: audit event %q for secret %d panicked inside its mutation's transaction: %v -- failing closed, mutation rolled back", row.eventType, row.secretID, r)
			err = fmt.Errorf("%w: audit write panicked: %v", ErrSecretMutationAuditUnavailable, r)
		}
	}()
	t := true
	sid, pid := row.secretID, row.projectID
	now := time.Now()
	event := &models.AuditEvent{
		EventType:    row.eventType,
		UserID:       row.userID,
		SecretNodeID: &sid,
		ProjectID:    &pid,
		IPAddress:    row.ip,
		Description:  withClientOriginNote(WithClientOrigin(ctx, row.clientOrigin), sanitizeAuditText(row.description)),
		Success:      &t,
		EventTime:    now,
		Diff:         row.diff,
		ActorType:    actorTypeFromContext(ctx),
	}
	if adminID, ok := impersonatorFromContext(ctx); ok {
		a := adminID
		event.ImpersonatedBy = &a
		event.ActingAs = row.userID
		event.Impersonation = true
	}
	prepareAuditEventForEmit(ctx, event)
	var accessLog *models.SecretAccessLog
	if row.accessAction != "" {
		accessLog = &models.SecretAccessLog{
			SecretNodeID: row.secretID,
			AccessedBy:   row.username,
			AccessTime:   now,
			Action:       row.accessAction,
			IPAddress:    row.ip,
			UserAgent:    row.userAgent,
		}
	}
	if werr := tx.LogAuditEventWithAccessLog(ctx, event, accessLog); werr != nil {
		log.Printf("SECURITY: failed to persist audit event %q for secret %d inside its mutation's transaction: %v -- failing closed, mutation rolled back", row.eventType, row.secretID, werr)
		return fmt.Errorf("%w: %v", ErrSecretMutationAuditUnavailable, werr)
	}
	sink.persisted = append(sink.persisted, event)
	return nil
}
