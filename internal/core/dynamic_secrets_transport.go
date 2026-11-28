package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The operator's transport policy (dynamic_secrets.insecure_allow_plaintext_dynamic_
// secret_transport) for postgres and mysql admin_dsns (#4374): a connection that
// does not verify the server certificate is refused unless the operator allowed
// insecure transport. The engine decides from the parsed driver config
// (ports.DynamicAdminDSNTransportInspector); core applies it where the admin gets
// the answer at once (save) and records every issue that goes through a weak one.
// The engine checks the same config again when it connects.

// adminDSNTransportWeakness asks engine whether adminDSN connects without verifying
// the server certificate. nil for an engine with no such setting.
func adminDSNTransportWeakness(engine ports.DynamicBackendEngine, adminDSN string) *dsn.TransportWeakness {
	if inspector, ok := engine.(ports.DynamicAdminDSNTransportInspector); ok {
		return inspector.AdminDSNTransportWeakness(adminDSN)
	}
	return nil
}

// checkAdminDSNTransportOnSave refuses a new or replacing admin_dsn whose connection
// does not verify the server certificate, whatever dsn.StoredSQLTransportGrace says
// (the soft period is for DSNs stored before the upgrade only). With the operator's
// flag it returns the weakness so the caller audits the save.
func (c *KeyorixCore) checkAdminDSNTransportOnSave(backendType, adminDSN string) (*dsn.TransportWeakness, error) {
	engine, err := c.dynamicEngine(backendType)
	if err != nil {
		return nil, err
	}
	w := adminDSNTransportWeakness(engine, adminDSN)
	if w == nil {
		return nil, nil
	}
	if !c.dynamicAllowInsecureTransport {
		return nil, w.Refusal()
	}
	return w, nil
}

// auditAdminDSNTransportAllowedOnSave records that a saved admin_dsn does not
// verify the server certificate and was accepted under the operator's flag. It
// names the config, backend and option, never the DSN.
func (c *KeyorixCore) auditAdminDSNTransportAllowedOnSave(ctx context.Context, actorID uint, cfg *models.DynamicSecretConfig, w *dsn.TransportWeakness) {
	if w == nil {
		return
	}
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_secret.config_insecure_transport", &actorID, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %d %q (%s) saved with admin_dsn option %s: %s; allowed by %s",
			cfg.ID, cfg.Name, w.Backend, w.Option, w.Effect(), dsn.TransportPolicyKey))
}

// checkAdminDSNTransportOnIssue runs before every issue. A weak stored admin_dsn
// is refused unless the operator's flag is set or the soft period holds
// (dsn.StoredSQLTransportGrace); when it is let through, every issue writes an
// audit event naming the config and option (the engine logs the WARNING when it
// connects). That event is the only record that a credential was issued over a
// connection that does not verify the server, so it fails closed like
// dynamic_lease.issued (#4716): it runs before engine.Issue, and if it was not
// committed the issue is refused with ErrMutationAuditUnavailable before anything
// is minted (AUDIT-DISCLOSURE-NOV-1).
func (c *KeyorixCore) checkAdminDSNTransportOnIssue(ctx context.Context, engine ports.DynamicBackendEngine, cfg *models.DynamicSecretConfig, adminDSN string, userID uint) error {
	w := adminDSNTransportWeakness(engine, adminDSN)
	if w == nil {
		return nil
	}
	grace := dsn.StoredSQLTransportGrace && !c.dynamicSQLTransportGraceEnded
	if !c.dynamicAllowInsecureTransport && !grace {
		return w.Refusal()
	}
	why := "allowed by " + dsn.TransportPolicyKey
	if !c.dynamicAllowInsecureTransport {
		why = "accepted only during the upgrade grace period, refused from the next release: set sslmode=verify-full (postgres) or tls=true (mysql), or the operator flag " + dsn.TransportPolicyKey
	}
	uid, pid := userID, cfg.ProjectID // attributed like dynamic_lease.issued
	if !c.writeAuditEventFull(ctx, "dynamic_lease.insecure_transport", &uid, nil, &pid, "",
		fmt.Sprintf("issuing from dynamic-secret config %d %q (%s) whose admin_dsn has %s: %s; %s",
			cfg.ID, cfg.Name, w.Backend, w.Option, w.Effect(), why)) {
		return fmt.Errorf("%w: audit event %q was not recorded; no credential was issued, retry", ErrMutationAuditUnavailable, "dynamic_lease.insecure_transport")
	}
	return nil
}
