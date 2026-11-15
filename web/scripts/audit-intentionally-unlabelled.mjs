// Audit event types the server emits that deliberately have NO entry in
// src/utils/eventLabels.ts. The parity test (eventLabelsParity.test.ts) fails for
// an emitted event that is neither labelled nor listed here.
//
// One entry per line, "event.type": 'why no curated label', so two PRs that add
// events do not collide. A reason must say why the humanized fallback
// ("Admin job run") is the intended text. Do not list an event just to silence
// the test: a row a customer reads on the audit page or dashboard gets a label.

// Shared reasons. An entry that needs its own reason writes a string instead.
const JOB = 'scheduled-job run row written by the scheduler, no person acts; the humanized job name reads fine';
const DIAG = 'internal failure diagnostic for operators (log-correlated), not a user action; humanized name reads fine';
const SYS = 'system housekeeping row with no acting user; humanized name reads fine';

export const INTENTIONALLY_UNLABELLED = {
    'admin_job.anomaly_alerts_run': JOB,
    'admin_job.check_read_quotas_run': JOB,
    'admin_job.expiry_reminders_run': JOB,
    'admin_job.record_hygiene_snapshot_run': JOB,
    'admin_job.role_expiry_check_run': JOB,
    'admin_job.rotation_reminders_run': JOB,
    'admin_job.run_alert_escalation_run': JOB,
    'admin_job.suspend_inactive_users_run': JOB,
    'admin_job.token_expiry_check_run': JOB,
    'audit.chain_migrated': SYS,
    'auth.keep_session_lookup_failed': DIAG,
    'auth.rate_limit_error': DIAG,
    'auth.session_facts_unavailable': DIAG,
    'auth.session_revocation_panicked': DIAG,
    'auth.undelivered_session_revoked': SYS,
    'auth.undelivered_session_unresolved': DIAG,
    'break_glass.notify_panicked': DIAG,
    'data.login_attempts_pruned': SYS,
    'dynamic_secret.project_cascade_failed': DIAG,
    'license.evaluated': SYS,
    'mfa.undelivered_stepup_grant_revoked': SYS,
    'mfa.undelivered_stepup_grant_unresolved': DIAG,
    'project.environment_seed_failed': DIAG,
    'project_member.role_confirmed_unchanged': SYS,
    'secret.rotate_noop': SYS,
    'setup_token.consume_error': DIAG,
    'setup_token.consume_failed': DIAG,
    'system.audit_verification_state_rejected': DIAG,
};
