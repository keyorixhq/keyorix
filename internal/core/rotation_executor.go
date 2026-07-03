// rotation_executor.go — automated secret rotation (ADR-046). Rotation policies say
// WHEN a secret should rotate and reminders nudge admins; this executor actually
// rotates the secrets that opted in (SecretNode.AutoRotate) by regenerating their
// value when they are overdue under an active covering policy.
//
// Only auto-rotate-enabled secrets are touched, and the new value is a freshly
// generated random string — so this is for secrets whose value Keyorix owns. A secret
// that mirrors an external system's credential must NOT enable auto-rotation, since
// regenerating it here does not update the upstream.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/rotation"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventAutoRotationFailures is audited once per run when one or more secrets failed.
const EventAutoRotationFailures = "rotation.failures_alerted"

// notifyRotationFailures broadcasts a single summary of ONE project's rotation
// failures to the configured deployment-wide notification channel (Slack/Teams/
// webhook/email) — a silently-failed credential rotation is a security event
// operators must see. Scoped to a single project: the caller (RunAutoRotation) calls
// this once per project rather than once per run, so a broadcast never bundles
// unrelated projects' secret names/failure reasons into one message (#391) — a
// deployment-wide channel is still an appropriate destination for this event (unlike
// the per-user events in notifications.go), it just must not cross project
// boundaries within a single message. No-op when nothing failed for this project;
// the sink is non-blocking.
func (c *KeyorixCore) notifyRotationFailures(ctx context.Context, projectID uint, failed map[uint]string) {
	if len(failed) == 0 || c.notificationSink == nil {
		return
	}
	lines := make([]string, 0, len(failed))
	for _, msg := range failed {
		lines = append(lines, "• "+msg)
	}
	sort.Strings(lines) // stable, deterministic ordering
	pid := projectID
	c.notificationSink.Deliver(NotificationEvent{
		Type:      "rotation.failed",
		Title:     fmt.Sprintf("Auto-rotation: %d secret(s) failed to rotate in %s", len(failed), c.projectLabel(ctx, projectID)),
		Message:   "The following secrets could not be auto-rotated:\n" + strings.Join(lines, "\n"),
		ProjectID: &pid,
		Link:      fmt.Sprintf("/projects/%d/secrets", projectID),
	})
}

// SetRotationManager wires the configured backend rotation executors (ADR-047) that
// apply a new credential to an upstream system. nil (the default) leaves backend
// rotation disabled — auto-rotation then only regenerates Keyorix-owned values.
func (c *KeyorixCore) SetRotationManager(m *rotation.Manager) {
	c.rotationManager = m
}

// RotationBackendNames lists the configured rotation-backend names (for discovery).
func (c *KeyorixCore) RotationBackendNames() []string {
	if c.rotationManager == nil {
		return nil
	}
	return c.rotationManager.Names()
}

// Audit events for automated rotation (ADR-046).
const (
	EventSecretAutoRotated      = "secret.auto_rotated"
	EventSecretAutoRotateConfig = "secret.auto_rotate_configured"
)

// Default generated value: 32 chars over a 62-symbol alphanumeric set (~190 bits).
// Alphanumeric so a consumer reading it back never trips over shell/URL metacharacters.
const (
	rotatedValueLength    = 32
	rotatedValueMinLength = 8
	rotatedValueMaxLength = 256
)

// Named charsets a secret may select via RotationCharset (ADR-046). "" = alphanumeric.
const (
	charsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	charsetLowerAlnum   = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetHex          = "0123456789abcdef"
	charsetAlnumSymbols = charsetAlphanumeric + "!@#$%^&*-_=+"
	rotatedValueCharset = charsetAlphanumeric // back-compat alias (default)
)

// resolveCharset maps a RotationCharset name to its character set, defaulting to
// alphanumeric for "" or an unknown name (fail-safe: never an empty alphabet).
func resolveCharset(name string) string {
	switch name {
	case "lower_alphanumeric":
		return charsetLowerAlnum
	case "hex":
		return charsetHex
	case "alphanumeric_symbols":
		return charsetAlnumSymbols
	default:
		return charsetAlphanumeric
	}
}

// resolveLength clamps a requested length into [min,max], defaulting to 32 for 0.
func resolveLength(n int) int {
	if n <= 0 {
		return rotatedValueLength
	}
	if n < rotatedValueMinLength {
		return rotatedValueMinLength
	}
	if n > rotatedValueMaxLength {
		return rotatedValueMaxLength
	}
	return n
}

// generateRotatedValue returns a fresh random value of the default shape (crypto/rand).
func generateRotatedValue() (string, error) {
	return generateRotatedValueSpec(0, "")
}

// generateRotatedValueSpec returns a fresh random value of the requested length and
// charset (crypto/rand), applying the defaults/clamping above.
func generateRotatedValueSpec(length int, charset string) (string, error) {
	n := resolveLength(length)
	set := resolveCharset(charset)
	b := make([]byte, n)
	for i := range b {
		ch, err := randChar(set)
		if err != nil {
			return "", err
		}
		b[i] = ch
	}
	return string(b), nil
}

// dueRotation is a secret that is due for auto-rotation this run, with the policy it is
// due under (for the audit trail).
type dueRotation struct {
	secret *models.SecretNode
	policy *models.RotationPolicy
}

// RunAutoRotation rotates every auto-rotate-enabled secret that is overdue under an
// active rotation policy, regenerating its value (a new version) and auditing each
// rotation. A secret covered by multiple policies is rotated at most once per run.
//
// Rotations are ordered by the secret dependency graph (ADR-052): within a project a
// secret rotates only after the secrets it depends on, mirroring the dependency-safe
// waves the rotation planner computes (ADR-053). When a dependency does NOT rotate this
// run — it failed, or was itself deferred — the dependent is DEFERRED rather than
// rotated against a now-stale dependency (dependency-first auto-rotation), and audited
// so an operator can act. Otherwise best-effort per secret: a generate/rotate failure is
// logged and skipped, never aborting the run. Returns the number of secrets rotated.
func (c *KeyorixCore) RunAutoRotation(ctx context.Context) (int, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, nil, nil)
	if err != nil {
		return 0, fmt.Errorf("auto-rotation: list policies: %w", err)
	}
	now := c.now()

	// Phase 1 — gather the secrets due for auto-rotation, deduped per secret. A secret
	// covered by several policies is rotated at most once, under the first active policy
	// it is due under (preserves the prior first-policy-wins behaviour). dueOrder keeps
	// discovery order so project grouping below is deterministic.
	due := map[uint]*dueRotation{}
	dueOrder := []uint{}
	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}
		secrets, err := c.scopedPolicySecrets(ctx, policy, nil)
		if err != nil {
			continue
		}
		for _, secret := range secrets {
			if !secret.AutoRotate {
				continue
			}
			if _, seen := due[secret.ID]; seen {
				continue // already due under an earlier policy
			}
			lastRotated := secret.CreatedAt
			if secret.LastRotatedAt != nil {
				lastRotated = *secret.LastRotatedAt
			}
			if int(now.Sub(lastRotated).Hours()/24) < policy.IntervalDays {
				continue // not yet due under this policy
			}
			due[secret.ID] = &dueRotation{secret: secret, policy: policy}
			dueOrder = append(dueOrder, secret.ID)
		}
	}
	if len(due) == 0 {
		return 0, nil
	}

	// Phase 2 — group the due secrets by project. Rotation dependencies are per-project
	// (ADR-052 edges never cross a project boundary), so ordering is computed per project.
	byProject := map[uint][]uint{}
	projectOrder := []uint{}
	for _, id := range dueOrder {
		pid := due[id].secret.ProjectID
		if _, ok := byProject[pid]; !ok {
			projectOrder = append(projectOrder, pid)
		}
		byProject[pid] = append(byProject[pid], id)
	}

	// Phase 3 — rotate each project's due secrets in dependency-safe wave order.
	rotated := 0
	// totalFailed accumulates every project's failures for the run-level audit summary
	// only (a bare count, no secret names/reasons — safe to bundle). The per-project
	// broadcast notification below uses a fresh, project-scoped map instead, so a
	// Slack/Teams/webhook message never bundles unrelated projects' secret names or
	// failure reasons together (#391).
	totalFailed := 0
	for _, pid := range projectOrder {
		ids := byProject[pid]
		candidateSet := make(map[uint]bool, len(ids))
		for _, id := range ids {
			candidateSet[id] = true
		}

		edges, eerr := c.storage.ListSecretDependenciesForProject(ctx, pid)
		if eerr != nil {
			// Can't determine the dependency order; degrade to a flat best-effort pass for
			// this project (no deferral) rather than skip its rotations entirely.
			log.Printf("auto-rotation: list dependencies for project %d: %v — rotating without dependency ordering", pid, eerr)
			edges = nil
		}
		waves, ok := rotationWaves(edges, candidateSet)
		if !ok {
			// A cycle should not occur (the graph is kept acyclic at add, ADR-052). Fall
			// back to a single flat wave with deferral disabled so a malformed graph never
			// blocks rotation.
			log.Printf("auto-rotation: dependency graph for project %d has a cycle — rotating without dependency ordering", pid)
			flat := append([]uint(nil), ids...)
			sort.Slice(flat, func(i, j int) bool { return flat[i] < flat[j] })
			waves = [][]uint{flat}
			edges = nil
		}

		// In-run dependencies per secret (edges to other due secrets in this project).
		dependsOnInRun := map[uint][]uint{}
		for _, e := range edges {
			if candidateSet[e.DependentSecretID] && candidateSet[e.DependsOnSecretID] {
				dependsOnInRun[e.DependentSecretID] = append(dependsOnInRun[e.DependentSecretID], e.DependsOnSecretID)
			}
		}

		// failed records why each non-rotated secret in THIS project did not rotate (a
		// genuine failure or a dependency-driven deferral). Scoped to this project only
		// (see totalFailed above / #391) and broadcast right after this project finishes,
		// before moving on to the next project's map.
		failed := map[uint]string{}
		blocked := map[uint]bool{} // due secrets that did not rotate this run (failed or deferred)
		for _, wave := range waves {
			for _, id := range wave {
				dr := due[id]
				// A dependency processed earlier (dependency-safe order guarantees it) did
				// not rotate — defer rather than rotate against a stale dependency.
				if depID, isBlocked := lowestBlockedDep(dependsOnInRun[id], blocked); isBlocked {
					blocked[id] = true
					depName := ""
					if d, ok := due[depID]; ok {
						depName = d.secret.Name
					}
					sid := id
					c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
						fmt.Sprintf("auto-rotation DEFERRED for secret %q: it depends on %q which did not rotate this run", dr.secret.Name, depName))
					failed[id] = fmt.Sprintf("%q: deferred — depends on %q which did not rotate this run", dr.secret.Name, depName)
					continue
				}
				if c.rotateOneSecret(ctx, dr.secret, dr.policy, failed) {
					rotated++
				} else {
					blocked[id] = true
				}
			}
		}
		totalFailed += len(failed)
		c.notifyRotationFailures(ctx, pid, failed)
	}

	if totalFailed > 0 {
		sysCtx := WithActorType(ctx, ActorTypeSystem)
		c.writeAuditEvent(sysCtx, EventAutoRotationFailures, nil, nil,
			fmt.Sprintf("auto-rotation: %d secret(s) failed to rotate", totalFailed))
	}
	return rotated, nil
}

// lowestBlockedDep returns the lowest-id dependency that is in blocked (and true), or
// 0/false if none of deps is blocked. Lowest-id makes the chosen dependency — and thus
// the deferral audit message — deterministic when several dependencies are blocked.
func lowestBlockedDep(deps []uint, blocked map[uint]bool) (uint, bool) {
	found := false
	var lowest uint
	for _, d := range deps {
		if blocked[d] && (!found || d < lowest) {
			found, lowest = true, d
		}
	}
	return lowest, found
}

// rotateOneSecret performs the actual rotation of a single due secret: generate a new
// value, optionally apply it to the configured backend (ADR-047) before storing so the
// two never drift, store the new version, and audit the outcome. Any failure is recorded
// in failed and logged; it returns true only when the secret was rotated and stored
// successfully. Best-effort: it never returns an error or aborts the run.
func (c *KeyorixCore) rotateOneSecret(ctx context.Context, secret *models.SecretNode, policy *models.RotationPolicy, failed map[uint]string) bool {
	val, gerr := generateRotatedValueSpec(secret.RotationLength, secret.RotationCharset)
	if gerr != nil {
		log.Printf("auto-rotation: generate value for secret %d: %v", secret.ID, gerr)
		failed[secret.ID] = fmt.Sprintf("%q: generate value: %v", secret.Name, gerr)
		return false
	}
	// Backend rotation (ADR-047): if the secret names a configured executor, rotate the
	// credential UPSTREAM first and store the resulting value only on success. For a
	// generate-upstream backend (e.g. a cloud key API) the stored value is what the
	// upstream minted; for a password-set backend it is the candidate we generated. A
	// backend that is unconfigured/unknown or whose upstream apply fails is skipped.
	storeVal := val
	incompleteMsg := ""
	if secret.RotationBackend != "" {
		upstreamVal, err := c.applyBackendRotation(ctx, secret, val)
		var partial *rotation.PartialRotationError
		switch {
		case errors.As(err, &partial):
			// The upstream minted the new credential but a prior, possibly compromised one
			// could not be removed. Store the new value (a cloud key API returns the key
			// material only once, so discarding it would orphan a live key) but flag the
			// rotation incomplete below so the run records a failure and alerts an operator
			// to remove the leftover.
			storeVal = partial.Value
			incompleteMsg = fmt.Sprintf("%q via backend %q ref %q: %v", secret.Name, secret.RotationBackend, secret.RotationRef, err)
		case err != nil:
			sid := secret.ID
			c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
				fmt.Sprintf("auto-rotation FAILED for secret %q via backend %q ref %q: %v", secret.Name, secret.RotationBackend, secret.RotationRef, err))
			log.Printf("auto-rotation: backend rotate secret %d: %v", secret.ID, err)
			failed[secret.ID] = fmt.Sprintf("%q via backend %q ref %q: %v", secret.Name, secret.RotationBackend, secret.RotationRef, err)
			return false
		default:
			storeVal = upstreamVal
		}
	}
	if _, rerr := c.RotateSecret(ctx, secret.ID, []byte(storeVal), "system:auto-rotation"); rerr != nil {
		log.Printf("auto-rotation: rotate secret %d: %v", secret.ID, rerr)
		failed[secret.ID] = fmt.Sprintf("%q: store new version: %v", secret.Name, rerr)
		sid := secret.ID
		if secret.RotationBackend != "" {
			// The upstream credential was rotated but storing the new value failed: the
			// live credential and Keyorix's record have now DRIFTED. Audit it distinctly
			// (the backend-apply-failure path above is audited too) so an operator can
			// reconcile — the live secret may no longer match Keyorix.
			c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
				fmt.Sprintf("auto-rotation DRIFT for secret %q: backend %q ref %q rotated upstream but storing the new value failed: %v — the live credential may no longer match Keyorix",
					secret.Name, secret.RotationBackend, secret.RotationRef, rerr))
		} else {
			c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
				fmt.Sprintf("auto-rotation FAILED to store new version for secret %q: %v", secret.Name, rerr))
		}
		return false
	}
	if incompleteMsg != "" {
		// The new credential is stored (so dependents may still rotate against it), but a
		// prior, possibly compromised credential survived upstream. Record it as a failure
		// (NOT a clean success) so the operator is notified to remove the leftover, and
		// audit it distinctly.
		failed[secret.ID] = incompleteMsg
		sid := secret.ID
		c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
			fmt.Sprintf("auto-rotation INCOMPLETE for secret %q: new credential stored but a prior credential is still live and must be removed manually — %s", secret.Name, incompleteMsg))
		log.Printf("auto-rotation: incomplete cleanup for secret %d: %s", secret.ID, incompleteMsg)
		return true
	}
	delete(failed, secret.ID)
	sid := secret.ID
	via := ""
	if secret.RotationBackend != "" {
		via = fmt.Sprintf(" via backend %q ref %q", secret.RotationBackend, secret.RotationRef)
	}
	c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
		fmt.Sprintf("auto-rotated secret %q (policy %q, interval %dd)%s", secret.Name, policy.Name, policy.IntervalDays, via))
	return true
}

// applyBackendRotation resolves the secret's named rotation executor and rotates the
// upstream credential (ADR-047). It returns the VALUE to store in Keyorix: for a
// generate-upstream backend (rotation.GeneratingExecutor, e.g. a cloud key API) that is
// the value the upstream minted; for a password-set backend it is the candidate passed
// in (which the executor applied). Returns an error (so the caller does NOT store
// anything) when no manager is configured, the backend is unknown, or the apply fails.
func (c *KeyorixCore) applyBackendRotation(ctx context.Context, secret *models.SecretNode, candidate string) (string, error) {
	if c.rotationManager == nil {
		return "", fmt.Errorf("no rotation backends configured")
	}
	exec, ok := c.rotationManager.Get(secret.RotationBackend)
	if !ok {
		return "", fmt.Errorf("unknown rotation backend %q", secret.RotationBackend)
	}
	if secret.RotationRef == "" {
		return "", fmt.Errorf("rotation_ref is required for backend rotation")
	}
	if gen, ok := exec.(rotation.GeneratingExecutor); ok {
		return gen.GenerateUpstream(ctx, secret.RotationRef)
	}
	if err := exec.Rotate(ctx, secret.RotationRef, candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

// knownRotationCharset reports whether name is a recognized charset (or "" = default).
func knownRotationCharset(name string) bool {
	switch name {
	case "", "alphanumeric", "lower_alphanumeric", "hex", "alphanumeric_symbols":
		return true
	default:
		return false
	}
}

// AutoRotateSpec is the per-secret automated-rotation configuration set via
// SetSecretAutoRotate (ADR-046/047). Length 0 = default; Charset "" = default
// alphanumeric. Backend "" = regenerate in Keyorix only; when Backend names a
// configured executor, Ref is the upstream identifier it rotates (required iff Backend
// is set).
type AutoRotateSpec struct {
	Enabled bool
	Length  int
	Charset string
	Backend string
	Ref     string
}

// SetSecretAutoRotate configures automated rotation for a secret and audits the change.
// Enable only for secrets whose value Keyorix owns, OR point Backend at an executor that
// rotates the upstream credential too (ADR-047). The caller (transport) must have
// enforced scoped secrets.write.
func (c *KeyorixCore) SetSecretAutoRotate(ctx context.Context, id uint, spec AutoRotateSpec, actorID uint) error {
	if !knownRotationCharset(spec.Charset) {
		return fmt.Errorf("unknown rotation charset %q (want alphanumeric|lower_alphanumeric|hex|alphanumeric_symbols)", spec.Charset)
	}
	if spec.Length != 0 && (spec.Length < rotatedValueMinLength || spec.Length > rotatedValueMaxLength) {
		return fmt.Errorf("rotation length %d out of range (%d–%d, or 0 for default)", spec.Length, rotatedValueMinLength, rotatedValueMaxLength)
	}
	// Backend and ref are both-or-neither: a backend with no ref can't be applied, and a
	// ref with no backend is meaningless.
	if (spec.Backend == "") != (spec.Ref == "") {
		return fmt.Errorf("rotation_backend and rotation_ref must be set together (or both empty)")
	}
	// Reject an unknown backend at configuration time (the backend's own allowed_refs
	// then bounds, at rotation time, which refs it will actually rotate).
	if spec.Backend != "" {
		if c.rotationManager == nil {
			return fmt.Errorf("no rotation backends are configured")
		}
		if _, ok := c.rotationManager.Get(spec.Backend); !ok {
			return fmt.Errorf("unknown rotation backend %q", spec.Backend)
		}
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	secret.AutoRotate = spec.Enabled
	secret.RotationLength = spec.Length
	secret.RotationCharset = spec.Charset
	secret.RotationBackend = spec.Backend
	secret.RotationRef = spec.Ref
	secret.UpdatedAt = c.now()
	if _, err := c.storage.UpdateSecret(ctx, secret); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	uid := actorID
	sid := id
	verb := "disabled"
	if spec.Enabled {
		verb = "enabled"
	}
	via := ""
	if spec.Backend != "" {
		via = fmt.Sprintf(" (backend %q ref %q)", spec.Backend, spec.Ref)
	}
	c.writeAuditEvent(ctx, EventSecretAutoRotateConfig, &uid, &sid,
		fmt.Sprintf("auto-rotation %s for secret %q%s", verb, secret.Name, via))
	return nil
}
