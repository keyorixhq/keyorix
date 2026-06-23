// certificate_expiry.go — proactive certificate-expiry monitoring (ADR-055). An
// opt-in background scan (see main.go) parses certificate-typed secrets, reads each
// certificate's real notAfter, and notifies project admins of certs that are expired
// or expiring within the lead window — so a certificate never silently lapses and
// takes down its consumers. Builds on the certificate parser (ADR-054); mirrors the
// secret-expiry reminder scheduler (notify project approvers once, de-duplicated).
//
// The scan decrypts certificate-typed secret values to read notAfter; it never
// returns or exposes the value or any private key, and it is opt-in/off by default.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// NotificationCertificateExpiry marks an in-app certificate-expiry reminder.
const NotificationCertificateExpiry = "secret.certificate_expiry"

const (
	// defaultCertExpiryLeadDays — certificates usually need more lead time to
	// re-issue than a generic secret, so the default window is wider.
	defaultCertExpiryLeadDays = 30
	certExpiryPageSize        = 500
)

// ScanCertificateExpiry finds certificate-typed secrets whose certificate is expired
// or expires within leadDays, and sends ONE standing digest notification to each
// affected project's approvers (de-duplicated, like the secret-expiry reminder).
// leadDays <= 0 falls back to the default. Returns the number of notifications created.
func (c *KeyorixCore) ScanCertificateExpiry(ctx context.Context, leadDays int) (int, error) {
	if leadDays <= 0 {
		leadDays = defaultCertExpiryLeadDays
	}
	now := c.now()
	cutoff := now.Add(time.Duration(leadDays) * 24 * time.Hour)

	certs, err := c.listCertificateSecrets(ctx)
	if err != nil {
		return 0, err
	}

	type counts struct{ expired, soon int }
	byProject := map[uint]*counts{}
	for _, s := range certs {
		notAfter, ok := c.certNotAfter(ctx, s)
		if !ok || notAfter.After(cutoff) {
			continue // not a parseable cert, or not expiring within the window
		}
		ct := byProject[s.ProjectID]
		if ct == nil {
			ct = &counts{}
			byProject[s.ProjectID] = ct
		}
		if notAfter.Before(now) {
			ct.expired++
		} else {
			ct.soon++
		}
	}

	sent := 0
	for projectID, ct := range byProject {
		if projectID == 0 || (ct.expired == 0 && ct.soon == 0) {
			continue
		}
		members, err := c.storage.ListProjectMembers(ctx, projectID)
		if err != nil {
			continue
		}
		pid := projectID
		msg := certificateExpiryMessage(c.projectLabel(ctx, projectID), ct.expired, ct.soon)
		for _, mbr := range members {
			if !isApproverRole(mbr.RoleName) {
				continue
			}
			if c.hasUnreadCertificateExpiry(ctx, mbr.UserID, projectID) {
				continue // a standing reminder already exists — don't pile up
			}
			c.notify(ctx, mbr.UserID, NotificationCertificateExpiry,
				"Certificates expiring", msg, &pid, "/secrets")
			sent++
		}
	}
	return sent, nil
}

// certNotAfter decrypts a certificate-typed secret's current value and returns the
// leaf certificate's notAfter. ok is false when the secret is suspended, has no
// version, or its value is not a parseable certificate. Reads the value off the
// max-reads-counting path (this is a system scan, not a user value read) and never
// surfaces the value or key — only the expiry time.
func (c *KeyorixCore) certNotAfter(ctx context.Context, secret *models.SecretNode) (time.Time, bool) {
	if secret.Status == SecretStatusSuspended {
		return time.Time{}, false
	}
	version, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
	if err != nil {
		return time.Time{}, false
	}
	value := version.EncryptedValue
	if c.encryption != nil {
		value, err = c.encryption.RetrieveSecret(version.ID)
		if err != nil {
			return time.Time{}, false
		}
	}
	cert, err := parseLeafCertificate(value)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

// listCertificateSecrets returns every certificate-typed secret across all projects,
// paging through all of them (expiry evaluation must not silently cap).
func (c *KeyorixCore) listCertificateSecrets(ctx context.Context) ([]*models.SecretNode, error) {
	certType := "certificate"
	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			Page: page, PageSize: certExpiryPageSize, Type: &certType,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, secrets...)
		if len(secrets) < certExpiryPageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
}

// certificateExpiryMessage renders the per-project digest.
func certificateExpiryMessage(project string, expired, soon int) string {
	switch {
	case expired > 0 && soon > 0:
		return fmt.Sprintf("%s: %d certificate(s) expired and %d expiring soon — review and re-issue.", project, expired, soon)
	case expired > 0:
		return fmt.Sprintf("%s: %d certificate(s) have expired — re-issue them.", project, expired)
	default:
		return fmt.Sprintf("%s: %d certificate(s) expiring soon — plan re-issuance.", project, soon)
	}
}

// hasUnreadCertificateExpiry reports whether the user already has an unread
// certificate-expiry reminder for the project (de-duplication).
func (c *KeyorixCore) hasUnreadCertificateExpiry(ctx context.Context, userID, projectID uint) bool {
	notes, err := c.storage.ListNotifications(ctx, userID, true, 100)
	if err != nil {
		return false // on a read error, prefer notifying over silently skipping
	}
	for _, n := range notes {
		if n.Type == NotificationCertificateExpiry && n.ProjectID != nil && *n.ProjectID == projectID {
			return true
		}
	}
	return false
}
