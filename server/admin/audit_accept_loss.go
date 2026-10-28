// audit_accept_loss.go implements `keyorix-server admin audit accept-loss`
// (docs/design-audit-reseal-options.md option A, the constraints of
// docs/design/recovery-options.md §2): the audited, key-holder way to accept a
// genuine, proven loss of audit rows, so that integrity protection of the rows
// written from now on resumes. The chain is reported "sealed" from then on,
// never valid again.
//
// Offline only: it takes the exclusive database lock (refusing --force) and the
// master passphrase, from which the checkpoint key is derived. A database
// writer or an API token cannot run it. All verification and every write is
// internal/core's (audit_seal_accept.go); this file resolves flags, prints the
// plan and asks for --confirm.
package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/spf13/cobra"
)

var (
	acceptLossBrokenIDs    []uint
	acceptLossOperator     string
	acceptLossReason       string
	acceptLossEvidence     string
	acceptLossAnchorFile   string
	acceptLossAnchorSHA256 string
	acceptLossConfirm      bool
	acceptLossPassphrase   crypto.PassphraseSource
)

var sha256HexRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var acceptLossCmd = &cobra.Command{
	Use:   "accept-loss",
	Short: "Accept a proven loss of audit rows (seal the gap) so checkpoints resume; the chain reads sealed, never valid",
	Long: `Accepts a genuine, proven loss of audit events, recorded with the checkpoint key,
so that the rows written from now on are certified again (a broken chain refuses
every checkpoint, so new tampering would no longer be notarised).

Run it with the server stopped: it takes the exclusive database lock (--force is
refused) and the master passphrase. It verifies first and refuses anything that is
not a proven loss at exactly the ids you name with --first-broken-id:
  - a gap: the walk breaks at the first surviving row after the lost rows, that row
    is intact, and its prev_hash names a row that is gone (not an inserted row);
  - a truncation: the walk is clean, but the head a signed checkpoint, high-water
    mark or verification state certified is gone (name that head).
It refuses a modified row, the pre-#1452 encoding (run the chain-encoding
migration), a key mismatch (follow the key-rotation runbook), an unauthenticated
store, an untrusted verification state (run a full verification) and an altered
earlier seal.

It prints what it will accept and writes nothing without --confirm. With --confirm
it writes, in this order: the seal record, ONE in-chain system.audit_loss_accepted
event, a fresh checkpoint and high-water mark of what survives, and the
verification state. If it stops part way, the chain reads broken until you run the
same command again, which completes it.

Afterwards every view reports the chain as "sealed": not_proven until a full
verification completes, then sealed (online status, posture, evidence pack;
'verify-audit' exits 4). It is never valid again: the lost rows are gone.

--reason and --operator are stored in the audit chain and the seal record: put no
secrets in them. --evidence-sha256 is the SHA-256 of the evidence you keep (the
database file or dump taken before running this, and the 'verify-audit --json'
report); compute it first. --anchor binds the acceptance to an 'export-checkpoint'
file taken after the lost rows existed (it must cover the lost range and is
authenticated with the checkpoint key); --anchor-sha256 records only the digest of
one kept elsewhere.

Exit codes: 0 accepted, 1 refused or failed (nothing written unless it says so).`,
	RunE: runAcceptLoss,
}

func init() {
	f := acceptLossCmd.Flags()
	f.UintSliceVar(&acceptLossBrokenIDs, "first-broken-id", nil, "The id where the walk breaks (the first row after the lost rows), or the missing certified head of a truncation; repeat for several gaps")
	f.StringVar(&acceptLossOperator, "operator", "", "Name of the person accepting the loss (stored in the audit chain; required)")
	f.StringVar(&acceptLossReason, "reason", "", "Why, with the incident or ticket reference (stored in the audit chain, no secrets; required)")
	f.StringVar(&acceptLossEvidence, "evidence-sha256", "", "SHA-256 (hex) of the evidence kept: the database file or dump, the verify-audit --json report (required)")
	f.StringVar(&acceptLossAnchorFile, "anchor", "", "An 'export-checkpoint' file taken after the lost rows existed: authenticated, must cover the lost range, measures the loss")
	f.StringVar(&acceptLossAnchorSHA256, "anchor-sha256", "", "SHA-256 of an anchor file kept elsewhere (recorded only, not checked)")
	f.BoolVar(&acceptLossConfirm, "confirm", false, "Write the seal (without it, only print what would be accepted)")
	registerPassphraseFlags(acceptLossCmd, &acceptLossPassphrase)
	auditCmd.AddCommand(acceptLossCmd)
}

func runAcceptLoss(cmd *cobra.Command, args []string) error {
	req, err := acceptLossRequest()
	if err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("storage.encryption is not enabled, so no checkpoint key exists to seal with")
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if lockBypass != "" {
		return fmt.Errorf("accept-loss runs only under the exclusive database lock (stop the server and every other admin command); --force is refused: %s", lockBypass)
	}
	key, kid, err := deriveCheckpointKey(cfg, acceptLossPassphrase)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(key)

	return withUsableStorage(cfg, func(store corestorage.Storage) error {
		return acceptLoss(cmd.Context(), cfg, store, key, kid, req)
	})
}

// acceptLossRequest validates the flags (before any passphrase prompt).
func acceptLossRequest() (core.AuditLossRequest, error) {
	req := core.AuditLossRequest{BrokenIDs: acceptLossBrokenIDs, Operator: strings.TrimSpace(acceptLossOperator),
		OSUser: hostOperator(), Reason: strings.TrimSpace(acceptLossReason), Evidence: strings.ToLower(acceptLossEvidence)}
	switch {
	case req.Operator == "":
		return req, fmt.Errorf("--operator is required")
	case req.Reason == "":
		return req, fmt.Errorf("--reason is required (an incident or ticket reference; it is stored, so no secrets)")
	case core.AuditLossTextProblem(req.Operator, req.Reason) != "":
		return req, fmt.Errorf("%s", core.AuditLossTextProblem(req.Operator, req.Reason))
	case !sha256HexRE.MatchString(acceptLossEvidence):
		return req, fmt.Errorf("--evidence-sha256 must be the 64-hex-digit SHA-256 of the evidence you keep (for example: shasum -a 256 secrets.db.bak)")
	case acceptLossAnchorSHA256 != "" && !sha256HexRE.MatchString(acceptLossAnchorSHA256):
		return req, fmt.Errorf("--anchor-sha256 must be a 64-hex-digit SHA-256")
	case acceptLossAnchorFile != "" && acceptLossAnchorSHA256 != "":
		return req, fmt.Errorf("pass --anchor or --anchor-sha256, not both")
	}
	req.AnchorDigest = strings.ToLower(acceptLossAnchorSHA256)
	if acceptLossAnchorFile != "" {
		data, err := secretenv.ReadRegularFile("audit anchor", acceptLossAnchorFile)
		if err != nil {
			return req, fmt.Errorf("--anchor: read %q: %w", acceptLossAnchorFile, err)
		}
		b, err := auditverify.ParseExternalAnchorBundle(data)
		if err != nil {
			return req, fmt.Errorf("--anchor: %w", err)
		}
		sum := sha256.Sum256(data)
		req.Anchor = &core.AuditLossAnchor{Digest: hex.EncodeToString(sum[:]), ChainedEvents: b.ChainedEvents, HeadID: uint(b.HeadID),
			HeadHash: b.HeadHash, KeyVersion: b.KeyVersion, Signature: b.Signature}
	}
	return req, nil
}

// acceptLoss plans, prints and (with --confirm) writes the seal.
func acceptLoss(ctx context.Context, cfg *config.Config, store corestorage.Storage, key []byte, kid string, req core.AuditLossRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c := core.NewKeyorixCore(store)
	c.SetAuditCheckpointKey(key, kid)
	if cfg.Storage.Type == "local" || cfg.Storage.Type == "sqlite" {
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		c.SetAuditHighWaterWitnessPath(auditverify.WitnessPath(dbPath))
	}
	fmt.Fprintln(os.Stderr, "Verifying the audit chain under the checkpoint key (this walks every row)...")
	plan, err := c.PlanAuditLossAcceptance(ctx, req)
	if err != nil {
		return err
	}
	for _, line := range plan.Describe() {
		fmt.Println(line)
	}
	if !acceptLossConfirm {
		return fmt.Errorf("nothing was written: re-run with --confirm to accept this loss")
	}
	fmt.Fprintln(os.Stderr, "Writing the seal record, the audit event, a fresh checkpoint and the verification state...")
	res, err := c.AcceptAuditLoss(ctx, plan)
	if err != nil {
		return fmt.Errorf("%w (if part of it was written, the chain reads broken until you run this command again)", err)
	}
	fmt.Printf("Accepted: seal #%d (record %s). New checkpoint #%d certifies %d events through #%d.\n",
		res.Seq, res.Digest, res.Checkpoint.ID, res.Checkpoint.ChainedEvents, res.Checkpoint.HeadID)
	fmt.Println("Next: start the server. The status reads not_proven until a full verification completes, then sealed;")
	fmt.Println("'keyorix-server admin verify-audit --checkpoint-key-file <key>' now exits 4 (SEALED). Export a fresh")
	fmt.Println("anchor with 'keyorix-server admin audit export-checkpoint' and keep it with the evidence.")
	return nil
}
