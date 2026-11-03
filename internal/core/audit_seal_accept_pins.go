// audit_seal_accept_pins.go — what pins the rows a new acceptance keeps
// (#3802). The entry hash is unkeyed, so a database writer can rewrite rows
// and recompute their hashes; only a signed artifact that certified a head h
// (its hash covers rows 1..h) shows the rows through h are the ones that were
// written. Before a loss is sealed, every such pin whose head still exists must
// match the row, and the surviving rows before each break that nothing signed
// pins are named in the plan and recorded in the seal as unauthenticated.
package core

import (
	"context"
	"fmt"
	"slices"
)

// auditLossCheckpointPage is the page size for reading every checkpoint row.
const auditLossCheckpointPage = 500

// auditLossPin is one row hash a signed artifact certified.
type auditLossPin struct {
	ID     uint
	Hash   string
	Source string
}

// auditLossPins collects every authenticated pin: each checkpoint row that
// authenticates under the current key and the seal binding of some prefix of
// the seal list (the one it was written under), the high-water mark, the
// retention anchor, the verification state's pin, last tail check and rolling
// cycle, the host witness, the earlier seal records and a verified anchor
// file. A checkpoint signed under another key, or one that authenticates under
// nothing, is not a pin: it is ignored, never trusted.
func (c *KeyorixCore) auditLossPins(ctx context.Context, f *auditLossFindings, plan *AuditLossPlan) ([]auditLossPin, error) {
	var pins []auditLossPin
	add := func(id uint, hash, source string) {
		if id != 0 && hash != "" {
			pins = append(pins, auditLossPin{ID: id, Hash: hash, Source: source})
		}
	}
	binds := make([]auditSealBinding, 0, len(f.seals.recs)+1)
	for k := range len(f.seals.recs) + 1 {
		binds = append(binds, sealBindingOf(f.seals.recs[:k]))
	}
	for after := uint(0); ; {
		page, err := c.storage.ListAuditCheckpoints(ctx, after, auditLossCheckpointPage)
		if err != nil {
			return nil, err
		}
		for _, cp := range page {
			if cp.KeyVersion == c.auditCkptKeyVersion && slices.ContainsFunc(binds, func(b auditSealBinding) bool { return c.checkpointSigMatchesUnder(cp, b, cp.Signature) }) {
				add(cp.HeadID, cp.HeadHash, fmt.Sprintf("signed checkpoint #%d", cp.ID))
			}
		}
		if len(page) < auditLossCheckpointPage {
			break
		}
		after = page[len(page)-1].ID
	}
	hw, err := c.authenticatedHighWaterBase(ctx)
	if err != nil {
		return nil, err
	}
	if hw != nil {
		add(hw.HeadID, hw.HeadHash, "the signed high-water mark")
	}
	if a := f.anchor; a != nil {
		add(a.RowID, a.EntryHash, "the signed retention anchor")
	}
	if st := f.state; st.Seals == len(f.seals.recs) {
		if p := st.Pin; p != nil {
			add(p.HeadID, p.HeadHash, "the signed verification state")
		}
		if lc := st.LastCheck; lc != nil && lc.Valid {
			add(lc.ThroughID, lc.HeadHash, "the signed verification state's last tail check")
		}
		if cy := st.Cycle; cy != nil {
			add(cy.SeedID, cy.SeedHash, "the signed verification state's rolling verification")
			add(cy.TargetID, cy.TargetHash, "the signed verification state's rolling verification")
		}
	}
	if w := plan.Witness; w != nil {
		add(w.HeadID, w.HeadHash, w.Source)
	}
	for _, r := range f.seals.recs {
		src := fmt.Sprintf("seal #%d", r.Seq)
		for _, g := range r.Gaps {
			add(g.LastGoodID, g.LastGoodHash, src)
			add(g.ResumeID, g.ResumeHash, src)
		}
		add(r.After.HeadID, r.After.HeadHash, src)
	}
	if a := plan.Anchor; a != nil && a.Verified {
		add(a.HeadID, a.HeadHash, "the external anchor file")
	}
	return pins, nil
}

// auditLossCheckPins refuses a plan when a pinned row that still exists no
// longer carries the certified hash (rewritten after it was certified, not
// lost), and returns, for each boundary the plan seals from (the last good row
// before each gap, a truncation's surviving head), the surviving rows above
// the highest matching pin at or below it: rows nothing signed pins.
func (c *KeyorixCore) auditLossCheckPins(ctx context.Context, f *auditLossFindings, plan *AuditLossPlan) ([]AuditSealSpan, error) {
	pins, err := c.auditLossPins(ctx, f, plan)
	if err != nil {
		return nil, err
	}
	var held []uint
	for _, p := range pins {
		hash, found, err := c.storage.AuditEntryHashByID(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		if !found {
			continue // lost (inside a named gap or truncation) or purged
		}
		if hash != p.Hash {
			return nil, auditLossRefused("audit event #%d differs from the hash %s certified (hash %s, now %s): it was rewritten after it was certified, which is tampering, not a row loss; investigate",
				p.ID, p.Source, shortHash(p.Hash), shortHash(hash))
		}
		held = append(held, p.ID)
	}
	var bounds []uint
	for _, g := range plan.Gaps {
		bounds = append(bounds, g.LastGoodID)
	}
	if t := plan.Truncation; t != nil {
		bounds = append(bounds, t.SurvivingHeadID)
	}
	floor := uint(1)
	if f.anchor != nil {
		floor = f.anchor.RowID
	}
	var spans []AuditSealSpan
	for _, b := range bounds {
		from := floor
		for _, id := range held {
			if id <= b && id+1 > from {
				from = id + 1
			}
		}
		if b == 0 || from > b {
			continue
		}
		if n := len(spans); n > 0 && spans[n-1].ThroughID >= from {
			spans[n-1].ThroughID = max(spans[n-1].ThroughID, b)
			continue
		}
		spans = append(spans, AuditSealSpan{FromID: from, ThroughID: b})
	}
	return spans, nil
}
