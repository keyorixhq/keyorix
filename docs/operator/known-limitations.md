# Operator known limitations

Gaps the operator runbooks name, kept in one place. Each is a product decision that has not
been made, not a bug and not a documentation gap. Update this page when a decision lands.

- **No marked chain-segment restart after a verified break.** `admin audit accept-loss` seals rows
  that are gone; a break caused by a modified row stays broken in every report and every
  checkpoint stays refused. The ways forward are to keep running on the broken chain or to
  restore a known-good archive ([audit-chain-break-runbook.md](audit-chain-break-runbook.md)
  sections 7 and 8).
- **No command reverses a DEK rotation.** The way back is to restore the archive taken before it;
  otherwise roll forward ([key-rotation-runbook.md](key-rotation-runbook.md), "Gaps in the
  product today").
